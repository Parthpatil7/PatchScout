"""
Training Pipeline for CodeBERT Vulnerability Detection Model
"""

import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
from torch.optim import AdamW
from transformers import get_linear_schedule_with_warmup
import pandas as pd
import numpy as np
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from tqdm import tqdm
import json
from sklearn.metrics import (
    f1_score, precision_score, recall_score,
    accuracy_score, classification_report, confusion_matrix
)

from .codebert_model import CodeBERTVulnerabilityDetector


class VulnerabilityDataset(Dataset):
    """PyTorch Dataset for vulnerability detection"""
    
    def __init__(
        self,
        df: pd.DataFrame,
        tokenizer,
        max_length: int = 512,
        cwe_to_idx: Optional[Dict] = None
    ):
        """
        Initialize dataset
        
        Args:
            df: DataFrame with 'code', 'label', 'cwe' columns
            tokenizer: Tokenizer instance
            max_length: Maximum sequence length
            cwe_to_idx: Mapping from CWE ID to index
        """
        self.df = df.reset_index(drop=True)
        self.tokenizer = tokenizer
        self.max_length = max_length
        self.cwe_to_idx = cwe_to_idx or {}
        
    def __len__(self):
        return len(self.df)
    
    def __getitem__(self, idx):
        row = self.df.iloc[idx]
        
        # Get code and label
        code = str(row['code'])
        label = int(row['label'])
        
        # Tokenize
        encoding = self.tokenizer(
            code,
            max_length=self.max_length,
            padding='max_length',
            truncation=True,
            return_tensors='pt'
        )
        
        # Get CWE label if available
        cwe_label = 0  # Default: unknown
        if 'cwe' in row and row['cwe'] and row['cwe'] in self.cwe_to_idx:
            cwe_label = self.cwe_to_idx[row['cwe']]
        
        # Get severity label
        severity_map = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}
        severity_label = severity_map.get(row.get('severity', 'High'), 1)
        
        return {
            'input_ids': encoding['input_ids'].squeeze(),
            'attention_mask': encoding['attention_mask'].squeeze(),
            'vulnerability_label': torch.tensor(label, dtype=torch.long),
            'cwe_label': torch.tensor(cwe_label, dtype=torch.long),
            'severity_label': torch.tensor(severity_label, dtype=torch.long)
        }


class VulnerabilityTrainer:
    """Trainer for CodeBERT vulnerability detection"""
    
    def __init__(
        self,
        model: CodeBERTVulnerabilityDetector,
        train_loader: DataLoader,
        val_loader: DataLoader,
        device: str = 'cuda' if torch.cuda.is_available() else 'cpu',
        learning_rate: float = 2e-5,
        num_epochs: int = 5,
        warmup_steps: int = 500,
        output_dir: str = 'models/checkpoints'
    ):
        """
        Initialize trainer
        
        Args:
            model: Model to train
            train_loader: Training data loader
            val_loader: Validation data loader
            device: Device to train on
            learning_rate: Learning rate
            num_epochs: Number of epochs
            warmup_steps: Warmup steps for scheduler
            output_dir: Directory to save checkpoints
        """
        self.model = model.to(device)
        self.train_loader = train_loader
        self.val_loader = val_loader
        self.device = device
        self.num_epochs = num_epochs
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Optimizer
        self.optimizer = AdamW(
            self.model.parameters(),
            lr=learning_rate,
            weight_decay=0.01
        )
        
        # Scheduler
        total_steps = len(train_loader) * num_epochs
        self.scheduler = get_linear_schedule_with_warmup(
            self.optimizer,
            num_warmup_steps=warmup_steps,
            num_training_steps=total_steps
        )
        
        # Loss functions
        self.vuln_criterion = nn.CrossEntropyLoss()
        self.cwe_criterion = nn.CrossEntropyLoss(ignore_index=0)  # Ignore unknown
        self.severity_criterion = nn.CrossEntropyLoss()
        
        # Loss weights for multi-task learning
        self.loss_weights = {
            'vulnerability': 1.0,
            'cwe': 0.5,
            'severity': 0.3
        }
        
        # Training history
        self.history = {
            'train_loss': [],
            'val_loss': [],
            'train_acc': [],
            'val_acc': [],
            'val_f1': [],
            'val_precision': [],
            'val_recall': []
        }
        
        print(f"🚀 Trainer initialized")
        print(f"   Device: {device}")
        print(f"   Training samples: {len(train_loader.dataset)}")
        print(f"   Validation samples: {len(val_loader.dataset)}")
    
    def train_epoch(self) -> Tuple[float, float]:
        """Train for one epoch"""
        self.model.train()
        total_loss = 0
        correct = 0
        total = 0
        
        progress_bar = tqdm(self.train_loader, desc="Training")
        
        for batch in progress_bar:
            # Move to device
            input_ids = batch['input_ids'].to(self.device)
            attention_mask = batch['attention_mask'].to(self.device)
            vuln_labels = batch['vulnerability_label'].to(self.device)
            cwe_labels = batch['cwe_label'].to(self.device)
            severity_labels = batch['severity_label'].to(self.device)
            
            # Forward pass
            self.optimizer.zero_grad()
            outputs = self.model(input_ids, attention_mask)
            
            # Calculate losses
            vuln_loss = self.vuln_criterion(
                outputs['vulnerability_logits'],
                vuln_labels
            )
            cwe_loss = self.cwe_criterion(
                outputs['cwe_logits'],
                cwe_labels
            )
            severity_loss = self.severity_criterion(
                outputs['severity_logits'],
                severity_labels
            )
            
            # Combined loss
            loss = (
                self.loss_weights['vulnerability'] * vuln_loss +
                self.loss_weights['cwe'] * cwe_loss +
                self.loss_weights['severity'] * severity_loss
            )
            
            # Backward pass
            loss.backward()
            torch.nn.utils.clip_grad_norm_(self.model.parameters(), 1.0)
            self.optimizer.step()
            self.scheduler.step()
            
            # Calculate accuracy
            predictions = torch.argmax(outputs['vulnerability_logits'], dim=-1)
            correct += (predictions == vuln_labels).sum().item()
            total += vuln_labels.size(0)
            
            total_loss += loss.item()
            
            # Update progress bar
            progress_bar.set_postfix({
                'loss': f'{loss.item():.4f}',
                'acc': f'{100.0 * correct / total:.2f}%'
            })
        
        avg_loss = total_loss / len(self.train_loader)
        accuracy = correct / total
        
        return avg_loss, accuracy
    
    def validate(self) -> Dict[str, float]:
        """Validate model"""
        self.model.eval()
        total_loss = 0
        all_predictions = []
        all_labels = []
        
        with torch.no_grad():
            for batch in tqdm(self.val_loader, desc="Validation"):
                # Move to device
                input_ids = batch['input_ids'].to(self.device)
                attention_mask = batch['attention_mask'].to(self.device)
                vuln_labels = batch['vulnerability_label'].to(self.device)
                cwe_labels = batch['cwe_label'].to(self.device)
                severity_labels = batch['severity_label'].to(self.device)
                
                # Forward pass
                outputs = self.model(input_ids, attention_mask)
                
                # Calculate loss
                vuln_loss = self.vuln_criterion(
                    outputs['vulnerability_logits'],
                    vuln_labels
                )
                cwe_loss = self.cwe_criterion(
                    outputs['cwe_logits'],
                    cwe_labels
                )
                severity_loss = self.severity_criterion(
                    outputs['severity_logits'],
                    severity_labels
                )
                
                loss = (
                    self.loss_weights['vulnerability'] * vuln_loss +
                    self.loss_weights['cwe'] * cwe_loss +
                    self.loss_weights['severity'] * severity_loss
                )
                
                total_loss += loss.item()
                
                # Get predictions
                predictions = torch.argmax(outputs['vulnerability_logits'], dim=-1)
                all_predictions.extend(predictions.cpu().numpy())
                all_labels.extend(vuln_labels.cpu().numpy())
        
        # Calculate metrics
        avg_loss = total_loss / len(self.val_loader)
        accuracy = accuracy_score(all_labels, all_predictions)
        f1 = f1_score(all_labels, all_predictions, average='binary')
        precision = precision_score(all_labels, all_predictions, average='binary')
        recall = recall_score(all_labels, all_predictions, average='binary')
        
        return {
            'loss': avg_loss,
            'accuracy': accuracy,
            'f1': f1,
            'precision': precision,
            'recall': recall
        }
    
    def train(self):
        """Full training loop"""
        print("\n" + "="*80)
        print("STARTING TRAINING")
        print("="*80)
        
        best_f1 = 0
        patience = 3
        patience_counter = 0
        
        for epoch in range(self.num_epochs):
            print(f"\n📊 Epoch {epoch + 1}/{self.num_epochs}")
            
            # Train
            train_loss, train_acc = self.train_epoch()
            
            # Validate
            val_metrics = self.validate()
            
            # Update history
            self.history['train_loss'].append(train_loss)
            self.history['train_acc'].append(train_acc)
            self.history['val_loss'].append(val_metrics['loss'])
            self.history['val_acc'].append(val_metrics['accuracy'])
            self.history['val_f1'].append(val_metrics['f1'])
            self.history['val_precision'].append(val_metrics['precision'])
            self.history['val_recall'].append(val_metrics['recall'])
            
            # Print metrics
            print(f"\n   Training   - Loss: {train_loss:.4f}, Acc: {train_acc:.4f}")
            print(f"   Validation - Loss: {val_metrics['loss']:.4f}, Acc: {val_metrics['accuracy']:.4f}")
            print(f"                F1: {val_metrics['f1']:.4f}, Precision: {val_metrics['precision']:.4f}, Recall: {val_metrics['recall']:.4f}")
            
            # Save best model
            if val_metrics['f1'] > best_f1:
                best_f1 = val_metrics['f1']
                self.save_checkpoint(epoch, val_metrics, is_best=True)
                patience_counter = 0
                print(f"   ✅ New best F1 score: {best_f1:.4f}")
            else:
                patience_counter += 1
            
            # Early stopping
            if patience_counter >= patience:
                print(f"\n⏹️  Early stopping triggered (patience: {patience})")
                break
            
            # Save regular checkpoint
            self.save_checkpoint(epoch, val_metrics, is_best=False)
        
        print("\n" + "="*80)
        print("TRAINING COMPLETED")
        print("="*80)
        print(f"Best F1 Score: {best_f1:.4f}")
        
        # Save training history
        self.save_history()
    
    def save_checkpoint(self, epoch: int, metrics: Dict, is_best: bool = False):
        """Save model checkpoint"""
        checkpoint = {
            'epoch': epoch,
            'model_state_dict': self.model.state_dict(),
            'optimizer_state_dict': self.optimizer.state_dict(),
            'metrics': metrics,
            'history': self.history
        }
        
        if is_best:
            path = self.output_dir / 'best_model.pt'
        else:
            path = self.output_dir / f'checkpoint_epoch_{epoch+1}.pt'
        
        torch.save(checkpoint, path)
        print(f"   💾 Saved checkpoint: {path}")
    
    def save_history(self):
        """Save training history"""
        history_path = self.output_dir / 'training_history.json'
        with open(history_path, 'w') as f:
            json.dump(self.history, f, indent=2)
        print(f"   📊 Saved training history: {history_path}")


if __name__ == "__main__":
    print("✅ Training pipeline ready")
    print("   Use train_model.py to start training")
