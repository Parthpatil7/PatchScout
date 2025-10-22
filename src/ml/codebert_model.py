"""
CodeBERT Model Integration for Vulnerability Detection
Uses pre-trained CodeBERT for semantic code understanding
"""

import torch
import torch.nn as nn
from transformers import (
    RobertaTokenizer,
    RobertaForSequenceClassification,
    RobertaConfig,
    AutoTokenizer,
    AutoModel
)
from typing import Dict, List, Tuple, Optional
import numpy as np


class CodeBERTVulnerabilityDetector(nn.Module):
    """
    CodeBERT-based vulnerability detection model
    Uses microsoft/codebert-base for code understanding
    """
    
    def __init__(
        self,
        num_labels: int = 2,  # Binary: vulnerable or not
        num_cwe_classes: int = 50,  # Top 50 CWE types
        model_name: str = "microsoft/codebert-base",
        dropout: float = 0.1
    ):
        """
        Initialize CodeBERT model
        
        Args:
            num_labels: Number of output labels (2 for binary classification)
            num_cwe_classes: Number of CWE classes to predict
            model_name: HuggingFace model name
            dropout: Dropout rate
        """
        super().__init__()
        
        print(f"🤖 Loading {model_name}...")
        
        # Load pre-trained CodeBERT
        self.codebert = AutoModel.from_pretrained(model_name)
        self.tokenizer = AutoTokenizer.from_pretrained(model_name)
        
        # Get hidden size
        self.hidden_size = self.codebert.config.hidden_size
        
        # Classification heads
        self.dropout = nn.Dropout(dropout)
        
        # Binary classification head (vulnerable or not)
        self.vulnerability_classifier = nn.Sequential(
            nn.Linear(self.hidden_size, 512),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(512, num_labels)
        )
        
        # Multi-class CWE classification head
        self.cwe_classifier = nn.Sequential(
            nn.Linear(self.hidden_size, 512),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(512, num_cwe_classes)
        )
        
        # Severity prediction head (Critical, High, Medium, Low)
        self.severity_classifier = nn.Sequential(
            nn.Linear(self.hidden_size, 256),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(256, 4)
        )
        
        print(f"✅ Model initialized with {self.count_parameters()} parameters")
    
    def count_parameters(self) -> int:
        """Count trainable parameters"""
        return sum(p.numel() for p in self.parameters() if p.requires_grad)
    
    def forward(
        self,
        input_ids: torch.Tensor,
        attention_mask: torch.Tensor,
        return_embeddings: bool = False
    ) -> Dict[str, torch.Tensor]:
        """
        Forward pass
        
        Args:
            input_ids: Token IDs
            attention_mask: Attention mask
            return_embeddings: Whether to return embeddings
            
        Returns:
            Dictionary with logits for each task
        """
        # Get CodeBERT embeddings
        outputs = self.codebert(
            input_ids=input_ids,
            attention_mask=attention_mask
        )
        
        # Use [CLS] token representation
        cls_output = outputs.last_hidden_state[:, 0, :]
        cls_output = self.dropout(cls_output)
        
        # Get predictions from each head
        vuln_logits = self.vulnerability_classifier(cls_output)
        cwe_logits = self.cwe_classifier(cls_output)
        severity_logits = self.severity_classifier(cls_output)
        
        result = {
            'vulnerability_logits': vuln_logits,
            'cwe_logits': cwe_logits,
            'severity_logits': severity_logits
        }
        
        if return_embeddings:
            result['embeddings'] = cls_output
        
        return result
    
    def freeze_base_model(self):
        """Freeze CodeBERT base model (only train classification heads)"""
        for param in self.codebert.parameters():
            param.requires_grad = False
        print("🔒 Froze CodeBERT base model parameters")
    
    def unfreeze_base_model(self):
        """Unfreeze CodeBERT base model"""
        for param in self.codebert.parameters():
            param.requires_grad = True
        print("🔓 Unfroze CodeBERT base model parameters")
    
    def tokenize(
        self,
        code_samples: List[str],
        max_length: int = 512,
        padding: str = 'max_length',
        truncation: bool = True
    ) -> Dict[str, torch.Tensor]:
        """
        Tokenize code samples
        
        Args:
            code_samples: List of code strings
            max_length: Maximum sequence length
            padding: Padding strategy
            truncation: Whether to truncate
            
        Returns:
            Dictionary with input_ids and attention_mask
        """
        return self.tokenizer(
            code_samples,
            max_length=max_length,
            padding=padding,
            truncation=truncation,
            return_tensors='pt'
        )
    
    def predict(
        self,
        code: str,
        device: str = 'cpu',
        threshold: float = 0.5
    ) -> Dict:
        """
        Predict vulnerability for a single code sample
        
        Args:
            code: Code string
            device: Device to run on
            threshold: Classification threshold
            
        Returns:
            Prediction dictionary
        """
        self.eval()
        self.to(device)
        
        with torch.no_grad():
            # Tokenize
            inputs = self.tokenize([code])
            input_ids = inputs['input_ids'].to(device)
            attention_mask = inputs['attention_mask'].to(device)
            
            # Forward pass
            outputs = self.forward(input_ids, attention_mask)
            
            # Get predictions
            vuln_probs = torch.softmax(outputs['vulnerability_logits'], dim=-1)
            cwe_probs = torch.softmax(outputs['cwe_logits'], dim=-1)
            severity_probs = torch.softmax(outputs['severity_logits'], dim=-1)
            
            vuln_pred = vuln_probs[0, 1].item()  # Probability of vulnerable
            cwe_pred = torch.argmax(cwe_probs, dim=-1)[0].item()
            severity_pred = torch.argmax(severity_probs, dim=-1)[0].item()
            
            severity_map = {0: 'Critical', 1: 'High', 2: 'Medium', 3: 'Low'}
            
            return {
                'is_vulnerable': vuln_pred > threshold,
                'vulnerability_score': vuln_pred,
                'predicted_cwe': cwe_pred,
                'predicted_severity': severity_map[severity_pred],
                'confidence': max(vuln_probs[0].tolist())
            }
    
    def save_model(self, path: str):
        """Save model checkpoint"""
        torch.save({
            'model_state_dict': self.state_dict(),
            'config': {
                'hidden_size': self.hidden_size,
                'num_labels': 2,
                'num_cwe_classes': 50
            }
        }, path)
        print(f"💾 Model saved to {path}")
    
    @classmethod
    def load_model(cls, path: str, device: str = 'cpu'):
        """Load model checkpoint"""
        checkpoint = torch.load(path, map_location=device)
        config = checkpoint['config']
        
        model = cls(
            num_labels=config['num_labels'],
            num_cwe_classes=config['num_cwe_classes']
        )
        model.load_state_dict(checkpoint['model_state_dict'])
        model.to(device)
        
        print(f"✅ Model loaded from {path}")
        return model


class GraphCodeBERTDetector(nn.Module):
    """
    GraphCodeBERT variant for vulnerability detection
    Better understanding of code structure and data flow
    """
    
    def __init__(
        self,
        num_labels: int = 2,
        model_name: str = "microsoft/graphcodebert-base",
        dropout: float = 0.1
    ):
        """Initialize GraphCodeBERT model"""
        super().__init__()
        
        print(f"🤖 Loading {model_name}...")
        
        try:
            self.model = AutoModel.from_pretrained(model_name)
            self.tokenizer = AutoTokenizer.from_pretrained(model_name)
            self.hidden_size = self.model.config.hidden_size
            
            # Classification head
            self.classifier = nn.Sequential(
                nn.Linear(self.hidden_size, 512),
                nn.ReLU(),
                nn.Dropout(dropout),
                nn.Linear(512, num_labels)
            )
            
            print(f"✅ GraphCodeBERT initialized")
        except Exception as e:
            print(f"⚠️  GraphCodeBERT not available: {e}")
            print("   Falling back to CodeBERT")
            # Fallback to CodeBERT
            self.model = AutoModel.from_pretrained("microsoft/codebert-base")
            self.tokenizer = AutoTokenizer.from_pretrained("microsoft/codebert-base")
            self.hidden_size = self.model.config.hidden_size
            self.classifier = nn.Sequential(
                nn.Linear(self.hidden_size, 512),
                nn.ReLU(),
                nn.Dropout(dropout),
                nn.Linear(512, num_labels)
            )
    
    def forward(self, input_ids, attention_mask):
        """Forward pass"""
        outputs = self.model(input_ids=input_ids, attention_mask=attention_mask)
        cls_output = outputs.last_hidden_state[:, 0, :]
        logits = self.classifier(cls_output)
        return logits


if __name__ == "__main__":
    # Test model loading
    print("Testing CodeBERT model...")
    
    try:
        model = CodeBERTVulnerabilityDetector()
        
        # Test prediction
        test_code = """
        def login(username, password):
            query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'"
            cursor.execute(query)
        """
        
        result = model.predict(test_code)
        print("\n🧪 Test Prediction:")
        print(f"   Vulnerable: {result['is_vulnerable']}")
        print(f"   Score: {result['vulnerability_score']:.3f}")
        print(f"   Severity: {result['predicted_severity']}")
        
    except Exception as e:
        print(f"⚠️  Error: {e}")
        print("   Make sure to install: pip install transformers torch")
