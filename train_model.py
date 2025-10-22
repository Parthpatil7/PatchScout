"""
Main Training Script for CodeBERT Vulnerability Detection
Run this to train the model on downloaded datasets
"""

import sys
import argparse
from pathlib import Path
import pandas as pd
import torch
from torch.utils.data import DataLoader

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.ml.dataset_downloader import MLDatasetDownloader
from src.ml.data_preprocessor import CodePreprocessor
from src.ml.codebert_model import CodeBERTVulnerabilityDetector
from src.ml.trainer import VulnerabilityDataset, VulnerabilityTrainer


def create_cwe_mapping(df: pd.DataFrame) -> dict:
    """Create CWE to index mapping"""
    unique_cwes = df['cwe'].dropna().unique()
    cwe_to_idx = {cwe: idx + 1 for idx, cwe in enumerate(unique_cwes)}  # 0 is reserved for unknown
    cwe_to_idx[None] = 0
    return cwe_to_idx


def main():
    parser = argparse.ArgumentParser(description='Train CodeBERT Vulnerability Detection Model')
    
    # Data arguments
    parser.add_argument('--data-dir', type=str, default='data/raw',
                       help='Directory containing raw datasets')
    parser.add_argument('--processed-dir', type=str, default='data/processed',
                       help='Directory for processed data')
    parser.add_argument('--download', action='store_true',
                       help='Download datasets before training')
    parser.add_argument('--datasets', nargs='+',
                       default=['devign', 'megavul', 'diversevul'],
                       help='Datasets to use for training')
    
    # Model arguments
    parser.add_argument('--model-name', type=str, default='microsoft/codebert-base',
                       help='Pretrained model name')
    parser.add_argument('--max-length', type=int, default=512,
                       help='Maximum sequence length')
    parser.add_argument('--num-cwe-classes', type=int, default=50,
                       help='Number of CWE classes')
    
    # Training arguments
    parser.add_argument('--batch-size', type=int, default=8,
                       help='Batch size for training')
    parser.add_argument('--learning-rate', type=float, default=2e-5,
                       help='Learning rate')
    parser.add_argument('--num-epochs', type=int, default=5,
                       help='Number of epochs')
    parser.add_argument('--warmup-steps', type=int, default=500,
                       help='Warmup steps')
    parser.add_argument('--freeze-base', action='store_true',
                       help='Freeze base model (only train classification heads)')
    
    # Output arguments
    parser.add_argument('--output-dir', type=str, default='models/checkpoints',
                       help='Directory to save model checkpoints')
    
    # Device
    parser.add_argument('--device', type=str, default='cuda' if torch.cuda.is_available() else 'cpu',
                       help='Device to use (cuda/cpu)')
    
    args = parser.parse_args()
    
    print("\n" + "="*80)
    print("PATCHSCOUT ML TRAINING PIPELINE")
    print("="*80)
    
    # Step 1: Download datasets
    if args.download:
        print("\n📥 STEP 1: Downloading datasets...")
        downloader = MLDatasetDownloader(data_dir=args.data_dir)
        
        for dataset_name in args.datasets:
            try:
                downloader.download_dataset(dataset_name)
            except Exception as e:
                print(f"⚠️  Error downloading {dataset_name}: {e}")
    else:
        print("\n⏭️  Skipping dataset download (use --download to enable)")
    
    # Step 2: Preprocess datasets
    print("\n🔄 STEP 2: Preprocessing datasets...")
    preprocessor = CodePreprocessor()
    downloader = MLDatasetDownloader(data_dir=args.data_dir)
    
    # Load and preprocess each dataset
    datasets = {}
    for dataset_name in args.datasets:
        try:
            df = downloader.preprocess_dataset(dataset_name)
            if not df.empty:
                datasets[dataset_name] = df
        except Exception as e:
            print(f"⚠️  Error preprocessing {dataset_name}: {e}")
    
    if not datasets:
        print("❌ No datasets loaded. Please check dataset availability.")
        return
    
    # Create unified dataset
    unified_df = preprocessor.create_unified_dataset(datasets)
    
    if len(unified_df) < 100:
        print(f"⚠️  Warning: Only {len(unified_df)} samples. This may not be enough for training.")
        print("   Consider downloading more datasets or using manual datasets.")
    
    # Split dataset
    train_df, val_df, test_df = preprocessor.split_dataset(unified_df)
    
    # Save processed data
    processed_dir = Path(args.processed_dir)
    preprocessor.save_processed_data(train_df, processed_dir / 'train')
    preprocessor.save_processed_data(val_df, processed_dir / 'val')
    preprocessor.save_processed_data(test_df, processed_dir / 'test')
    
    # Step 3: Create CWE mapping
    print("\n🗺️  STEP 3: Creating CWE mappings...")
    cwe_to_idx = create_cwe_mapping(unified_df)
    print(f"   Found {len(cwe_to_idx)} unique CWEs")
    
    # Step 4: Initialize model
    print("\n🤖 STEP 4: Initializing CodeBERT model...")
    model = CodeBERTVulnerabilityDetector(
        num_labels=2,
        num_cwe_classes=args.num_cwe_classes,
        model_name=args.model_name
    )
    
    if args.freeze_base:
        model.freeze_base_model()
    
    # Step 5: Create data loaders
    print("\n📦 STEP 5: Creating data loaders...")
    train_dataset = VulnerabilityDataset(
        train_df,
        model.tokenizer,
        max_length=args.max_length,
        cwe_to_idx=cwe_to_idx
    )
    val_dataset = VulnerabilityDataset(
        val_df,
        model.tokenizer,
        max_length=args.max_length,
        cwe_to_idx=cwe_to_idx
    )
    
    train_loader = DataLoader(
        train_dataset,
        batch_size=args.batch_size,
        shuffle=True,
        num_workers=0  # Set to 0 for Windows compatibility
    )
    val_loader = DataLoader(
        val_dataset,
        batch_size=args.batch_size,
        shuffle=False,
        num_workers=0
    )
    
    # Step 6: Train model
    print("\n🚀 STEP 6: Starting training...")
    trainer = VulnerabilityTrainer(
        model=model,
        train_loader=train_loader,
        val_loader=val_loader,
        device=args.device,
        learning_rate=args.learning_rate,
        num_epochs=args.num_epochs,
        warmup_steps=args.warmup_steps,
        output_dir=args.output_dir
    )
    
    trainer.train()
    
    # Step 7: Save final model
    print("\n💾 STEP 7: Saving final model...")
    final_model_path = Path(args.output_dir) / 'final_model.pt'
    model.save_model(str(final_model_path))
    
    # Save CWE mapping
    import json
    cwe_mapping_path = Path(args.output_dir) / 'cwe_mapping.json'
    with open(cwe_mapping_path, 'w') as f:
        json.dump(cwe_to_idx, f, indent=2)
    print(f"   Saved CWE mapping to {cwe_mapping_path}")
    
    print("\n" + "="*80)
    print("✅ TRAINING PIPELINE COMPLETED SUCCESSFULLY")
    print("="*80)
    print(f"\nModel saved to: {final_model_path}")
    print(f"\nTo use the model:")
    print(f"  python -m src.main -d test_samples --use-ml-model")


if __name__ == "__main__":
    main()
