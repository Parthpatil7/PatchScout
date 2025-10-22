"""
Data Preprocessing Pipeline for ML Training
Converts raw code samples into model-ready format
"""

import re
import ast
import pandas as pd
import numpy as np
from typing import Dict, List, Tuple, Optional
from pathlib import Path
import json
from tqdm import tqdm


class CodePreprocessor:
    """Preprocesses code samples for ML training"""
    
    def __init__(self):
        """Initialize preprocessor"""
        self.max_length = 512  # Maximum token length for CodeBERT
        self.min_length = 10   # Minimum code length
        
    def clean_code(self, code: str, language: str) -> str:
        """
        Clean and normalize code
        
        Args:
            code: Raw code string
            language: Programming language
            
        Returns:
            Cleaned code
        """
        if not code or not isinstance(code, str):
            return ""
        
        # Remove excessive whitespace
        code = re.sub(r'\n\s*\n', '\n\n', code)
        
        # Remove comments based on language
        if language.lower() in ['python']:
            # Remove Python comments
            code = re.sub(r'#.*$', '', code, flags=re.MULTILINE)
            code = re.sub(r'""".*?"""', '', code, flags=re.DOTALL)
            code = re.sub(r"'''.*?'''", '', code, flags=re.DOTALL)
        elif language.lower() in ['java', 'c', 'c++', 'javascript', 'php']:
            # Remove C-style comments
            code = re.sub(r'//.*$', '', code, flags=re.MULTILINE)
            code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
        
        # Normalize whitespace
        code = re.sub(r'[ \t]+', ' ', code)
        code = code.strip()
        
        return code
    
    def extract_features(self, code: str, language: str) -> Dict:
        """
        Extract code features for analysis
        
        Args:
            code: Code string
            language: Programming language
            
        Returns:
            Dictionary of features
        """
        features = {
            'length': len(code),
            'num_lines': code.count('\n') + 1,
            'num_functions': 0,
            'num_loops': 0,
            'num_conditionals': 0,
            'complexity': 0
        }
        
        # Count common patterns
        features['num_loops'] = len(re.findall(r'\b(for|while)\b', code))
        features['num_conditionals'] = len(re.findall(r'\bif\b', code))
        
        # Count functions based on language
        if language.lower() == 'python':
            features['num_functions'] = len(re.findall(r'\ndef\s+\w+', code))
        elif language.lower() in ['java', 'c', 'c++']:
            features['num_functions'] = len(re.findall(r'\b\w+\s+\w+\s*\([^)]*\)\s*\{', code))
        
        # Basic cyclomatic complexity estimate
        features['complexity'] = features['num_conditionals'] + features['num_loops'] + 1
        
        return features
    
    def tokenize_code(self, code: str, language: str) -> List[str]:
        """
        Simple tokenization of code
        
        Args:
            code: Code string
            language: Programming language
            
        Returns:
            List of tokens
        """
        # Split by common delimiters
        tokens = re.findall(r'\w+|[^\w\s]', code)
        return tokens[:self.max_length]
    
    def normalize_labels(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Normalize vulnerability labels across datasets
        
        Args:
            df: DataFrame with vulnerability labels
            
        Returns:
            DataFrame with normalized labels
        """
        # Map common label variations to standard format
        label_mapping = {
            'vulnerable': 1,
            'vuln': 1,
            'true': 1,
            'yes': 1,
            '1': 1,
            1: 1,
            'non-vulnerable': 0,
            'non_vulnerable': 0,
            'safe': 0,
            'false': 0,
            'no': 0,
            '0': 0,
            0: 0
        }
        
        if 'label' in df.columns:
            df['label'] = df['label'].map(lambda x: label_mapping.get(str(x).lower(), 0))
        elif 'target' in df.columns:
            df['label'] = df['target'].map(lambda x: label_mapping.get(str(x).lower(), 0))
        elif 'vulnerable' in df.columns:
            df['label'] = df['vulnerable'].map(lambda x: label_mapping.get(str(x).lower(), 0))
        
        return df
    
    def extract_cwe_info(self, text: str) -> Optional[str]:
        """
        Extract CWE ID from text
        
        Args:
            text: Text containing CWE information
            
        Returns:
            CWE ID or None
        """
        if not text or not isinstance(text, str):
            return None
        
        # Match CWE-XXX pattern
        match = re.search(r'CWE-(\d+)', text, re.IGNORECASE)
        if match:
            return f"CWE-{match.group(1)}"
        
        return None
    
    def extract_cve_info(self, text: str) -> Optional[str]:
        """
        Extract CVE ID from text
        
        Args:
            text: Text containing CVE information
            
        Returns:
            CVE ID or None
        """
        if not text or not isinstance(text, str):
            return None
        
        # Match CVE-YYYY-XXXXX pattern
        match = re.search(r'CVE-\d{4}-\d{4,}', text, re.IGNORECASE)
        if match:
            return match.group(0).upper()
        
        return None
    
    def create_unified_dataset(self, datasets: Dict[str, pd.DataFrame]) -> pd.DataFrame:
        """
        Merge multiple datasets into unified format
        
        Args:
            datasets: Dictionary of dataset_name -> DataFrame
            
        Returns:
            Unified DataFrame with standard columns
        """
        unified_data = []
        
        print("\n🔄 Creating unified dataset...")
        
        for dataset_name, df in datasets.items():
            print(f"\n   Processing {dataset_name}...")
            
            if df.empty:
                print(f"   ⚠️  Empty dataset: {dataset_name}")
                continue
            
            # Normalize labels
            df = self.normalize_labels(df)
            
            # Extract relevant columns
            for idx, row in tqdm(df.iterrows(), total=len(df), desc=f"   {dataset_name}"):
                # Extract code
                code = None
                if 'func' in row:
                    code = row['func']
                elif 'code' in row:
                    code = row['code']
                elif 'source' in row:
                    code = row['source']
                
                if not code or len(str(code)) < self.min_length:
                    continue
                
                # Extract language
                language = 'C'  # Default
                if 'language' in row:
                    language = row['language']
                elif 'lang' in row:
                    language = row['lang']
                
                # Extract label
                label = row.get('label', 0)
                
                # Extract CWE/CVE
                cwe = None
                cve = None
                
                for col in ['cwe', 'CWE', 'cwe_id']:
                    if col in row:
                        cwe = self.extract_cwe_info(str(row[col]))
                        break
                
                for col in ['cve', 'CVE', 'cve_id']:
                    if col in row:
                        cve = self.extract_cve_info(str(row[col]))
                        break
                
                # Clean code
                clean_code = self.clean_code(str(code), language)
                
                if len(clean_code) < self.min_length:
                    continue
                
                # Extract features
                features = self.extract_features(clean_code, language)
                
                unified_data.append({
                    'code': clean_code,
                    'label': int(label),
                    'language': language,
                    'cwe': cwe,
                    'cve': cve,
                    'dataset_source': dataset_name,
                    'length': features['length'],
                    'num_lines': features['num_lines'],
                    'complexity': features['complexity']
                })
        
        unified_df = pd.DataFrame(unified_data)
        
        print(f"\n✅ Unified dataset created:")
        print(f"   Total samples: {len(unified_df)}")
        print(f"   Vulnerable: {(unified_df['label'] == 1).sum()}")
        print(f"   Non-vulnerable: {(unified_df['label'] == 0).sum()}")
        print(f"   Languages: {unified_df['language'].value_counts().to_dict()}")
        
        return unified_df
    
    def split_dataset(
        self,
        df: pd.DataFrame,
        train_ratio: float = 0.7,
        val_ratio: float = 0.15,
        test_ratio: float = 0.15,
        stratify: bool = True
    ) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
        """
        Split dataset into train/val/test
        
        Args:
            df: Input DataFrame
            train_ratio: Training set ratio
            val_ratio: Validation set ratio
            test_ratio: Test set ratio
            stratify: Whether to stratify by label
            
        Returns:
            Tuple of (train_df, val_df, test_df)
        """
        from sklearn.model_selection import train_test_split
        
        # Shuffle dataset
        df = df.sample(frac=1, random_state=42).reset_index(drop=True)
        
        if stratify:
            stratify_col = df['label']
        else:
            stratify_col = None
        
        # First split: train + rest
        train_df, temp_df = train_test_split(
            df,
            test_size=(1 - train_ratio),
            stratify=stratify_col,
            random_state=42
        )
        
        # Second split: val + test
        val_size = val_ratio / (val_ratio + test_ratio)
        val_df, test_df = train_test_split(
            temp_df,
            test_size=(1 - val_size),
            stratify=temp_df['label'] if stratify else None,
            random_state=42
        )
        
        print(f"\n📊 Dataset split:")
        print(f"   Training: {len(train_df)} samples ({train_ratio*100:.1f}%)")
        print(f"   Validation: {len(val_df)} samples ({val_ratio*100:.1f}%)")
        print(f"   Test: {len(test_df)} samples ({test_ratio*100:.1f}%)")
        
        return train_df, val_df, test_df
    
    def save_processed_data(self, df: pd.DataFrame, output_path: Path):
        """
        Save processed dataset
        
        Args:
            df: Processed DataFrame
            output_path: Output file path
        """
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Save as CSV
        csv_path = output_path.with_suffix('.csv')
        df.to_csv(csv_path, index=False)
        print(f"   ✓ Saved CSV to {csv_path}")
        
        # Save as JSON (for CodeBERT)
        json_path = output_path.with_suffix('.json')
        df.to_json(json_path, orient='records', lines=True)
        print(f"   ✓ Saved JSON to {json_path}")
        
        # Save statistics
        stats = {
            'total_samples': len(df),
            'vulnerable_samples': int((df['label'] == 1).sum()),
            'non_vulnerable_samples': int((df['label'] == 0).sum()),
            'languages': df['language'].value_counts().to_dict(),
            'avg_length': float(df['length'].mean()),
            'avg_complexity': float(df['complexity'].mean())
        }
        
        stats_path = output_path.parent / 'dataset_stats.json'
        with open(stats_path, 'w') as f:
            json.dump(stats, f, indent=2)
        print(f"   ✓ Saved statistics to {stats_path}")


if __name__ == "__main__":
    preprocessor = CodePreprocessor()
    print("✅ Code preprocessor initialized")
