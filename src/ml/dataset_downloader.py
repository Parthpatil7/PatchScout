"""
Advanced Dataset Downloader and Preprocessor for ML Training
Handles all competition-recommended datasets
"""

import os
import json
import shutil
import zipfile
import tarfile
import requests
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from tqdm import tqdm
import pandas as pd


class MLDatasetDownloader:
    """Downloads and preprocesses datasets for ML training"""
    
    DATASETS = {
        'sard': {
            'name': 'SARD - Software Assurance Reference Dataset',
            'url': 'https://samate.nist.gov/SARD/',
            'manual': True,
            'format': 'various',
            'languages': ['C', 'C++', 'Java', 'PHP', 'Python'],
            'description': 'Real and synthetic vulnerable code samples from NIST'
        },
        'devign': {
            'name': 'Devign - GitHub Vulnerability Dataset',
            'url': 'https://github.com/epicosy/devign',
            'git_clone': 'https://github.com/epicosy/devign.git',
            'format': 'json',
            'languages': ['C'],
            'description': 'GitHub-based dataset with vulnerable/non-vulnerable labels'
        },
        'codexglue': {
            'name': 'CodeXGLUE Defect Detection',
            'url': 'https://github.com/microsoft/CodeXGLUE',
            'git_clone': 'https://github.com/microsoft/CodeXGLUE.git',
            'format': 'json',
            'languages': ['C'],
            'description': 'Dataset for defect prediction and repair'
        },
        'multilang': {
            'name': 'Multi-language Dataset (Oct 2024)',
            'url': 'https://zenodo.org/records/13870382',
            'download_url': 'https://zenodo.org/records/13870382/files/vulnerabilities_dataset.zip',
            'format': 'csv/json',
            'languages': ['C', 'C++', 'Java', 'JavaScript', 'Go', 'PHP', 'Ruby', 'Python'],
            'description': 'Multi-language with CWE/CVE labels and patches'
        },
        'megavul': {
            'name': 'MegaVul - Large-scale C/C++ Vulnerability Dataset',
            'url': 'https://github.com/Icyrockton/MegaVul',
            'git_clone': 'https://github.com/Icyrockton/MegaVul.git',
            'format': 'json',
            'languages': ['C', 'C++'],
            'description': 'CVE-linked vulnerabilities in JSON format'
        },
        'diversevul': {
            'name': 'DiverseVul - CWE Classification Dataset',
            'url': 'https://github.com/wagner-group/diversevul',
            'git_clone': 'https://github.com/wagner-group/diversevul.git',
            'format': 'json',
            'languages': ['C', 'C++'],
            'description': 'Vulnerable functions across CWE types'
        },
        'cae_vul': {
            'name': 'CAE Vulnerability Dataset',
            'url': 'https://github.com/CAE-Vuldataset/CAE-Vuldataset',
            'git_clone': 'https://github.com/CAE-Vuldataset/CAE-Vuldataset.git',
            'format': 'various',
            'languages': ['Multiple'],
            'description': 'Open source vulnerability dataset'
        },
        'vulnerability_dataset': {
            'name': 'GitHub Vulnerability Dataset',
            'url': 'https://github.com/ppakshad/VulnerabilityDataset',
            'git_clone': 'https://github.com/ppakshad/VulnerabilityDataset.git',
            'format': 'various',
            'languages': ['Multiple'],
            'description': 'Dataset for vulnerability detection and program analysis'
        }
    }
    
    def __init__(self, data_dir: str = "data/raw"):
        """
        Initialize dataset downloader
        
        Args:
            data_dir: Directory to store downloaded datasets
        """
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.processed_dir = Path("data/processed")
        self.processed_dir.mkdir(parents=True, exist_ok=True)
    
    def list_datasets(self):
        """List all available datasets with details"""
        print("\n" + "="*80)
        print("AVAILABLE TRAINING DATASETS FOR ML MODEL")
        print("="*80)
        
        for key, info in self.DATASETS.items():
            print(f"\n📦 {key.upper()}")
            print(f"   Name: {info['name']}")
            print(f"   URL: {info['url']}")
            print(f"   Format: {info['format']}")
            print(f"   Languages: {', '.join(info['languages'])}")
            print(f"   Description: {info['description']}")
            if info.get('manual'):
                print(f"   ⚠️  Manual download required")
    
    def download_dataset(self, dataset_name: str, force: bool = False) -> Path:
        """
        Download a specific dataset
        
        Args:
            dataset_name: Name of the dataset to download
            force: Force re-download even if dataset exists
            
        Returns:
            Path to downloaded dataset
        """
        if dataset_name not in self.DATASETS:
            raise ValueError(f"Unknown dataset: {dataset_name}. Available: {list(self.DATASETS.keys())}")
        
        info = self.DATASETS[dataset_name]
        dataset_path = self.data_dir / dataset_name
        
        if dataset_path.exists() and not force:
            print(f"✓ Dataset '{dataset_name}' already exists at {dataset_path}")
            return dataset_path
        
        print(f"\n📥 Downloading {info['name']}...")
        
        # Handle git clone datasets
        if 'git_clone' in info:
            return self._clone_git_repo(info['git_clone'], dataset_path)
        
        # Handle direct download
        elif 'download_url' in info:
            return self._download_file(info['download_url'], dataset_path)
        
        # Manual download required
        else:
            print(f"\n⚠️  Manual Download Required")
            print(f"   Please visit: {info['url']}")
            print(f"   Download the dataset and extract it to: {dataset_path}")
            dataset_path.mkdir(parents=True, exist_ok=True)
            return dataset_path
    
    def _clone_git_repo(self, git_url: str, target_path: Path) -> Path:
        """Clone a git repository"""
        import subprocess
        
        target_path.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            print(f"   Cloning from {git_url}...")
            subprocess.run(
                ['git', 'clone', git_url, str(target_path)],
                check=True,
                capture_output=True
            )
            print(f"   ✓ Successfully cloned to {target_path}")
            return target_path
        except subprocess.CalledProcessError as e:
            print(f"   ✗ Error cloning repository: {e}")
            print(f"   Please manually clone: git clone {git_url} {target_path}")
            target_path.mkdir(parents=True, exist_ok=True)
            return target_path
    
    def _download_file(self, url: str, target_path: Path) -> Path:
        """Download a file with progress bar"""
        target_path.mkdir(parents=True, exist_ok=True)
        filename = url.split('/')[-1]
        file_path = target_path / filename
        
        try:
            response = requests.get(url, stream=True)
            response.raise_for_status()
            
            total_size = int(response.headers.get('content-length', 0))
            
            with open(file_path, 'wb') as f, tqdm(
                total=total_size,
                unit='B',
                unit_scale=True,
                desc=filename
            ) as pbar:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
                    pbar.update(len(chunk))
            
            # Extract if zip or tar
            if filename.endswith('.zip'):
                with zipfile.ZipFile(file_path, 'r') as zip_ref:
                    zip_ref.extractall(target_path)
                file_path.unlink()  # Remove zip file
            elif filename.endswith(('.tar.gz', '.tgz')):
                with tarfile.open(file_path, 'r:gz') as tar_ref:
                    tar_ref.extractall(target_path)
                file_path.unlink()  # Remove tar file
            
            print(f"   ✓ Downloaded and extracted to {target_path}")
            return target_path
            
        except Exception as e:
            print(f"   ✗ Error downloading: {e}")
            print(f"   Please manually download from: {url}")
            return target_path
    
    def download_all(self, skip_manual: bool = True):
        """
        Download all datasets
        
        Args:
            skip_manual: Skip datasets that require manual download
        """
        print("\n🚀 Starting bulk dataset download...")
        
        for dataset_name, info in self.DATASETS.items():
            if skip_manual and info.get('manual'):
                print(f"\n⏭️  Skipping {dataset_name} (manual download required)")
                continue
            
            try:
                self.download_dataset(dataset_name)
            except Exception as e:
                print(f"✗ Error downloading {dataset_name}: {e}")
        
        print("\n✅ Dataset download process completed!")
    
    def preprocess_dataset(self, dataset_name: str) -> pd.DataFrame:
        """
        Preprocess a dataset into unified format
        
        Args:
            dataset_name: Name of the dataset to preprocess
            
        Returns:
            DataFrame with columns: code, label, cwe, cve, language, severity
        """
        dataset_path = self.data_dir / dataset_name
        
        if not dataset_path.exists():
            raise FileNotFoundError(f"Dataset not found: {dataset_path}")
        
        print(f"\n🔄 Preprocessing {dataset_name}...")
        
        # Dataset-specific preprocessing
        if dataset_name == 'devign':
            return self._preprocess_devign(dataset_path)
        elif dataset_name == 'megavul':
            return self._preprocess_megavul(dataset_path)
        elif dataset_name == 'diversevul':
            return self._preprocess_diversevul(dataset_path)
        elif dataset_name == 'multilang':
            return self._preprocess_multilang(dataset_path)
        else:
            print(f"   ⚠️  No specific preprocessor for {dataset_name}")
            return pd.DataFrame()
    
    def _preprocess_devign(self, path: Path) -> pd.DataFrame:
        """Preprocess Devign dataset"""
        # Look for JSON file
        json_files = list(path.glob("**/*.json"))
        
        if not json_files:
            print("   ⚠️  No JSON files found in Devign dataset")
            return pd.DataFrame()
        
        data = []
        for json_file in json_files:
            with open(json_file, 'r') as f:
                records = json.load(f)
                if isinstance(records, list):
                    data.extend(records)
                else:
                    data.append(records)
        
        df = pd.DataFrame(data)
        print(f"   ✓ Loaded {len(df)} samples from Devign")
        return df
    
    def _preprocess_megavul(self, path: Path) -> pd.DataFrame:
        """Preprocess MegaVul dataset"""
        json_files = list(path.glob("**/*.json"))
        
        data = []
        for json_file in json_files[:100]:  # Sample first 100 files
            try:
                with open(json_file, 'r', encoding='utf-8') as f:
                    record = json.load(f)
                    data.append(record)
            except Exception as e:
                continue
        
        df = pd.DataFrame(data)
        print(f"   ✓ Loaded {len(df)} samples from MegaVul")
        return df
    
    def _preprocess_diversevul(self, path: Path) -> pd.DataFrame:
        """Preprocess DiverseVul dataset"""
        # Look for CSV or JSON files
        csv_files = list(path.glob("**/*.csv"))
        
        if csv_files:
            df = pd.concat([pd.read_csv(f) for f in csv_files], ignore_index=True)
            print(f"   ✓ Loaded {len(df)} samples from DiverseVul")
            return df
        
        return pd.DataFrame()
    
    def _preprocess_multilang(self, path: Path) -> pd.DataFrame:
        """Preprocess Multi-language dataset"""
        csv_files = list(path.glob("**/*.csv"))
        json_files = list(path.glob("**/*.json"))
        
        dfs = []
        
        for csv_file in csv_files:
            try:
                df = pd.read_csv(csv_file)
                dfs.append(df)
            except Exception as e:
                print(f"   ⚠️  Error reading {csv_file}: {e}")
        
        if dfs:
            df = pd.concat(dfs, ignore_index=True)
            print(f"   ✓ Loaded {len(df)} samples from Multi-language dataset")
            return df
        
        return pd.DataFrame()


if __name__ == "__main__":
    downloader = MLDatasetDownloader()
    
    # List available datasets
    downloader.list_datasets()
    
    # Download specific datasets
    print("\n" + "="*80)
    print("DOWNLOADING RECOMMENDED DATASETS")
    print("="*80)
    
    # Download automatically downloadable datasets
    for dataset_name in ['devign', 'codexglue', 'megavul', 'diversevul']:
        try:
            downloader.download_dataset(dataset_name)
        except Exception as e:
            print(f"Error: {e}")
