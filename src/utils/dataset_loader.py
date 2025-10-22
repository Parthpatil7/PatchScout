"""
Data loader for training and benchmark datasets
"""

import os
import requests
from pathlib import Path
from typing import Optional
from tqdm import tqdm


class DatasetLoader:
    """Handles downloading and loading of vulnerability datasets"""
    
    DATASETS = {
        'sard': {
            'name': 'Software Assurance Reference Dataset',
            'url': 'https://samate.nist.gov/SARD/',
            'description': 'Real and synthetic vulnerable code samples'
        },
        'devign': {
            'name': 'Devign Dataset',
            'url': 'https://github.com/epicosy/devign',
            'description': 'GitHub-based dataset with vulnerable/non-vulnerable labels'
        },
        'codexglue': {
            'name': 'CodeXGLUE Defect Detection',
            'url': 'https://github.com/microsoft/CodeXGLUE',
            'description': 'Dataset for defect prediction and repair'
        },
        'multilang': {
            'name': 'Multi-language Dataset (2024)',
            'url': 'https://zenodo.org/records/13870382',
            'description': 'C, C++, Java, JS, Go, PHP, Ruby, Python with CWE/CVE labels'
        },
        'megavul': {
            'name': 'MegaVul',
            'url': 'https://github.com/Icyrockton/MegaVul',
            'description': 'C/C++ vulnerabilities from repositories, CVE-linked'
        },
        'diversevul': {
            'name': 'DiverseVul',
            'url': 'https://github.com/wagner-group/diversevul',
            'description': 'Vulnerable functions across CWE types'
        }
    }
    
    def __init__(self, data_dir: str = "data/raw"):
        """
        Initialize dataset loader
        
        Args:
            data_dir: Directory to store downloaded datasets
        """
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
    
    def list_datasets(self):
        """List all available datasets"""
        print("Available Datasets:")
        print("=" * 80)
        for key, info in self.DATASETS.items():
            print(f"\n{key.upper()}")
            print(f"  Name: {info['name']}")
            print(f"  URL: {info['url']}")
            print(f"  Description: {info['description']}")
    
    def download_dataset(self, dataset_name: str, force: bool = False):
        """
        Download a specific dataset
        
        Args:
            dataset_name: Name of the dataset to download
            force: Force re-download even if dataset exists
        """
        if dataset_name not in self.DATASETS:
            raise ValueError(f"Unknown dataset: {dataset_name}")
        
        dataset_info = self.DATASETS[dataset_name]
        dataset_path = self.data_dir / dataset_name
        
        if dataset_path.exists() and not force:
            print(f"Dataset {dataset_name} already exists at {dataset_path}")
            return dataset_path
        
        print(f"Downloading {dataset_info['name']}...")
        print(f"URL: {dataset_info['url']}")
        print(f"Note: Please follow the instructions at the URL to download the dataset.")
        print(f"Save it to: {dataset_path}")
        
        dataset_path.mkdir(parents=True, exist_ok=True)
        
        return dataset_path
    
    def load_dataset(self, dataset_name: str):
        """
        Load a downloaded dataset
        
        Args:
            dataset_name: Name of the dataset to load
            
        Returns:
            Loaded dataset (format depends on dataset type)
        """
        dataset_path = self.data_dir / dataset_name
        
        if not dataset_path.exists():
            raise FileNotFoundError(f"Dataset not found: {dataset_path}")
        
        # TODO: Implement dataset-specific loading logic
        print(f"Loading dataset from {dataset_path}...")
        
        return None


if __name__ == "__main__":
    # Example usage
    loader = DatasetLoader()
    loader.list_datasets()
