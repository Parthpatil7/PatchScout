"""Data loader metadata utility for training and benchmark datasets (experimental)."""

from pathlib import Path
from typing import Dict, Any
import logging

logger = logging.getLogger(__name__)


class DatasetLoader:
    """Handles dataset registry, download location prep, and metadata loading."""

    DATASETS = {
        'sard': {
            'name': 'Software Assurance Reference Dataset',
            'url': 'https://samate.nist.gov/SARD/',
            'description': 'Real and synthetic vulnerable code samples',
        },
        'devign': {
            'name': 'Devign Dataset',
            'url': 'https://github.com/epicosy/devign',
            'description': 'GitHub-based dataset with vulnerable/non-vulnerable labels',
        },
        'codexglue': {
            'name': 'CodeXGLUE Defect Detection',
            'url': 'https://github.com/microsoft/CodeXGLUE',
            'description': 'Dataset for defect prediction and repair',
        },
        'multilang': {
            'name': 'Multi-language Dataset (2024)',
            'url': 'https://zenodo.org/records/13870382',
            'description': 'C, C++, Java, JS, Go, PHP, Ruby, Python with CWE/CVE labels',
        },
        'megavul': {
            'name': 'MegaVul',
            'url': 'https://github.com/Icyrockton/MegaVul',
            'description': 'C/C++ vulnerabilities from repositories, CVE-linked',
        },
        'diversevul': {
            'name': 'DiverseVul',
            'url': 'https://github.com/wagner-group/diversevul',
            'description': 'Vulnerable functions across CWE types',
        },
    }

    def __init__(self, data_dir: str = 'data/raw'):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)

    def list_datasets(self):
        """List all available datasets."""
        print('Available Datasets:')
        print('=' * 80)
        for key, info in self.DATASETS.items():
            print(f"\n{key.upper()}")
            print(f"  Name: {info['name']}")
            print(f"  URL: {info['url']}")
            print(f"  Description: {info['description']}")

    def download_dataset(self, dataset_name: str, force: bool = False):
        """
        Prepare local directory for dataset download.

        Note: Actual dataset retrieval is intentionally manual and experimental.
        """
        if dataset_name not in self.DATASETS:
            raise ValueError(f'Unknown dataset: {dataset_name}')

        dataset_info = self.DATASETS[dataset_name]
        dataset_path = self.data_dir / dataset_name

        if dataset_path.exists() and not force:
            logger.info('dataset path already exists: %s', dataset_path)
            return dataset_path

        logger.warning(
            'dataset download is experimental/manual for %s; follow source URL %s',
            dataset_name,
            dataset_info['url'],
        )

        dataset_path.mkdir(parents=True, exist_ok=True)
        return dataset_path

    def load_dataset(self, dataset_name: str) -> Dict[str, Any]:
        """
        Load dataset metadata from local path.

        This method currently returns metadata only and is marked experimental.
        """
        dataset_path = self.data_dir / dataset_name

        if not dataset_path.exists():
            raise FileNotFoundError(f'Dataset not found: {dataset_path}')

        logger.warning('dataset loading is experimental; returning metadata only for %s', dataset_name)

        files = [str(path) for path in dataset_path.rglob('*') if path.is_file()]
        return {
            'dataset': dataset_name,
            'path': str(dataset_path),
            'status': 'experimental',
            'file_count': len(files),
            'files': files,
        }


if __name__ == '__main__':
    loader = DatasetLoader()
    loader.list_datasets()
