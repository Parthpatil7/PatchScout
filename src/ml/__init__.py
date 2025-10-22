"""ML module for PatchScout"""

from .codebert_model import CodeBERTVulnerabilityDetector, GraphCodeBERTDetector
from .dataset_downloader import MLDatasetDownloader
from .data_preprocessor import CodePreprocessor
from .trainer import VulnerabilityDataset, VulnerabilityTrainer
from .hybrid_detector import HybridVulnerabilityDetector, MLModelManager

__all__ = [
    'CodeBERTVulnerabilityDetector',
    'GraphCodeBERTDetector',
    'MLDatasetDownloader',
    'CodePreprocessor',
    'VulnerabilityDataset',
    'VulnerabilityTrainer',
    'HybridVulnerabilityDetector',
    'MLModelManager'
]
