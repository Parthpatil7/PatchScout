"""ML module — Stream B: DeepSeek 6.7B (local via Ollama) + Tree-sitter AST"""

from .ast_extractor  import ASTExtractor
from .deepseek_runner import DeepSeekRunner
from .hybrid_detector import HybridVulnerabilityDetector, MLModelManager

__all__ = [
    "ASTExtractor",
    "DeepSeekRunner",
    "HybridVulnerabilityDetector",
    "MLModelManager",
]
