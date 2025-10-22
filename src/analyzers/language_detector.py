"""Automatic language detection"""

from pathlib import Path
from typing import Optional


class LanguageDetector:
    """Automatically detect programming language from file"""
    
    def __init__(self):
        """Initialize language detector"""
        self.extension_map = {
            '.py': 'python',
            '.pyw': 'python',
            '.java': 'java',
            '.c': 'c',
            '.h': 'c',
            '.cpp': 'cpp',
            '.cc': 'cpp',
            '.cxx': 'cpp',
            '.hpp': 'cpp',
            '.php': 'php',
            '.php3': 'php',
            '.php4': 'php',
            '.php5': 'php',
            '.phtml': 'php',
            '.rb': 'ruby',
            '.rs': 'rust',
            '.kt': 'kotlin',
            '.kts': 'kotlin',
            '.swift': 'swift',
            '.js': 'javascript',
            '.jsx': 'javascript',
            '.ts': 'typescript',
            '.tsx': 'typescript',
            '.go': 'go',
            '.html': 'html',
            '.htm': 'html'
        }
        
    def detect(self, file_path: str) -> Optional[str]:
        """
        Detect language from file path
        
        Args:
            file_path: Path to the file
            
        Returns:
            Language name or None if not detected
        """
        path = Path(file_path)
        extension = path.suffix.lower()
        
        return self.extension_map.get(extension)
    
    def is_supported(self, file_path: str, stage: int = 1) -> bool:
        """
        Check if file language is supported for given stage
        
        Args:
            file_path: Path to the file
            stage: Competition stage (1, 2, or 3)
            
        Returns:
            True if language is supported
        """
        language = self.detect(file_path)
        
        if not language:
            return False
        
        stage_1_langs = ['java', 'python', 'c', 'cpp', 'php']
        stage_2_langs = stage_1_langs + ['ruby', 'rust', 'kotlin', 'swift']
        stage_3_langs = stage_2_langs + ['javascript', 'typescript', 'go', 'html']
        
        if stage == 1:
            return language in stage_1_langs
        elif stage == 2:
            return language in stage_2_langs
        else:
            return language in stage_3_langs
