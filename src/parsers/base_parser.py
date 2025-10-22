"""Base parser class for all language parsers"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
from pathlib import Path


class BaseParser(ABC):
    """Abstract base class for language-specific parsers"""
    
    def __init__(self, language: str):
        """
        Initialize parser
        
        Args:
            language: Programming language identifier
        """
        self.language = language
        self.file_extensions = []
        
    @abstractmethod
    def parse(self, code: str, file_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Parse source code and return AST/analysis
        
        Args:
            code: Source code string
            file_path: Optional file path for context
            
        Returns:
            Dictionary containing parsed information
        """
        pass
    
    @abstractmethod
    def extract_functions(self, parsed_code: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Extract function definitions from parsed code
        
        Args:
            parsed_code: Parsed code dictionary
            
        Returns:
            List of function definitions with metadata
        """
        pass
    
    @abstractmethod
    def extract_imports(self, parsed_code: Dict[str, Any]) -> List[str]:
        """
        Extract import statements
        
        Args:
            parsed_code: Parsed code dictionary
            
        Returns:
            List of imported modules/packages
        """
        pass
    
    def can_parse(self, file_path: str) -> bool:
        """
        Check if this parser can handle the file
        
        Args:
            file_path: Path to the file
            
        Returns:
            True if parser can handle this file type
        """
        path = Path(file_path)
        return path.suffix.lower() in self.file_extensions
    
    def get_line_content(self, code: str, line_number: int, context: int = 3) -> Dict[str, Any]:
        """
        Get content of a specific line with context
        
        Args:
            code: Source code string
            line_number: Line number (1-indexed)
            context: Number of lines before/after to include
            
        Returns:
            Dictionary with line content and context
        """
        lines = code.split('\n')
        
        if line_number < 1 or line_number > len(lines):
            return {
                'line_number': line_number,
                'content': '',
                'context_before': [],
                'context_after': []
            }
        
        # Convert to 0-indexed
        idx = line_number - 1
        
        start = max(0, idx - context)
        end = min(len(lines), idx + context + 1)
        
        return {
            'line_number': line_number,
            'content': lines[idx],
            'context_before': lines[start:idx],
            'context_after': lines[idx + 1:end],
            'snippet': '\n'.join(lines[start:end])
        }
    
    def tokenize(self, code: str) -> List[str]:
        """
        Simple tokenization of code
        
        Args:
            code: Source code string
            
        Returns:
            List of tokens
        """
        import re
        # Simple regex-based tokenization
        tokens = re.findall(r'\b\w+\b|[^\s\w]', code)
        return tokens
