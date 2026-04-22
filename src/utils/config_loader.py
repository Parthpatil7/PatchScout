"""
Configuration loader utility
"""

import yaml
from pathlib import Path
from typing import Dict, Any


class ConfigLoader:
    """Configuration loader class"""
    
    def __init__(self, config_path: str = "config/config.yaml"):
        """
        Initialize config loader
        
        Args:
            config_path: Path to configuration file
        """
        self.config_path = config_path
        self._config = None
        
    def load_config(self) -> Dict[str, Any]:
        """
        Load configuration from YAML file
        
        Returns:
            Dictionary containing configuration
        """
        if self._config is not None:
            return self._config
            
        config_file = Path(self.config_path)
        
        if not config_file.exists():
            # Return default config if file doesn't exist
            self._config = self._get_default_config()
            return self._config
        
        with open(config_file, 'r') as f:
            self._config = yaml.safe_load(f)
        
        return self._config
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration"""
        return {
            'model': {
                'type': 'deepseek',
                'name': 'deepseek-ai/deepseek-coder-6.7b-instruct',
                'device': 'auto'
            },
            'detection': {
                'engine': 'deepseek',
                'ml_threshold': 0.35,
            },
            'languages': {
                'stage_1': ['java', 'python', 'c', 'cpp', 'php'],
                'stage_2': ['java', 'python', 'c', 'cpp', 'php', 'ruby', 'rust', 'kotlin', 'swift'],
                'stage_3': ['java', 'python', 'c', 'cpp', 'php', 'ruby', 'rust', 'kotlin', 'swift', 'html', 'javascript', 'go']
            }
        }
    
    def get_supported_languages(self, stage: int = 1) -> list:
        """
        Get list of supported languages for a specific stage
        
        Args:
            stage: Competition stage (1, 2, or 3)
            
        Returns:
            List of supported language identifiers
        """
        config = self.load_config()
        stage_key = f"stage_{stage}"
        return config.get('languages', {}).get(stage_key, [])


def load_config(config_path: str = "config/config.yaml") -> Dict[str, Any]:
    """
    Load configuration from YAML file (legacy function)
    
    Args:
        config_path: Path to configuration file
        
    Returns:
        Dictionary containing configuration
    """
    loader = ConfigLoader(config_path)
    return loader.load_config()


def get_supported_languages(config: Dict[str, Any], stage: int = 1) -> list:
    """
    Get list of supported languages for a specific stage
    
    Args:
        config: Configuration dictionary
        stage: Competition stage (1, 2, or 3)
        
    Returns:
        List of supported language identifiers
    """
    stage_key = f"stage_{stage}"
    return config.get('languages', {}).get(stage_key, [])

