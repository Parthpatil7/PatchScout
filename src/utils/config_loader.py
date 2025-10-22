"""
Configuration loader utility
"""

import yaml
from pathlib import Path
from typing import Dict, Any


def load_config(config_path: str = "config/config.yaml") -> Dict[str, Any]:
    """
    Load configuration from YAML file
    
    Args:
        config_path: Path to configuration file
        
    Returns:
        Dictionary containing configuration
    """
    config_file = Path(config_path)
    
    if not config_file.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")
    
    with open(config_file, 'r') as f:
        config = yaml.safe_load(f)
    
    return config


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
