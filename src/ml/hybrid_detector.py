"""
Hybrid Detection System
Combines ML-based detection with pattern-based detection
"""

import torch
from pathlib import Path
from typing import Dict, List, Optional
import numpy as np

from .codebert_model import CodeBERTVulnerabilityDetector


class HybridVulnerabilityDetector:
    """
    Hybrid detector that combines:
    1. ML model (CodeBERT) - for complex/semantic vulnerabilities
    2. Pattern-based detection - for known/simple vulnerabilities
    """
    
    def __init__(
        self,
        pattern_detector,  # VulnerabilityDetector instance
        ml_model_path: Optional[str] = None,
        use_ml: bool = True,
        ml_threshold: float = 0.7,
        device: str = 'cpu'
    ):
        """
        Initialize hybrid detector
        
        Args:
            pattern_detector: Pattern-based VulnerabilityDetector
            ml_model_path: Path to trained ML model
            use_ml: Whether to use ML model
            ml_threshold: Confidence threshold for ML predictions
            device: Device to run ML model on
        """
        self.pattern_detector = pattern_detector
        self.use_ml = use_ml
        self.ml_threshold = ml_threshold
        self.device = device
        self.ml_model = None
        
        # Load ML model if available
        if use_ml and ml_model_path and Path(ml_model_path).exists():
            try:
                print(f"🤖 Loading ML model from {ml_model_path}...")
                self.ml_model = CodeBERTVulnerabilityDetector.load_model(
                    ml_model_path,
                    device=device
                )
                print("✅ ML model loaded successfully")
            except Exception as e:
                print(f"⚠️  Failed to load ML model: {e}")
                print("   Falling back to pattern-based detection only")
                self.use_ml = False
        else:
            self.use_ml = False
            if use_ml:
                print("⚠️  ML model not found. Using pattern-based detection only.")
    
    def detect_vulnerabilities(
        self,
        code: str,
        language: str,
        ast_data: Optional[Dict] = None
    ) -> List[Dict]:
        """
        Detect vulnerabilities using hybrid approach
        
        Args:
            code: Source code
            language: Programming language
            ast_data: Parsed AST data
            
        Returns:
            List of detected vulnerabilities
        """
        vulnerabilities = []
        
        # 1. Pattern-based detection (fast, reliable for known patterns)
        pattern_vulns = self.pattern_detector.detect_vulnerabilities(
            code, language, ast_data
        )
        
        # 2. ML-based detection (for semantic/complex vulnerabilities)
        ml_vulns = []
        if self.use_ml and self.ml_model:
            try:
                ml_vulns = self._ml_detect(code, language)
            except Exception as e:
                print(f"⚠️  ML detection error: {e}")
        
        # 3. Merge and deduplicate detections
        vulnerabilities = self._merge_detections(pattern_vulns, ml_vulns, code)
        
        return vulnerabilities
    
    def _ml_detect(self, code: str, language: str) -> List[Dict]:
        """
        Detect vulnerabilities using ML model
        
        Args:
            code: Source code
            language: Programming language
            
        Returns:
            List of ML-detected vulnerabilities
        """
        if not self.ml_model:
            return []
        
        # Get ML prediction
        prediction = self.ml_model.predict(code, device=self.device)
        
        vulnerabilities = []
        
        # Only add if confidence is above threshold
        if prediction['is_vulnerable'] and prediction['vulnerability_score'] >= self.ml_threshold:
            # Map CWE index to actual CWE ID (would need CWE mapping file)
            cwe_id = f"CWE-{prediction['predicted_cwe']}"
            
            vulnerabilities.append({
                'type': 'ML-Detected Vulnerability',
                'cwe': cwe_id,
                'severity': prediction['predicted_severity'],
                'confidence': prediction['vulnerability_score'],
                'line': 0,  # ML doesn't provide line numbers
                'description': f'ML model detected potential vulnerability (confidence: {prediction["vulnerability_score"]:.2%})',
                'code_snippet': code[:100] + '...' if len(code) > 100 else code,
                'detection_method': 'ML'
            })
        
        return vulnerabilities
    
    def _merge_detections(
        self,
        pattern_vulns: List[Dict],
        ml_vulns: List[Dict],
        code: str
    ) -> List[Dict]:
        """
        Merge and deduplicate pattern and ML detections
        
        Args:
            pattern_vulns: Pattern-based detections
            ml_vulns: ML-based detections
            code: Source code
            
        Returns:
            Merged list of vulnerabilities
        """
        # Start with pattern-based detections (higher precision)
        merged = pattern_vulns.copy()
        
        # Add detection method tag
        for vuln in merged:
            vuln['detection_method'] = 'Pattern'
        
        # Add ML detections if they don't overlap with pattern detections
        for ml_vuln in ml_vulns:
            # Check if similar vulnerability already detected by patterns
            is_duplicate = False
            for pattern_vuln in pattern_vulns:
                # Consider duplicate if same CWE or similar type
                if (ml_vuln.get('cwe') == pattern_vuln.get('cwe') or
                    self._similar_vulnerability_type(ml_vuln['type'], pattern_vuln['type'])):
                    # Enhance pattern detection with ML confidence
                    pattern_vuln['ml_confidence'] = ml_vuln['confidence']
                    is_duplicate = True
                    break
            
            if not is_duplicate:
                # Add unique ML detection
                merged.append(ml_vuln)
        
        # Sort by severity and confidence
        severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}
        merged.sort(key=lambda x: (
            severity_order.get(x['severity'], 4),
            -x.get('confidence', 0.5)
        ))
        
        return merged
    
    def _similar_vulnerability_type(self, type1: str, type2: str) -> bool:
        """Check if two vulnerability types are similar"""
        type1_lower = type1.lower()
        type2_lower = type2.lower()
        
        # Define similar vulnerability groups
        similar_groups = [
            {'sql injection', 'sqli', 'sql'},
            {'xss', 'cross-site scripting', 'cross site scripting'},
            {'command injection', 'command exec', 'code injection'},
            {'buffer overflow', 'buffer', 'memory corruption'},
        ]
        
        for group in similar_groups:
            if any(term in type1_lower for term in group) and any(term in type2_lower for term in group):
                return True
        
        return False
    
    def get_statistics(self) -> Dict:
        """Get detection statistics"""
        return {
            'ml_enabled': self.use_ml,
            'ml_model_loaded': self.ml_model is not None,
            'detection_methods': ['Pattern-based', 'ML-based'] if self.use_ml else ['Pattern-based'],
            'ml_threshold': self.ml_threshold,
            'device': self.device
        }


class MLModelManager:
    """Manages ML model lifecycle"""
    
    def __init__(self, models_dir: str = 'models/checkpoints'):
        """Initialize model manager"""
        self.models_dir = Path(models_dir)
        self.models_dir.mkdir(parents=True, exist_ok=True)
    
    def get_best_model_path(self) -> Optional[Path]:
        """Get path to best trained model"""
        best_model = self.models_dir / 'best_model.pt'
        if best_model.exists():
            return best_model
        
        final_model = self.models_dir / 'final_model.pt'
        if final_model.exists():
            return final_model
        
        return None
    
    def list_available_models(self) -> List[Path]:
        """List all available model checkpoints"""
        return list(self.models_dir.glob('*.pt'))
    
    def get_model_info(self, model_path: Path) -> Dict:
        """Get information about a model checkpoint"""
        try:
            checkpoint = torch.load(model_path, map_location='cpu')
            return {
                'path': str(model_path),
                'epoch': checkpoint.get('epoch', 'unknown'),
                'metrics': checkpoint.get('metrics', {}),
                'size_mb': model_path.stat().st_size / (1024 * 1024)
            }
        except Exception as e:
            return {'path': str(model_path), 'error': str(e)}


if __name__ == "__main__":
    # Test hybrid detector
    print("✅ Hybrid detection system ready")
    
    manager = MLModelManager()
    best_model = manager.get_best_model_path()
    
    if best_model:
        print(f"   Best model found: {best_model}")
        info = manager.get_model_info(best_model)
        print(f"   Model info: {info}")
    else:
        print("   No trained model found. Run train_model.py first.")
