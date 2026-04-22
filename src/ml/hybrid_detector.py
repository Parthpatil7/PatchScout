"""
Hybrid Detection System — Stream A + Stream B Weighted Fusion
Architecture: Static(Semgrep/Flawfinder) + DeepSeek 6.7B → Fusion Engine → Tagged Results

Fusion formula:  score = (0.6 × ML_confidence) + (0.4 × static_flag)
Detection tags:  both | llm_only | static_only | anomaly
"""

import logging
from pathlib import Path
from typing import Dict, List, Optional

from .ast_extractor import ASTExtractor
from .deepseek_runner import DeepSeekRunner

logger = logging.getLogger(__name__)

_SEVERITY_ORDER = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}

# Weighted fusion coefficients (must sum to 1.0)
_W_ML     = 0.6
_W_STATIC = 0.4


def _cwe_match(cwe_a: Optional[str], cwe_b: Optional[str]) -> bool:
    """True when both CWE IDs are non-empty and equal (case-insensitive)."""
    if not cwe_a or not cwe_b:
        return False
    return cwe_a.upper() == cwe_b.upper()


class HybridVulnerabilityDetector:
    """
    Combines Stream A (static pattern detector) with Stream B (DeepSeek 6.7B
    semantic analysis) via a weighted scoring fusion engine.

    Detection tags assigned per vulnerability:
        both        — flagged by both static analyser and LLM
        llm_only    — flagged by LLM alone (fusion score ≥ ml_threshold)
        static_only — flagged by static analyser alone
        anomaly     — LLM flagged VULNERABLE but could not identify a CWE
    """

    def __init__(
        self,
        pattern_detector,                   # VulnerabilityDetector instance (Stream A)
        use_ml: bool = True,
        ml_threshold: float = 0.35,         # minimum fusion score for llm_only entries
        device: str = 'auto',               # forwarded to DeepSeekRunner.device_map
        # legacy param kept for API compatibility — no longer used
        ml_model_path: Optional[str] = None,
    ):
        self.pattern_detector = pattern_detector
        self.use_ml           = use_ml
        self.ml_threshold     = ml_threshold

        self.ast_extractor   = ASTExtractor()
        self.deepseek_runner = DeepSeekRunner(device_map=device)
        self.last_ds_result: Optional[Dict] = None   # accessible by code_analyzer

        if use_ml:
            logger.info("HybridDetector ready — DeepSeek loads lazily on first inference.")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def detect_vulnerabilities(
        self,
        code: str,
        language: str,
        file_path: str = "",
        ast_data: Optional[Dict] = None,    # ignored; AST extracted internally
    ) -> List[Dict]:
        """
        Run Stream A (static) + Stream B (DeepSeek) and return a fused,
        tagged list of vulnerabilities sorted by severity then fusion score.
        """
        # ── Stream A: static pattern detection ──────────────────────────
        try:
            if hasattr(self.pattern_detector, 'detect_vulnerabilities'):
                static_vulns = self.pattern_detector.detect_vulnerabilities(
                    code, language, ast_data
                )
            else:
                static_vulns = self.pattern_detector.detect(code, language, file_path)
        except Exception as exc:
            logger.warning("Pattern detector error: %s", exc)
            static_vulns = []

        for v in static_vulns:
            v.setdefault('detection_method', 'static')

        # ── Stream B: DeepSeek semantic analysis ─────────────────────────
        ds_result: Optional[Dict] = None
        if self.use_ml:
            try:
                ast_info = self.ast_extractor.extract(code, language)
                ds_result = self.deepseek_runner.run(
                    code, language, ast_info['paths']
                )
            except Exception as exc:
                logger.warning("DeepSeek inference error: %s", exc)

        self.last_ds_result = ds_result   # expose for code_analyzer

        # ── Fusion engine ─────────────────────────────────────────────────
        return self._fuse(static_vulns, ds_result, code)

    # ------------------------------------------------------------------
    # Weighted fusion engine
    # ------------------------------------------------------------------

    def _fuse(
        self,
        static_vulns: List[Dict],
        ds: Optional[Dict],
        code: str,
    ) -> List[Dict]:
        """
        Merge Stream A and Stream B results.

        score = (0.6 × ML_confidence) + (0.4 × static_flag)

        static_flag = 1.0  for every vulnerability the static analyser found
        ML_confidence      = DeepSeek confidence when it corroborates the same CWE,
                             0.0 otherwise
        """
        ds_conf    = ds.get('confidence', 0.0)    if ds else 0.0
        ds_verdict = ds.get('verdict', 'CLEAN')   if ds else 'CLEAN'
        ds_cwe     = ds.get('cwe_id')             if ds else None
        ds_anomaly = ds.get('is_anomaly', False)  if ds else False
        ds_anom_sc = ds.get('anomaly_score', 0.0) if ds else 0.0

        fused: List[Dict] = []
        llm_cwe_consumed = False    # becomes True once LLM CWE is matched to a static entry

        # ── Annotate each static finding with LLM corroboration ─────────
        ds_fixed   = ds.get('fixed_code')   if ds else None
        ds_explain = ds.get('explanation')  if ds else None

        for sv in static_vulns:
            ml_conf  = 0.0
            tag      = 'static_only'

            if ds_verdict == 'VULNERABLE':
                if ds_cwe and _cwe_match(sv.get('cwe'), ds_cwe):
                    ml_conf          = ds_conf
                    tag              = 'both'
                    llm_cwe_consumed = True
                elif not ds_cwe and ds_anomaly:
                    ml_conf          = ds_anom_sc
                    tag              = 'both'
                    llm_cwe_consumed = True

            score = _W_ML * ml_conf + _W_STATIC * 1.0
            entry = {
                **sv,
                'fusion_score':     round(score, 4),
                'detection_method': tag,
                'llm_confidence':   round(ml_conf, 4),
                'static_flag':      1.0,
            }
            # Attach DeepSeek's fix and explanation to corroborated entries
            if tag == 'both' and ds_fixed:
                entry['fixed_code']  = ds_fixed
                entry['explanation'] = ds_explain or sv.get('description', '')
            fused.append(entry)

        # ── LLM-only: DeepSeek found something the static pass missed ────
        if ds and ds_verdict == 'VULNERABLE' and not llm_cwe_consumed:
            score = _W_ML * ds_conf  # static_flag = 0
            if score >= self.ml_threshold:
                fused.append(self._llm_only_entry(ds, code, score))

        # ── Anomaly: VULNERABLE verdict but no parseable CWE ─────────────
        if ds and ds_anomaly and not llm_cwe_consumed:
            anom_score = _W_ML * ds_anom_sc
            fused.append(self._anomaly_entry(ds, code, anom_score))

        # Sort by severity (low index = higher severity), then fusion score DESC
        fused.sort(key=lambda x: (
            _SEVERITY_ORDER.get(x.get('severity', 'Medium'), 4),
            -x.get('fusion_score', 0.0),
        ))

        return fused

    # ------------------------------------------------------------------
    # Entry builders for LLM-only and anomaly detections
    # ------------------------------------------------------------------

    def _llm_only_entry(self, ds: Dict, code: str, score: float) -> Dict:
        snippet = (code[:120] + '…') if len(code) > 120 else code
        return {
            'type':             ds.get('cwe_name') or 'LLM-Detected Vulnerability',
            'cwe':              ds.get('cwe_id'),
            'severity':         'High',
            'confidence':       ds['confidence'],
            'line_number':      0,
            'description':      ds.get('explanation', ''),
            'fixed_code':       ds.get('fixed_code'),
            'code_snippet':     snippet,
            'detection_method': 'llm_only',
            'fusion_score':     round(score, 4),
            'llm_confidence':   ds['confidence'],
            'static_flag':      0.0,
        }

    def _anomaly_entry(self, ds: Dict, code: str, score: float) -> Dict:
        snippet = (code[:120] + '…') if len(code) > 120 else code
        base_expl = ds.get('explanation', '')
        description = (
            'DeepSeek flagged anomalous security-relevant behaviour without '
            'matching a known CWE. Manual review recommended. ' + base_expl
        )[:800]
        return {
            'type':             'Potential Security Anomaly',
            'cwe':              None,
            'severity':         'Medium',
            'confidence':       ds['anomaly_score'],
            'line_number':      0,
            'description':      description,
            'fixed_code':       ds.get('fixed_code'),
            'code_snippet':     snippet,
            'detection_method': 'anomaly',
            'fusion_score':     round(score, 4),
            'llm_confidence':   ds['anomaly_score'],
            'static_flag':      0.0,
        }

    # ------------------------------------------------------------------
    # Diagnostics
    # ------------------------------------------------------------------

    def get_statistics(self) -> Dict:
        return {
            'ml_enabled':      self.use_ml,
            'deepseek_loaded': self.deepseek_runner.is_loaded(),
            'ast_available':   self.ast_extractor.available,
            'fusion_weights':  {'ml': _W_ML, 'static': _W_STATIC},
            'detection_tags':  ['both', 'llm_only', 'static_only', 'anomaly'],
        }


# ---------------------------------------------------------------------------
# MLModelManager — preserved for backward compatibility
# ---------------------------------------------------------------------------

class MLModelManager:
    """Manages model artefact files under models_dir."""

    def __init__(self, models_dir: str = 'models/checkpoints'):
        self.models_dir = Path(models_dir)
        self.models_dir.mkdir(parents=True, exist_ok=True)

    def get_best_model_path(self) -> Optional[Path]:
        for name in ('best_model.pt', 'final_model.pt'):
            p = self.models_dir / name
            if p.exists():
                return p
        return None

    def list_available_models(self) -> List[Path]:
        return list(self.models_dir.glob('*.pt'))

    def get_model_info(self, model_path: Path) -> Dict:
        try:
            import torch
            checkpoint = torch.load(model_path, map_location='cpu')
            return {
                'path':    str(model_path),
                'epoch':   checkpoint.get('epoch', 'unknown'),
                'metrics': checkpoint.get('metrics', {}),
                'size_mb': model_path.stat().st_size / (1024 * 1024),
            }
        except Exception as exc:
            return {'path': str(model_path), 'error': str(exc)}
