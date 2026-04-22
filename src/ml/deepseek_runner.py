"""
DeepSeek Coder 6.7B Instruct — Stream B Semantic Analysis
Runs the model LOCALLY via Ollama (no GPU required for CPU inference,
GPU used automatically if available).

Setup (one-time):
    1. Download Ollama from https://ollama.com and install it
    2. In a terminal run:  ollama pull deepseek-coder:6.7b-instruct
    3. Ollama runs as a background service on http://localhost:11434

No extra Python packages needed — uses the built-in `requests` library.

Output contract:
    confidence:    float 0.0–1.0
    anomaly_score: float 0.0–1.0  (non-zero when VULNERABLE but no CWE found)
"""

import re
import logging
import requests
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

OLLAMA_URL   = "http://localhost:11434/api/chat"
OLLAMA_MODEL = "deepseek-coder:6.7b-instruct"

# ── Prompt templates ──────────────────────────────────────────────────────────

_SYSTEM_PROMPT = (
    "You are an expert security analyst specialising in source code vulnerability detection. "
    "You identify CWE vulnerabilities, explain the root cause clearly, and always provide "
    "a complete corrected version of the code. "
    "Respond ONLY in the exact numbered format requested — no extra commentary."
)

_USER_TEMPLATE = """\
### Language: {language}

### Code:
{code}

### Control Flow Paths (AST-derived):
{paths}

### Task:
Analyse the code above for security vulnerabilities and respond in this EXACT format:

1. VERDICT: [write only VULNERABLE or CLEAN]
2. CWE: [e.g. CWE-89: SQL Injection] or [NONE]
3. EXPLANATION: [2-3 sentences explaining the vulnerability or why the code is safe]
4. FIXED_CODE:
```
[complete corrected version of the code with the vulnerability fixed]
```
5. CONFIDENCE: [a decimal between 0.0 and 1.0]"""

_MAX_CODE_CHARS = 4_000   # ~1 000 tokens; keeps the prompt inside Ollama's context


class DeepSeekRunner:
    """
    Sends code to DeepSeek Coder 6.7B Instruct running locally through Ollama.

    Typical usage:
        runner = DeepSeekRunner()
        ok     = runner.load()          # checks Ollama is running
        result = runner.run(code, 'python', ast_paths)
    """

    MODEL_ID = OLLAMA_MODEL

    def __init__(
        self,
        model_id: str = OLLAMA_MODEL,
        ollama_url: str = OLLAMA_URL,
        max_new_tokens: int = 1024,
        temperature: float = 0.1,
        device_map: str = "auto",       # kept for API compat, Ollama manages this
    ):
        self.model_id     = model_id
        self.ollama_url   = ollama_url
        self.max_tokens   = max_new_tokens
        self.temperature  = temperature

        self._loaded = False

    # ── lifecycle ─────────────────────────────────────────────────────────────

    def load(self) -> bool:
        """Check Ollama is running and the model is pulled. Safe to call multiple times."""
        if self._loaded:
            return True

        try:
            # Check Ollama service is up
            r = requests.get("http://localhost:11434/api/tags", timeout=5)
            r.raise_for_status()
            available = [m["name"] for m in r.json().get("models", [])]

            # Accept any variant of the model name
            matched = any(self.model_id.split(":")[0] in m for m in available)
            if not matched:
                logger.warning(
                    "Model '%s' not found in Ollama. Run:  ollama pull %s",
                    self.model_id, self.model_id,
                )
                logger.warning("Available models: %s", available or "none")
                return False

            self._loaded = True
            logger.info("Ollama ready — using model: %s", self.model_id)
            return True

        except requests.exceptions.ConnectionError:
            logger.warning(
                "Ollama is not running. Start it with:  ollama serve  "
                "(or open the Ollama desktop app)"
            )
        except Exception as exc:
            logger.warning("Ollama check failed: %s", exc)

        return False

    def is_loaded(self) -> bool:
        return self._loaded

    # ── prompt builder ────────────────────────────────────────────────────────

    def build_messages(
        self,
        code: str,
        language: str,
        ast_paths: List[str],
    ) -> List[Dict[str, str]]:
        """Build the structured chat messages list for Ollama."""
        if len(code) > _MAX_CODE_CHARS:
            code = code[:_MAX_CODE_CHARS] + "\n... [truncated]"

        paths_block = (
            "\n".join(f"  {p}" for p in ast_paths[:10])
            if ast_paths else "  (no AST paths available)"
        )

        return [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user",   "content": _USER_TEMPLATE.format(
                language=language,
                code=code,
                paths=paths_block,
            )},
        ]

    # ── inference ─────────────────────────────────────────────────────────────

    def run(
        self,
        code: str,
        language: str,
        ast_paths: Optional[List[str]] = None,
    ) -> Dict:
        """
        Run DeepSeek locally via Ollama on a code snippet.

        Returns:
        {
            'verdict':       'VULNERABLE' | 'CLEAN',
            'cwe_id':        'CWE-89' | None,
            'cwe_name':      str | None,
            'explanation':   str,
            'fixed_code':    str | None,
            'confidence':    float,        # 0.0–1.0
            'anomaly_score': float,        # non-zero = POTENTIAL_ANOMALY
            'is_anomaly':    bool,
            'raw_response':  str,
        }
        """
        if not self._loaded:
            if not self.load():
                return self._empty_result(
                    "Ollama not running or model not pulled. "
                    "Run: ollama pull deepseek-coder:6.7b-instruct"
                )

        messages = self.build_messages(code, language, ast_paths or [])

        try:
            response = requests.post(
                self.ollama_url,
                json={
                    "model":    self.model_id,
                    "messages": messages,
                    "stream":   False,
                    "options": {
                        "temperature":   self.temperature,
                        "num_predict":   self.max_tokens,
                        "num_ctx":       4096,
                    },
                },
                timeout=120,    # local inference can take up to 2 min on CPU
            )
            response.raise_for_status()
            generated = response.json()["message"]["content"]
            return self._parse_response(generated)

        except requests.exceptions.Timeout:
            logger.error("Ollama inference timed out (120s)")
            return self._empty_result("Inference timed out — model may be loading, try again")
        except Exception as exc:
            logger.error("Ollama inference error: %s", exc)
            return self._empty_result(str(exc))

    # ── response parser ───────────────────────────────────────────────────────

    def _parse_response(self, raw: str) -> Dict:
        """Parse the structured 5-step response from DeepSeek."""
        result: Dict = {
            "verdict":       "CLEAN",
            "cwe_id":        None,
            "cwe_name":      None,
            "explanation":   "",
            "fixed_code":    None,
            "confidence":    0.5,
            "anomaly_score": 0.0,
            "is_anomaly":    False,
            "raw_response":  raw,
        }

        text = raw.strip()

        # 1. Verdict
        if re.search(r'\bVULNERABLE\b', text, re.IGNORECASE):
            result["verdict"] = "VULNERABLE"
        elif re.search(r'\bCLEAN\b', text, re.IGNORECASE):
            result["verdict"] = "CLEAN"

        # 2. CWE
        cwe_m = re.search(r'CWE-(\d+)', text, re.IGNORECASE)
        if cwe_m:
            result["cwe_id"] = f"CWE-{cwe_m.group(1)}"
            name_m = re.search(
                rf'CWE-{cwe_m.group(1)}\s*[:\-–]?\s*([^\n.{{}}]+)',
                text, re.IGNORECASE,
            )
            if name_m:
                result["cwe_name"] = name_m.group(1).strip()[:120]

        # 3. Explanation
        expl_m = re.search(
            r'3\.\s*EXPLANATION\s*[:\-]?\s*(.+?)(?=\n\s*4\.|```|FIXED_CODE)',
            text, re.IGNORECASE | re.DOTALL,
        )
        if expl_m:
            result["explanation"] = expl_m.group(1).strip()[:800]
        else:
            lines = [l.strip() for l in text.splitlines()
                     if l.strip() and not re.match(r'^\d+[.\)]', l.strip())]
            result["explanation"] = " ".join(lines[:3])[:800]

        # 4. Fixed code — extract from ``` fences
        code_m = re.search(r'```[a-zA-Z]*\n(.*?)```', text, re.DOTALL)
        if code_m:
            result["fixed_code"] = code_m.group(1).strip()

        # 5. Confidence
        conf_m = re.search(
            r'(?:5\.\s*CONFIDENCE|confidence)[^0-9]*?(0\.\d+|1\.0)',
            text, re.IGNORECASE,
        )
        if conf_m:
            try:
                result["confidence"] = max(0.0, min(1.0, float(conf_m.group(1))))
            except ValueError:
                pass

        # Anomaly: VULNERABLE but no parseable CWE
        if result["verdict"] == "VULNERABLE" and result["cwe_id"] is None:
            result["is_anomaly"]    = True
            result["anomaly_score"] = result["confidence"]

        return result

    # ── helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _empty_result(reason: str) -> Dict:
        return {
            "verdict":       "CLEAN",
            "cwe_id":        None,
            "cwe_name":      None,
            "explanation":   reason,
            "fixed_code":    None,
            "confidence":    0.0,
            "anomaly_score": 0.0,
            "is_anomaly":    False,
            "raw_response":  "",
        }
