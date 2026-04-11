"""Main code analyzer orchestrating all components."""

from typing import Dict, List, Any, Optional, Tuple, Set
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
import time

from ..parsers import JavaParser, PythonParser, CParser, PHPParser
from ..detectors import VulnerabilityDetector, CVEMapper, CWEMapper
from .language_detector import LanguageDetector

logger = logging.getLogger(__name__)


class CodeAnalyzer:
    """Main code analyzer coordinating parsing and detection."""

    SUPPORTED_LANGUAGES = {'python', 'java', 'c', 'cpp', 'php'}

    def __init__(self, config: Dict[str, Any]):
        self.config = config or {}
        self.language_detector = LanguageDetector()
        self.vulnerability_detector = VulnerabilityDetector(self.config)

        use_reference_cves = bool(
            self.config.get('reporting', {}).get('use_reference_cves', False)
        )
        self.cve_mapper = CVEMapper(use_reference_cves=use_reference_cves)
        self.cwe_mapper = CWEMapper()

        self.parsers = {
            'python': PythonParser(),
            'java': JavaParser(),
            'c': CParser(),
            'cpp': CParser(),
            'php': PHPParser(),
        }

        self.max_file_size_mb = float(
            self.config.get('detection', {}).get('max_file_size_mb', 10)
        )
        self.max_workers = int(self.config.get('performance', {}).get('max_workers', 1))
        self.supported_languages_sorted = sorted(self.SUPPORTED_LANGUAGES)
        self.last_scan_summary: Dict[str, Any] = {}

    def analyze_file(self, file_path: str, language: Optional[str] = None) -> Dict[str, Any]:
        start_time = time.time()
        file_obj = Path(file_path)

        if not file_obj.exists() or not file_obj.is_file():
            return {
                'success': False,
                'error': 'File not found or not a regular file',
                'file_path': file_path,
            }

        file_size_mb = file_obj.stat().st_size / (1024 * 1024)
        if file_size_mb > self.max_file_size_mb:
            return {
                'success': False,
                'error': f'File too large ({file_size_mb:.2f}MB > {self.max_file_size_mb}MB)',
                'file_path': file_path,
                'skipped': True,
                'skip_reason': 'file_too_large',
            }

        if language:
            language = language.lower().strip()
        else:
            language = self.language_detector.detect(file_path)

        if not language:
            return {
                'success': False,
                'error': 'Unable to detect language',
                'file_path': file_path,
            }

        if language not in self.SUPPORTED_LANGUAGES:
            return {
                'success': False,
                'error': (
                    f"Language '{language}' is detected but not yet supported by analyzer backend. "
                    f"Supported languages: {self.supported_languages_sorted}"
                ),
                'file_path': file_path,
                'language': language,
                'skipped': True,
                'skip_reason': 'unsupported_language',
            }

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as handle:
                code = handle.read()
        except Exception as exc:  # pragma: no cover
            return {
                'success': False,
                'error': f'Failed to read file: {str(exc)}',
                'file_path': file_path,
            }

        parser = self.parsers.get(language)
        parsed_code = parser.parse(code, file_path) if parser else {'success': True, 'code': code}

        vulnerabilities = self.vulnerability_detector.detect(code, language, file_path)
        if parser and parsed_code.get('success'):
            vulnerabilities.extend(self._get_parser_vulnerabilities(parser, parsed_code, language, file_path))

        normalized = [
            self._normalize_vulnerability(v, file_path=file_path, language=language)
            for v in vulnerabilities
        ]
        normalized = self._deduplicate_vulnerabilities(normalized)

        for vuln in normalized:
            if not vuln.get('cwe'):
                vuln['cwe'] = self.cwe_mapper.get_cwe_from_vulnerability_type(vuln.get('type', ''))
            vuln['cve'] = self.cve_mapper.map_vulnerability_to_cve(vuln)

        processing_time = time.time() - start_time
        logger.info(
            "analyze_file completed",
            extra={
                'file_path': file_path,
                'language': language,
                'vulnerability_count': len(normalized),
                'processing_time_seconds': round(processing_time, 3),
            },
        )

        return {
            'success': True,
            'file_path': file_path,
            'language': language,
            'vulnerabilities': normalized,
            'vulnerability_count': len(normalized),
            'processing_time': processing_time,
            'file_size_kb': len(code) / 1024,
            'lines_of_code': len(code.split('\n')),
        }

    def _normalize_vulnerability(
        self,
        vulnerability: Dict[str, Any],
        file_path: str,
        language: str,
    ) -> Dict[str, Any]:
        line_number = vulnerability.get('line_number', vulnerability.get('line', 0))

        try:
            line_number = int(line_number)
        except (TypeError, ValueError):
            line_number = 0

        normalized = {
            'type': vulnerability.get('type', vulnerability.get('vulnerability_type', 'Unknown')),
            'severity': vulnerability.get('severity', 'Medium'),
            'cwe': vulnerability.get('cwe', vulnerability.get('cwe_id', '')),
            'cve': vulnerability.get('cve', vulnerability.get('cve_id', 'N/A')),
            'line_number': line_number,
            'code_snippet': vulnerability.get('code_snippet', ''),
            'description': vulnerability.get('description', ''),
            'file_path': vulnerability.get('file_path', vulnerability.get('file_name', file_path)),
            'language': vulnerability.get('language', language),
            'source': vulnerability.get('source', 'parser_rule'),
            'confidence': vulnerability.get('confidence', 0.65),
        }

        if not normalized['code_snippet'] and vulnerability.get('function'):
            normalized['code_snippet'] = f"use of {vulnerability['function']}"

        try:
            normalized['confidence'] = round(float(normalized['confidence']), 2)
        except (TypeError, ValueError):
            normalized['confidence'] = 0.65

        normalized['confidence'] = max(0.0, min(1.0, normalized['confidence']))
        return normalized

    def _get_parser_vulnerabilities(
        self,
        parser,
        parsed_code: Dict[str, Any],
        language: str,
        file_path: str,
    ) -> List[Dict[str, Any]]:
        vulnerabilities = []

        if isinstance(parser, PythonParser):
            dangerous_funcs = parser.find_dangerous_functions(parsed_code)
            for func in dangerous_funcs:
                vulnerabilities.append(
                    {
                        'type': func['risk_type'],
                        'severity': 'High',
                        'line': func['line'],
                        'code_snippet': f"Use of {func['function']}()",
                        'description': f"Dangerous function {func['function']}() detected",
                        'file_path': file_path,
                        'language': language,
                        'source': 'python_parser',
                        'confidence': 0.75,
                    }
                )
            vulnerabilities.extend(parser.find_sql_patterns(parsed_code))

        elif isinstance(parser, JavaParser):
            vulnerabilities.extend(parser.find_sql_injection_patterns(parsed_code))
            vulnerabilities.extend(parser.find_command_injection(parsed_code))
            vulnerabilities.extend(parser.find_xxe_vulnerabilities(parsed_code))

        elif isinstance(parser, CParser):
            vulnerabilities.extend(parser.find_buffer_overflow(parsed_code))
            vulnerabilities.extend(parser.find_format_string_bugs(parsed_code))
            vulnerabilities.extend(parser.find_use_after_free(parsed_code))
            vulnerabilities.extend(parser.find_integer_overflow(parsed_code))

        elif isinstance(parser, PHPParser):
            vulnerabilities.extend(parser.find_sql_injection(parsed_code))
            vulnerabilities.extend(parser.find_xss_vulnerabilities(parsed_code))
            vulnerabilities.extend(parser.find_command_injection(parsed_code))
            vulnerabilities.extend(parser.find_file_inclusion(parsed_code))
            vulnerabilities.extend(parser.find_insecure_deserialization(parsed_code))

        return [
            self._normalize_vulnerability(v, file_path=file_path, language=language)
            for v in vulnerabilities
        ]

    def _deduplicate_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen: Set[Tuple[str, int, str, str, str]] = set()
        deduped: List[Dict[str, Any]] = []

        for vuln in vulnerabilities:
            key = (
                vuln.get('type', ''),
                int(vuln.get('line_number', 0) or 0),
                vuln.get('code_snippet', ''),
                vuln.get('language', ''),
                vuln.get('file_path', ''),
            )
            if key in seen:
                continue
            seen.add(key)
            deduped.append(vuln)

        return deduped

    def analyze_directory(self, directory_path: str, recursive: bool = True) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        path = Path(directory_path)

        files = [f for f in (path.rglob('*') if recursive else path.glob('*')) if f.is_file()]
        supported = [str(f) for f in files if self.language_detector.is_supported(str(f))]

        skipped_unsupported = len(files) - len(supported)
        skipped_too_large = 0

        if self.max_workers > 1 and len(supported) > 1:
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                future_map = {executor.submit(self.analyze_file, file_path): file_path for file_path in supported}
                for future in as_completed(future_map):
                    result = future.result()
                    if result.get('success'):
                        results.append(result)
                    elif result.get('skip_reason') == 'file_too_large':
                        skipped_too_large += 1
        else:
            for file_path in supported:
                result = self.analyze_file(file_path)
                if result.get('success'):
                    results.append(result)
                elif result.get('skip_reason') == 'file_too_large':
                    skipped_too_large += 1

        self.last_scan_summary = {
            'files_discovered': len(files),
            'files_supported': len(supported),
            'files_analyzed': len(results),
            'files_skipped_unsupported': skipped_unsupported,
            'files_skipped_too_large': skipped_too_large,
            'vulnerabilities_found': sum(r.get('vulnerability_count', 0) for r in results),
        }
        logger.info("directory scan summary", extra=self.last_scan_summary)

        return results

    def get_summary_statistics(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        total_files = len(results)
        total_vulnerabilities = sum(r.get('vulnerability_count', 0) for r in results)
        total_processing_time = sum(r.get('processing_time', 0) for r in results)

        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        type_counts: Dict[str, int] = {}
        language_counts: Dict[str, int] = {}

        for result in results:
            language = result.get('language', 'Unknown')
            language_counts[language] = language_counts.get(language, 0) + 1

            for vuln in result.get('vulnerabilities', []):
                severity = vuln.get('severity', 'Medium')
                severity_counts[severity] = severity_counts.get(severity, 0) + 1

                vuln_type = vuln.get('type', 'Unknown')
                type_counts[vuln_type] = type_counts.get(vuln_type, 0) + 1

        return {
            'total_files_analyzed': total_files,
            'total_vulnerabilities': total_vulnerabilities,
            'total_processing_time': round(total_processing_time, 2),
            'average_time_per_file': round(total_processing_time / total_files, 2) if total_files > 0 else 0,
            'vulnerabilities_by_severity': severity_counts,
            'vulnerabilities_by_type': type_counts,
            'files_by_language': language_counts,
            'scan_summary': self.last_scan_summary,
        }
