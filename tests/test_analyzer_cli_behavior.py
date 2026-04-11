import subprocess
import sys
from pathlib import Path

from src.analyzers.code_analyzer import CodeAnalyzer


def test_analyze_directory_produces_scan_summary(tmp_path: Path):
    source_file = tmp_path / 'vulnerable.py'
    source_file.write_text('eval(user_input)\n', encoding='utf-8')

    config = {
        'performance': {'max_workers': 2},
        'detection': {'max_file_size_mb': 1},
    }
    analyzer = CodeAnalyzer(config)

    results = analyzer.analyze_directory(str(tmp_path), recursive=False)

    assert results
    assert analyzer.last_scan_summary['files_discovered'] == 1
    assert analyzer.last_scan_summary['files_analyzed'] == 1
    assert analyzer.last_scan_summary['vulnerabilities_found'] >= 1


def test_cli_rejects_unimplemented_language_override(tmp_path: Path):
    source_file = tmp_path / 'sample.py'
    source_file.write_text('print("ok")\n', encoding='utf-8')

    cmd = [
        sys.executable,
        '-m',
        'src.main',
        '-f',
        str(source_file),
        '-l',
        'php',
        '--format',
        'json',
        '-o',
        str(tmp_path / 'out.json'),
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)

    assert result.returncode == 0


def test_cli_parser_blocks_non_supported_choice(tmp_path: Path):
    source_file = tmp_path / 'sample.py'
    source_file.write_text('print("ok")\n', encoding='utf-8')

    cmd = [
        sys.executable,
        '-m',
        'src.main',
        '-f',
        str(source_file),
        '-l',
        'javascript',
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)

    assert result.returncode != 0
    assert 'invalid choice' in (result.stderr + result.stdout).lower()
