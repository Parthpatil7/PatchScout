"""
PatchScout Web Application
Flask-based interface for AI-powered vulnerability detection using DeepSeek 6.7B
"""

import os
import sys
import json
import uuid
import shutil
import zipfile
import logging
from pathlib import Path
from datetime import datetime

from flask import Flask, render_template, request, jsonify, send_file

sys.path.insert(0, str(Path(__file__).parent))

from src.analyzers import CodeAnalyzer
from src.reporting import ReportGenerator
from src.utils import ConfigLoader

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = 'patchscout-2024'
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50 MB
app.config['UPLOAD_FOLDER']  = 'uploads'
app.config['RESULTS_FOLDER'] = 'web_results'

os.makedirs(app.config['UPLOAD_FOLDER'],  exist_ok=True)
os.makedirs(app.config['RESULTS_FOLDER'], exist_ok=True)

ALLOWED_EXTENSIONS = {'c', 'cpp', 'cc', 'cxx', 'h', 'hpp', 'py', 'php', 'java', 'zip'}

# ── helpers ──────────────────────────────────────────────────────────────────

def allowed_file(filename: str) -> bool:
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def _load_scans():
    """Return list of scan metadata dicts, newest first."""
    scans = []
    results_dir = Path(app.config['RESULTS_FOLDER'])
    for d in results_dir.glob('scan_*'):
        meta = d / 'metadata.json'
        if meta.exists():
            try:
                scans.append(json.loads(meta.read_text()))
            except Exception:  # noqa: BLE001
                pass
    return sorted(scans, key=lambda s: s.get('timestamp', ''), reverse=True)


def _severity_counts(vulns):
    counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
    for v in vulns:
        sev = v.get('severity', 'Medium')
        sev = sev[0].upper() + sev[1:].lower()
        counts[sev] = counts.get(sev, 0) + 1
    return counts


# ── pages ─────────────────────────────────────────────────────────────────────

@app.route('/')
@app.route('/dashboard')
def dashboard():
    scans = _load_scans()
    completed = [s for s in scans if s.get('status') == 'completed']
    return render_template('dashboard.html',
        total_scans=len(scans),
        total_vulnerabilities=sum(s.get('vulnerability_count', 0) for s in completed),
        safe_scans=sum(1 for s in completed if s.get('vulnerability_count', 0) == 0),
        critical_count=sum(s.get('critical_count', 0) for s in completed),
        high_count=sum(s.get('high_count', 0) for s in completed),
        medium_count=sum(s.get('medium_count', 0) for s in completed),
        low_count=sum(s.get('low_count', 0) for s in completed),
        recent_scans=[{**s, 'date': datetime.fromisoformat(s.get('timestamp', datetime.now().isoformat())).strftime('%Y-%m-%d %H:%M')} for s in scans[:5]],
    )


@app.route('/upload')
def upload_page():
    return render_template('upload.html')


@app.route('/scans')
def scans():
    all_scans = _load_scans()
    for s in all_scans:
        s['date'] = datetime.fromisoformat(s.get('timestamp', datetime.now().isoformat())).strftime('%Y-%m-%d %H:%M')
    return render_template('scans.html', scans=all_scans)


@app.route('/scan/<scan_id>')
def scan_detail(scan_id):
    results_dir = Path(app.config['RESULTS_FOLDER']) / f'scan_{scan_id}'
    meta_file    = results_dir / 'metadata.json'
    results_file = results_dir / 'results.json'

    if not meta_file.exists():
        return render_template('error.html', error='Scan not found'), 404

    scan = json.loads(meta_file.read_text())
    scan['date'] = datetime.fromisoformat(scan.get('timestamp', datetime.now().isoformat())).strftime('%Y-%m-%d %H:%M')

    files = []
    if results_file.exists():
        data = json.loads(results_file.read_text())
        files = data.get('files', [])

    return render_template('scan_detail.html', scan=scan, files=files)


# ── API ───────────────────────────────────────────────────────────────────────

@app.route('/api/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file            = request.files['file']
    software_name   = request.form.get('software_name', 'Unknown Software')
    software_version= request.form.get('software_version', '')

    if not file.filename or not allowed_file(file.filename):
        return jsonify({'error': 'Invalid or unsupported file type'}), 400

    scan_id    = str(uuid.uuid4())[:8]
    upload_dir = Path(app.config['UPLOAD_FOLDER']) / scan_id
    results_dir= Path(app.config['RESULTS_FOLDER']) / f'scan_{scan_id}'
    upload_dir.mkdir(parents=True, exist_ok=True)
    results_dir.mkdir(parents=True, exist_ok=True)

    filename  = file.filename
    file_path = upload_dir / filename
    file.save(str(file_path))

    # Extract ZIP if needed
    if filename.lower().endswith('.zip'):
        extract_dir = upload_dir / filename.rsplit('.', 1)[0]
        extract_dir.mkdir(exist_ok=True)
        try:
            with zipfile.ZipFile(file_path, 'r') as zf:
                zf.extractall(extract_dir)
        except Exception as e:
            return jsonify({'error': f'ZIP extraction failed: {e}'}), 400

    try:
        config = ConfigLoader().load_config()
        analyzer = CodeAnalyzer(config)

        exts = ['.c', '.cpp', '.cc', '.cxx', '.h', '.hpp', '.py', '.php', '.java']
        files_to_scan = []
        for ext in exts:
            files_to_scan.extend(upload_dir.rglob(f'*{ext}'))

        if not files_to_scan:
            _save_meta(results_dir, scan_id, software_name, software_version,
                       filename, 'completed', 0, {}, warning='No supported source files found')
            return jsonify({'success': True, 'scan_id': scan_id,
                            'warning': 'No supported source files found'})

        # ── Analyse each file ──────────────────────────────────────────
        results    = []
        all_vulns  = []
        sev_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}

        for fp in files_to_scan:
            try:
                result = analyzer.analyze_file(str(fp))
                if not result.get('success'):
                    continue

                vulns = result.get('vulnerabilities', [])
                sc    = _severity_counts(vulns)
                for k in sev_counts:
                    sev_counts[k] += sc.get(k, 0)
                all_vulns.extend(vulns)

                # Build the per-file record — preserve ALL fields
                file_record = {
                    'file_path':         result['file_path'],
                    'language':          result.get('language', 'unknown'),
                    'detector_mode':     result.get('detector_mode', 'pattern'),
                    'vulnerability_count': len(vulns),
                    'processing_time':   round(result.get('processing_time', 0), 2),
                    'lines_of_code':     result.get('lines_of_code', 0),
                    'vulnerabilities':   vulns,            # full dicts with fixed_code etc.
                    'deepseek_analysis': result.get('deepseek_analysis'),   # verdict/explanation/fixed_code
                    'original_code':     result.get('original_code', ''),   # source for side-by-side
                }
                results.append(file_record)

            except Exception as e:
                logger.error("Error analysing %s: %s", fp, e)

        # ── Save results.json ──────────────────────────────────────────
        scan_results = {
            'scan_id':   scan_id,
            'timestamp': datetime.now().isoformat(),
            'total_files': len(results),
            'total_vulnerabilities': len(all_vulns),
            'severity_breakdown': sev_counts,
            'files': results,
        }
        (results_dir / 'results.json').write_text(
            json.dumps(scan_results, indent=2, default=str)
        )

        # ── Generate Excel report ──────────────────────────────────────
        try:
            report_vulns = []
            for fr in results:
                for v in fr.get('vulnerabilities', []):
                    report_vulns.append({
                        'language':          fr.get('language', 'unknown'),
                        'vulnerability_type':v.get('type', 'Unknown'),
                        'cve_id':            v.get('cve', 'N/A'),
                        'severity':          v.get('severity', 'Unknown'),
                        'cwe_id':            v.get('cwe', 'N/A'),
                        'file_path':         fr.get('file_path', ''),
                        'line_number':       v.get('line_number', 'N/A'),
                        'code_snippet':      v.get('code_snippet', 'N/A'),
                        'fixed_code':        v.get('fixed_code', 'N/A'),
                        'detection_method':  v.get('detection_method', 'static'),
                    })
            rg = ReportGenerator(config)
            excel_path = results_dir / f'report_{scan_id}.xlsx'
            rg.generate_excel_report(report_vulns, str(excel_path), team_name=software_name)
        except Exception as e:
            logger.error("Excel report failed: %s", e)

        _save_meta(results_dir, scan_id, software_name, software_version,
                   filename, 'completed', len(all_vulns), sev_counts)

        # Cleanup uploads
        try:
            shutil.rmtree(upload_dir)
        except Exception:
            pass

        return jsonify({'success': True, 'scan_id': scan_id})

    except Exception as e:
        logger.exception("Scan failed")
        _save_meta(results_dir, scan_id, software_name, software_version,
                   filename, 'failed', 0, {}, error=str(e))
        return jsonify({'error': str(e)}), 500


def _save_meta(results_dir, scan_id, name, version, filename,
               status, vuln_count, sev_counts, error=None, warning=None):
    meta = {
        'id':                scan_id,
        'software_name':     name,
        'version':           version,
        'filename':          filename,
        'timestamp':         datetime.now().isoformat(),
        'status':            status,
        'vulnerability_count': vuln_count,
        'critical_count':    sev_counts.get('Critical', 0),
        'high_count':        sev_counts.get('High', 0),
        'medium_count':      sev_counts.get('Medium', 0),
        'low_count':         sev_counts.get('Low', 0),
    }
    if error:
        meta['error'] = error
    if warning:
        meta['warning'] = warning
    (results_dir / 'metadata.json').write_text(json.dumps(meta, indent=2))


@app.route('/api/download/<scan_id>')
def download_report(scan_id):
    report = Path(app.config['RESULTS_FOLDER']) / f'scan_{scan_id}' / f'report_{scan_id}.xlsx'
    if not report.exists():
        return jsonify({'error': 'Report not found'}), 404
    return send_file(report, as_attachment=True,
                     download_name=f'patchscout_report_{scan_id}.xlsx',
                     mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')


# ── run ───────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    print("\n" + "=" * 60)
    print("  PatchScout — AI Vulnerability Detection")
    print("  Powered by DeepSeek 6.7B via HF Inference API")
    print("=" * 60)
    print("  Open: http://localhost:5000")
    print("  Stop: Ctrl+C\n")
    app.run(debug=True, host='0.0.0.0', port=5000)
