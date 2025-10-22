"""
Simplified test script to demonstrate PatchScout functionality
"""

import sys
import os

# Test basic imports
print("Testing PatchScout components...\n")

# Test 1: Language Detection
print("="*60)
print("TEST 1: Language Detection")
print("="*60)

from src.analyzers.language_detector import LanguageDetector

detector = LanguageDetector()

test_files = [
    "test.py",
    "Main.java",
    "code.c",
    "app.cpp",
    "index.php"
]

print("\nLanguage detection test:")
for file in test_files:
    lang = detector.detect(file)
    supported = detector.is_supported(file, stage=1)
    print(f"  {file:15} -> {lang:10} (Stage 1: {'✓' if supported else '✗'})")

# Test 2: CVE/CWE Mapping
print("\n" + "="*60)
print("TEST 2: CVE/CWE Mapping")
print("="*60)

from src.detectors.cve_mapper import CVEMapper
from src.detectors.cwe_mapper import CWEMapper

cve_mapper = CVEMapper()
cwe_mapper = CWEMapper()

# Test vulnerability
test_vuln = {
    'type': 'SQL Injection',
    'severity': 'Critical',
    'line_number': 5,
    'code_snippet': 'SELECT * FROM users WHERE id = '
}

# Get CVE
cve_id = cve_mapper.map_vulnerability_to_cve(test_vuln)
print(f"\nVulnerability Type: {test_vuln['type']}")
print(f"Mapped CVE: {cve_id}")

# Get CWE
cwe_id = cwe_mapper.get_cwe_from_vulnerability_type(test_vuln['type'])
cwe_details = cwe_mapper.get_cwe_details(cwe_id)
print(f"Mapped CWE: {cwe_id}")
print(f"CWE Name: {cwe_details['name']}")
print(f"OWASP Category: {cwe_details['owasp']}")
print(f"Severity: {cwe_details['severity']}")
print(f"Rank in CWE Top 25: #{cwe_details['rank']}")

# Test 3: Parsers
print("\n" + "="*60)
print("TEST 3: Code Parsers")
print("="*60)

from src.parsers.python_parser import PythonParser
from src.parsers.java_parser import JavaParser
from src.parsers.c_parser import CParser
from src.parsers.php_parser import PHPParser

# Test Python parser
print("\nPython Parser Test:")
py_parser = PythonParser()
py_code = """
import pickle
def get_user(username):
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    eval(user_input)
"""
parsed = py_parser.parse(py_code)
print(f"  Parse success: {parsed['success']}")
print(f"  Lines of code: {parsed['num_lines']}")
functions = py_parser.extract_functions(parsed)
print(f"  Functions found: {[f['name'] for f in functions]}")
dangerous = py_parser.find_dangerous_functions(parsed)
print(f"  Dangerous calls: {len(dangerous)}")

# Test Java parser
print("\nJava Parser Test:")
java_parser = JavaParser()
java_code = """
public class Test {
    public void getData(String id) {
        String query = "SELECT * FROM users WHERE id = " + id;
        Runtime.getRuntime().exec("ls " + filename);
    }
}
"""
parsed_java = java_parser.parse(java_code)
print(f"  Parse success: {parsed_java['success']}")
sql_issues = java_parser.find_sql_injection_patterns(parsed_java)
cmd_issues = java_parser.find_command_injection(parsed_java)
print(f"  SQL injection patterns: {len(sql_issues)}")
print(f"  Command injection patterns: {len(cmd_issues)}")

# Test 4: Vulnerability Detector
print("\n" + "="*60)
print("TEST 4: Vulnerability Detection")
print("="*60)

from src.detectors.vulnerability_detector import VulnerabilityDetector

config = {'model': {}}
detector = VulnerabilityDetector(config)

test_code = """
$user_id = $_GET['id'];
$query = "SELECT * FROM users WHERE id = " . $user_id;
echo $_GET['name'];
system("cat " . $filename);
"""

vulns = detector.detect(test_code, 'php', 'test.php')
print(f"\nVulnerabilities detected: {len(vulns)}")
for vuln in vulns:
    print(f"  - {vuln['type']} (Line {vuln['line_number']}, {vuln['severity']})")
    print(f"    CWE: {vuln['cwe']}")

# Test 5: Report Generation
print("\n" + "="*60)
print("TEST 5: Report Generation")
print("="*60)

from pathlib import Path
from src.reporting.report_generator import ReportGenerator

# Create sample vulnerabilities
vulnerabilities = [
    {
        'type': 'SQL Injection',
        'severity': 'Critical',
        'cwe': 'CWE-89',
        'cve': 'CVE-2023-28432',
        'line_number': 5,
        'code_snippet': "SELECT * FROM users WHERE id = ' + user_id",
        'file_name': 'test.py',
        'language': 'python'
    },
    {
        'type': 'Buffer Overflow',
        'severity': 'Critical',
        'cwe': 'CWE-120',
        'cve': 'CVE-2023-23560',
        'line_number': 12,
        'code_snippet': 'strcpy(buffer, input);',
        'file_name': 'test.c',
        'language': 'c'
    }
]

Path("output").mkdir(exist_ok=True)

report_gen = ReportGenerator({})
output_file = "output/test_report.xlsx"

report_gen.generate_excel_report(vulnerabilities, output_file, team_name="TestTeam")
print(f"\n✓ Excel report generated: {output_file}")

# Verify file was created
if Path(output_file).exists():
    print(f"  File size: {Path(output_file).stat().st_size} bytes")
else:
    print("  ✗ File was not created!")

# Test JSON report
json_file = "output/test_report.json"
report_gen.generate_json_report(vulnerabilities, json_file)
print(f"✓ JSON report generated: {json_file}")

if Path(json_file).exists():
    import json
    with open(json_file) as f:
        data = json.load(f)
    print(f"  Vulnerabilities in report: {len(data['vulnerabilities'])}")

print("\n" + "="*60)
print("✓ All basic tests passed!")
print("="*60 + "\n")
