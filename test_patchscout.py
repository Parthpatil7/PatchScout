"""
Test script to demonstrate PatchScout functionality
"""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / 'src'))

from analyzers import CodeAnalyzer, LanguageDetector
from detectors import VulnerabilityDetector, CVEMapper, CWEMapper
from reporting import ReportGenerator
from utils import ConfigLoader

def test_single_file():
    """Test analysis of a single file"""
    print("="*60)
    print("TEST 1: Single File Analysis")
    print("="*60)
    
    # Load config
    config_loader = ConfigLoader()
    config = config_loader.load_config()
    
    # Initialize analyzer
    analyzer = CodeAnalyzer(config)
    
    # Analyze Python file
    test_file = "test_samples/vulnerable.py"
    print(f"\nAnalyzing: {test_file}")
    
    result = analyzer.analyze_file(test_file)
    
    if result.get('success'):
        print(f"✓ File analyzed successfully")
        print(f"  Language: {result['language']}")
        print(f"  Vulnerabilities found: {result['vulnerability_count']}")
        print(f"  Processing time: {result['processing_time']:.3f}s")
        
        if result['vulnerabilities']:
            print(f"\n  Top vulnerabilities:")
            for vuln in result['vulnerabilities'][:5]:
                print(f"    - Line {vuln.get('line_number')}: {vuln.get('type')} ({vuln.get('severity')})")
    else:
        print(f"✗ Analysis failed: {result.get('error')}")

def test_directory_analysis():
    """Test analysis of entire directory"""
    print("\n" + "="*60)
    print("TEST 2: Directory Analysis")
    print("="*60)
    
    config_loader = ConfigLoader()
    config = config_loader.load_config()
    analyzer = CodeAnalyzer(config)
    
    test_dir = "test_samples"
    print(f"\nAnalyzing directory: {test_dir}")
    
    results = analyzer.analyze_directory(test_dir, recursive=False)
    
    print(f"\n✓ Analysis complete")
    print(f"  Files analyzed: {len(results)}")
    print(f"  Total vulnerabilities: {sum(r.get('vulnerability_count', 0) for r in results)}")
    
    for result in results:
        if result.get('success') and result.get('vulnerability_count', 0) > 0:
            print(f"\n  {result['file_path']}:")
            print(f"    Language: {result['language']}")
            print(f"    Vulnerabilities: {result['vulnerability_count']}")

def test_cve_cwe_mapping():
    """Test CVE and CWE mapping"""
    print("\n" + "="*60)
    print("TEST 3: CVE/CWE Mapping")
    print("="*60)
    
    cve_mapper = CVEMapper()
    cwe_mapper = CWEMapper()
    
    # Test vulnerability
    test_vuln = {
        'type': 'SQL Injection',
        'severity': 'Critical',
        'line_number': 5,
        'code_snippet': 'SELECT * FROM users WHERE id = ' + str(user_id)
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

def test_report_generation():
    """Test report generation"""
    print("\n" + "="*60)
    print("TEST 4: Report Generation")
    print("="*60)
    
    config_loader = ConfigLoader()
    config = config_loader.load_config()
    
    # Create sample vulnerabilities
    vulnerabilities = [
        {
            'type': 'SQL Injection',
            'severity': 'Critical',
            'cwe': 'CWE-89',
            'cve': 'CVE-2023-28432',
            'line_number': 5,
            'code_snippet': "SELECT * FROM users WHERE id = ' + user_id",
            'file_name': 'test_samples/vulnerable.py',
            'language': 'python'
        },
        {
            'type': 'Buffer Overflow',
            'severity': 'Critical',
            'cwe': 'CWE-120',
            'cve': 'CVE-2023-23560',
            'line_number': 12,
            'code_snippet': 'strcpy(buffer, input);',
            'file_name': 'test_samples/vulnerable.c',
            'language': 'c'
        },
        {
            'type': 'Cross-Site Scripting (XSS)',
            'severity': 'High',
            'cwe': 'CWE-79',
            'cve': 'CVE-2023-26360',
            'line_number': 8,
            'code_snippet': 'echo $_GET["name"];',
            'file_name': 'test_samples/vulnerable.php',
            'language': 'php'
        }
    ]
    
    # Generate Excel report
    report_gen = ReportGenerator(config)
    output_file = "output/test_report.xlsx"
    
    Path("output").mkdir(exist_ok=True)
    
    report_gen.generate_excel_report(vulnerabilities, output_file, team_name="TestTeam")
    print(f"\n✓ Excel report generated: {output_file}")
    
    # Generate JSON report
    json_file = "output/test_report.json"
    report_gen.generate_json_report(vulnerabilities, json_file)
    print(f"✓ JSON report generated: {json_file}")

def test_language_detection():
    """Test language detection"""
    print("\n" + "="*60)
    print("TEST 5: Language Detection")
    print("="*60)
    
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

def main():
    """Run all tests"""
    print("\n" + "#"*60)
    print("#" + " "*18 + "PatchScout Test Suite" + " "*20 + "#")
    print("#"*60 + "\n")
    
    try:
        test_language_detection()
        test_cve_cwe_mapping()
        test_single_file()
        test_directory_analysis()
        test_report_generation()
        
        print("\n" + "="*60)
        print("✓ All tests completed successfully!")
        print("="*60 + "\n")
        
    except Exception as e:
        print(f"\n✗ Test failed with error: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
