"""
Report Generator for PatchScout
Generates Excel reports in the required competition format
"""

import pandas as pd
from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime


class ReportGenerator:
    """Generates vulnerability reports in various formats"""
    
    REQUIRED_COLUMNS = [
        "S.No",
        "Primary Language of Benchmark",
        "Vulnerability",
        "CVE ID",
        "Severity",
        "Common Weakness Enumeration (CWE) Id",
        "file name with path",
        "line number",
        "Code Snippet at the line"
    ]
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize report generator
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
    
    def generate_excel_report(
        self, 
        vulnerabilities: List[Dict[str, Any]], 
        output_path: str,
        team_name: str = "Team_Name"
    ):
        """
        Generate Excel report in competition format
        
        Args:
            vulnerabilities: List of detected vulnerabilities
            output_path: Path to save the Excel file
            team_name: Name of the team (for filename)
        """
        # Prepare data for DataFrame
        report_data = []
        
        for idx, vuln in enumerate(vulnerabilities, start=1):
            row = {
                "S.No": idx,
                "Primary Language of Benchmark": vuln.get('language', 'Unknown'),
                "Vulnerability": vuln.get('vulnerability_type', 'Unknown'),
                "CVE ID": vuln.get('cve_id', 'N/A'),
                "Severity": vuln.get('severity', 'Unknown'),
                "Common Weakness Enumeration (CWE) Id": vuln.get('cwe_id', 'N/A'),
                "file name with path": vuln.get('file_path', 'Unknown'),
                "line number": vuln.get('line_number', 'N/A'),
                "Code Snippet at the line": vuln.get('code_snippet', 'N/A')
            }
            report_data.append(row)
        
        # Create DataFrame
        df = pd.DataFrame(report_data, columns=self.REQUIRED_COLUMNS)
        
        # Ensure output directory exists
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Generate filename as per competition format: GC_PS_01_Startup_name
        if not output_path.endswith('.xlsx'):
            output_path = output_file.parent / f"GC_PS_01_{team_name}.xlsx"
        
        # Save to Excel
        with pd.ExcelWriter(output_path, engine='openpyxl') as writer:
            df.to_excel(writer, sheet_name='Vulnerabilities', index=False)
            
            # Add summary sheet
            summary_df = self._generate_summary(vulnerabilities)
            summary_df.to_excel(writer, sheet_name='Summary', index=False)
        
        return output_path
    
    def _generate_summary(self, vulnerabilities: List[Dict[str, Any]]) -> pd.DataFrame:
        """
        Generate summary statistics
        
        Args:
            vulnerabilities: List of detected vulnerabilities
            
        Returns:
            DataFrame with summary information
        """
        total_vulns = len(vulnerabilities)
        
        # Count by severity
        severity_counts = {
            'Critical': 0,
            'High': 0,
            'Medium': 0,
            'Low': 0
        }
        
        # Count by language
        language_counts = {}
        
        # Count by CWE
        cwe_counts = {}
        
        for vuln in vulnerabilities:
            # Severity
            severity = vuln.get('severity', 'Unknown')
            if severity in severity_counts:
                severity_counts[severity] += 1
            
            # Language
            language = vuln.get('language', 'Unknown')
            language_counts[language] = language_counts.get(language, 0) + 1
            
            # CWE
            cwe = vuln.get('cwe_id', 'N/A')
            cwe_counts[cwe] = cwe_counts.get(cwe, 0) + 1
        
        # Create summary data
        summary_data = [
            {"Metric": "Total Vulnerabilities", "Count": total_vulns},
            {"Metric": "Critical Severity", "Count": severity_counts['Critical']},
            {"Metric": "High Severity", "Count": severity_counts['High']},
            {"Metric": "Medium Severity", "Count": severity_counts['Medium']},
            {"Metric": "Low Severity", "Count": severity_counts['Low']},
            {"Metric": "Report Generated", "Count": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
        ]
        
        return pd.DataFrame(summary_data)
    
    def generate_json_report(self, vulnerabilities: List[Dict[str, Any]], output_path: str):
        """Generate JSON format report"""
        import json
        
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        report = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "total_vulnerabilities": len(vulnerabilities),
                "tool": "PatchScout v1.0.0"
            },
            "vulnerabilities": vulnerabilities
        }
        
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        return output_path


# Example usage
if __name__ == "__main__":
    # Sample vulnerability data
    sample_vulns = [
        {
            "language": "Java",
            "vulnerability_type": "SQL Injection",
            "cve_id": "CVE-2024-12345",
            "severity": "High",
            "cwe_id": "CWE-89",
            "file_path": "src/main/java/Database.java",
            "line_number": 42,
            "code_snippet": "String query = \"SELECT * FROM users WHERE id = \" + userId;"
        },
        {
            "language": "Python",
            "vulnerability_type": "Command Injection",
            "cve_id": "N/A",
            "severity": "Critical",
            "cwe_id": "CWE-78",
            "file_path": "app/utils.py",
            "line_number": 15,
            "code_snippet": "os.system(f'ping {host}')"
        }
    ]
    
    generator = ReportGenerator({})
    output = generator.generate_excel_report(sample_vulns, "output/test_report.xlsx", "TestTeam")
    print(f"Report generated: {output}")
