# PatchScout 🛡️

**AI-Powered Vulnerability Detection Tool for Open-Source Software**

[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Status-In%20Development-yellow.svg)]()

## 🎯 Overview

PatchScout is an advanced AI-powered tool that leverages Large Language Models (LLMs) and machine learning techniques to detect vulnerabilities and malicious code in software source code. Built for the AI Grand Challenge, PatchScout aims to empower developers to create secure, reliable, and resilient open-source software at scale.

### 🌟 Key Features

- **Multi-Language Support**: Java, Python, C/C++/C#, PHP, Ruby, Rust, Kotlin, Swift, HTML, JavaScript, Go
- **Comprehensive Detection**: CVEs, CWEs, OWASP Top 10, zero-day vulnerabilities, malicious patterns
- **Automated Mitigation**: Suggests fixes and code hardening techniques
- **Real-Time Analysis**: IDE integration for instant feedback
- **Detailed Reporting**: Generates comprehensive security reports with severity rankings
- **Adaptive Learning**: Improves accuracy through feedback on false positives/negatives

---

## 📋 Problem Statement

The development of a large language model (LLM) or similar AI techniques-based tool for detection of vulnerabilities (Malicious Code) in source code of software (especially open-source software) and suggestion of mitigation measures could provide a range of capabilities that assist developers in identifying, mitigating, and preventing security vulnerabilities and malicious behaviour.

### Key Capabilities

#### Malicious Code Detection
- **Identify Malicious Patterns:** Analyze source code to identify patterns indicative of malicious behaviour (e.g., backdoors, trojans, spyware, unauthorized access).
- **Suspicious Code Snippets:** Flag suspicious or non-idiomatic code, such as encoded payloads, obfuscated code, or unusual library usage.
- **Code Behaviour Analysis:** Employ dynamic analysis to evaluate code behaviour, identifying suspicious actions like network communication, privilege escalation, or data exfiltration.

#### Vulnerability Detection
- **Common Vulnerabilities and Exposures (CVEs):** Detect and list known CVEs (buffer overflows, SQL injections, XSS, etc.) by scanning for vulnerable code patterns.
- **Unknown / Zero-Day Vulnerabilities:** Attempt to detect potential unknown/zero-day vulnerabilities through code pattern or misconfiguration analysis.
- **Dependency Vulnerabilities:** Check open-source dependencies for known vulnerabilities.
- **Severity Ranking:** Allow users to filter and prioritize vulnerabilities based on severity.
- **Risk Assessment:** Provide risk assessment to help prioritize which vulnerabilities to address first.

#### Code Quality and Best Practices Enforcement
- **Code Review and Suggestions:** Suggest code quality improvements and safer alternatives.
- **Automated Code Audits:** Automate code audits, reporting potential security flaws and mitigation suggestions.
- **Compliance Assistance:** Assist in ensuring compliance with standards (e.g., OWASP, PCI DSS).

#### Mitigation Measures and Recommendations
- **Automated Patches and Fixes:** Suggest or automate fixes for vulnerabilities or malicious code.
- **Code Hardening:** Suggest security hardening techniques (input validation, encryption, least privilege principle).
- **Customizable Security Rules:** Allow enforcement of project- or organization-specific security policies.

#### Reporting and Documentation
- **Detailed Security Reports:** Generate reports explaining vulnerabilities, their severity, and remediation steps.

#### User-friendly Interface
- **Real-time Analysis and Feedback:** Integrate with IDEs for real-time feedback.
- **Collaboration Tools:** Enable team collaboration on security issues and track resolution progress.

#### Adaptive Learning and Customisation
- **Learning from False Positives/Negatives:** Improve accuracy over time with feedback.
- **Customisable Sensitivity:** Allow users to adjust detection sensitivity based on project needs.


---

## 🚀 Getting Started

### Prerequisites

- Python 3.9 or higher
- pip package manager
- Git

### Installation

```bash
# Clone the repository
git clone https://github.com/Parthpatil7/PatchScout.git
cd PatchScout

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Quick Start

```bash
# Run vulnerability scan on a single file
python src/main.py --file path/to/code.java

# Scan entire project
python src/main.py --directory path/to/project --language java

# Generate report
python src/main.py --directory path/to/project --output report.xlsx
```

---

## 📁 Project Structure

```
PatchScout/
├── src/                    # Source code
│   ├── analyzers/         # Language-specific analyzers
│   ├── detectors/         # Vulnerability detection modules
│   ├── mitigation/        # Mitigation suggestion engine
│   ├── parsers/           # Code parsers for different languages
│   ├── reporting/         # Report generation
│   └── main.py            # Main entry point
├── models/                # Trained models and weights
├── data/                  # Training and test datasets
│   ├── raw/              # Raw datasets
│   ├── processed/        # Preprocessed data
│   └── benchmarks/       # Benchmark datasets
├── tests/                 # Unit and integration tests
├── docs/                  # Documentation
├── output/                # Generated reports and results
├── config/                # Configuration files
├── requirements.txt       # Python dependencies
└── README.md             # This file
```

---

## 🎯 Competition Timeline

### Stage I - Initial Submission (Oct 28 - Oct 31, 2025)
- **Dataset Release**: Oct 28, 2025 at 10:00 AM
- **Submission Deadline**: Oct 31, 2025, Midnight
- **Languages**: Java, Python, C/C++/C#, PHP
- **Deliverable**: Excel sheet with vulnerability findings
- **Top 15-20 teams** selected for physical evaluation

### Stage II - Enhanced Capabilities
- Additional language support: Ruby, Rust, Kotlin, Swift, HTML, JavaScript, Go
- Mitigation measures implementation
- Performance optimization
- **Top 6 teams** advance

### Stage III - Final Evaluation
- Comprehensive testing across all application types
- Scalability demonstration
- Complete documentation
- User interface evaluation

---

## 🔍 Core Capabilities

### Malicious Code Detection
- **Identify Malicious Patterns**: Detect backdoors, trojans, spyware, unauthorized access code
- **Suspicious Code Snippets**: Flag encoded payloads, obfuscated code, unusual library usage
- **Code Behaviour Analysis**: Dynamic analysis for network communication, privilege escalation, data exfiltration

### Vulnerability Detection
- **Common Vulnerabilities and Exposures (CVEs)**: Detect and list known CVEs (buffer overflows, SQL injections, XSS, etc.) by scanning the code for patterns that match or resemble vulnerable code structures.
- **Unknown / Zero-Day Vulnerabilities**: Attempt to detect potential unknown/zero-day vulnerabilities through code pattern or misconfiguration analysis.
- **Dependency Vulnerabilities**: Check open-source dependencies for known vulnerabilities.
- **Severity Ranking**: Filter and prioritize vulnerabilities based on severity.
- **Risk Assessment**: Provide risk assessment to help prioritize which vulnerabilities to address first.

### Code Quality and Best Practices Enforcement
- **Code Review and Suggestions**: Suggest code quality improvements and safer alternatives.
- **Automated Code Audits**: Automate code audits, reporting potential security flaws and mitigation suggestions.
- **Compliance Assistance**: Assist in ensuring compliance with standards (e.g., OWASP, PCI DSS).

### Mitigation Measures and Recommendations
- **Automated Patches and Fixes**: Suggest or automate fixes for vulnerabilities or malicious code.
- **Code Hardening**: Suggest security hardening techniques (input validation, encryption, least privilege principle).
- **Customizable Security Rules**: Allow enforcement of project- or organization-specific security policies.

### Reporting and Documentation
- **Detailed Security Reports**: Generate reports explaining vulnerabilities, their severity, and remediation steps.

### User-friendly Interface
- **Real-time Analysis and Feedback**: Integrate with IDEs for real-time feedback.
- **Collaboration Tools**: Enable team collaboration on security issues and track resolution progress.

### Adaptive Learning and Customisation
- **Learning from False Positives/Negatives**: Improve accuracy over time with feedback.
- **Customisable Sensitivity**: Allow users to adjust detection sensitivity based on project needs.

---

## 📊 Evaluation Criteria

### Stage I Shortlisting (Weightage)
- **Languages Supported** (30%): Java, Python, C/C++/C#, PHP
- **Vulnerabilities Detected** (40%): Critical/High (60%), Medium (30%), Low (10%)
- **Detection Accuracy** (30%): F1 Score

### Stage I Physical Evaluation
- **Languages Supported** (20%)
- **Vulnerabilities Detected** (30%)
- **Detection Accuracy** (20%)
- **Approach** (30%): Methodology, Architecture, Scalability, Resource Utilization

### Stage II & III
- Extended language support
- Mitigation measures quality
- Processing time performance
- Explainability of decisions
- Granularity of detection
- Scalability and documentation

---

## 📚 Training Datasets

- [SARD - Software Assurance Reference Dataset](https://samate.nist.gov/SARD/)
- [Devign - GitHub Vulnerability Dataset](https://github.com/epicosy/devign)
- [CodeXGLUE - Defect Detection](https://github.com/microsoft/CodeXGLUE)
- [Multi-language Dataset (2024)](https://zenodo.org/records/13870382)
- [MegaVul - C/C++ Vulnerabilities](https://github.com/Icyrockton/MegaVul)
- [DiverseVul - CWE Classification](https://github.com/wagner-group/diversevul)

---

## 🤝 Contributing

We welcome contributions! Please see our contributing guidelines for more details.

---

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

## 📧 Contact

For questions or support, please contact the development team.

---

Ultimately, PatchScout aims to combine the power of LLMs and AI with traditional vulnerability detection and mitigation techniques  making it a highly valuable tool for open-source software development teams.
