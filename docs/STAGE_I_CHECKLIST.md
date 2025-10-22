# Stage I Submission Checklist

**Deadline: October 31, 2025, Midnight**  
**Dataset Release: October 28, 2025, 10:00 AM**

## ✅ Pre-Submission Requirements

### Core Functionality
- [ ] Java parser and analyzer
- [ ] Python parser and analyzer  
- [ ] C/C++ parser and analyzer
- [ ] PHP parser and analyzer
- [ ] CVE detection and mapping
- [ ] CWE classification
- [ ] Severity ranking (Critical/High/Medium/Low)

### Detection Capabilities
- [ ] SQL Injection detection
- [ ] Cross-Site Scripting (XSS)
- [ ] Buffer Overflow
- [ ] Command Injection
- [ ] Path Traversal
- [ ] Insecure Deserialization
- [ ] Authentication Issues
- [ ] Cryptographic Failures
- [ ] OWASP Top 10 coverage
- [ ] CWE Top 25 coverage

### Output Format
- [ ] Excel report generation
- [ ] Required columns implemented:
  - S.No
  - Primary Language of Benchmark
  - Vulnerability
  - CVE ID
  - Severity
  - CWE ID
  - File name with path
  - Line number
  - Code Snippet at the line
- [ ] Filename format: `GC_PS_01_[Team_Name].xlsx`

### Performance Metrics
- [ ] F1 Score calculation
- [ ] Precision measurement
- [ ] Recall measurement
- [ ] Processing time tracking
- [ ] Performance optimization completed

### Testing
- [ ] Unit tests for parsers
- [ ] Integration tests for detection
- [ ] End-to-end testing on sample datasets
- [ ] Testing on competition dataset (after Oct 28)
- [ ] Validation of output format

## 📊 Evaluation Criteria Checklist

### Languages Supported (30% weightage)
- [ ] Java support verified
- [ ] Python support verified
- [ ] C/C++ support verified
- [ ] C# support (optional)
- [ ] PHP support verified

### Vulnerabilities Detected (40% weightage)
- [ ] Critical severity vulnerabilities
- [ ] High severity vulnerabilities  
- [ ] Medium severity vulnerabilities
- [ ] Low severity vulnerabilities
- [ ] CVE mapping accurate
- [ ] CWE mapping accurate

### Detection Accuracy (30% weightage)
- [ ] F1 Score > 0.70 (target: 0.75+)
- [ ] Low false positive rate
- [ ] Low false negative rate
- [ ] Validated against ground truth

## 📅 Timeline (Oct 28 - Oct 31)

### Day 1 (Oct 28)
- [ ] Download competition dataset (10:00 AM)
- [ ] Analyze dataset structure
- [ ] Identify dataset languages and vulnerability types
- [ ] Initial test run on dataset

### Day 2 (Oct 29)
- [ ] Process full dataset
- [ ] Fine-tune detection rules
- [ ] Optimize performance
- [ ] Generate initial results

### Day 3 (Oct 30)
- [ ] Review and validate results
- [ ] Fix any bugs or issues
- [ ] Improve accuracy
- [ ] Generate draft Excel report

### Day 4 (Oct 31)
- [ ] Final testing
- [ ] Generate final Excel report
- [ ] Verify all requirements
- [ ] Submit before midnight ✓

## 🚀 Submission

### Files to Submit
- [ ] Excel file: `GC_PS_01_[Team_Name].xlsx`
- [ ] Documentation (if required)
- [ ] Tool source code (if required)

### Pre-Submission Verification
- [ ] All columns present in Excel
- [ ] Data format correct
- [ ] No missing values in required fields
- [ ] File naming convention followed
- [ ] File size within limits
- [ ] Checksums/integrity verified

### Submission Portal
- [ ] Account access verified
- [ ] Submission portal tested
- [ ] Backup submission plan ready
- [ ] Confirmation email received

## 📈 Expected Results

### Minimum Thresholds
- **Critical + High**: 60% of total weightage
- **Medium**: 30% of total weightage  
- **Low**: 10% of total weightage
- **F1 Score**: > 0.70
- **Languages**: All 4 (Java, Python, C/C++, PHP)

### Target Results (Top 15-20)
- **Total Vulnerabilities**: Comprehensive coverage
- **Accuracy**: F1 > 0.75
- **Speed**: < 1 sec per KB
- **CVE/CWE Mapping**: 90%+ accuracy

## 🔧 Technical Preparation

### Environment
- [ ] Python environment configured
- [ ] All dependencies installed
- [ ] GPU access configured (if needed)
- [ ] Sufficient disk space
- [ ] Backup systems ready

### Data
- [ ] Training datasets downloaded
- [ ] Model weights available
- [ ] CVE/CWE databases updated
- [ ] Test datasets prepared

### Monitoring
- [ ] Logging enabled
- [ ] Error tracking configured
- [ ] Performance monitoring active
- [ ] Resource usage tracking

## 📞 Contingency Plans

### Technical Issues
- [ ] Backup computation resources
- [ ] Alternative API keys
- [ ] Local model fallback
- [ ] Manual review process

### Submission Issues  
- [ ] Early submission (avoid last minute)
- [ ] Alternative submission methods
- [ ] Contact information ready
- [ ] Screenshots/proof of attempt

## Notes

- Dataset will be released on **Oct 28, 2025 at 10:00 AM**
- **4 days** to complete analysis and submit
- Top **15-20 teams** will be shortlisted
- Physical/VC evaluation for shortlisted teams
- Be ready for demo and presentation

---

**Good Luck! 🍀**
