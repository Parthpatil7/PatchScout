# PatchScout Documentation

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                         PatchScout                          │
│                  Vulnerability Detection Tool               │
└─────────────────────────────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────┐
│                      Input Layer                            │
│  • Source Code Files (Java, Python, C/C++, PHP, etc.)      │
│  • Directories / Projects                                   │
│  • Configuration Files                                      │
└─────────────────────────────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────┐
│                   Parsing & Analysis Layer                  │
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌─────────────────┐  │
│  │   Language   │  │  AST Parser  │  │  Code Tokenizer │  │
│  │   Detector   │  │              │  │                 │  │
│  └──────────────┘  └──────────────┘  └─────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────┐
│                    AI/ML Detection Engine                   │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │           LLM-Based Analysis                        │   │
│  │  • Pattern Recognition                              │   │
│  │  • Semantic Understanding                           │   │
│  │  • Context-Aware Detection                          │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │        Static Analysis Components                   │   │
│  │  • Rule-Based Detection                             │   │
│  │  • Pattern Matching                                 │   │
│  │  • Control Flow Analysis                            │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │        Vulnerability Databases                      │   │
│  │  • CVE Database                                     │   │
│  │  • CWE Mappings                                     │   │
│  │  • OWASP Top 10                                     │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────┐
│              Vulnerability Classification Layer             │
│                                                             │
│  • Severity Assessment (Critical/High/Medium/Low)          │
│  • CWE/CVE Mapping                                         │
│  • Risk Scoring                                            │
│  • Priority Ranking                                        │
└─────────────────────────────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────┐
│                 Mitigation Engine                           │
│                                                             │
│  • Fix Suggestions                                         │
│  • Code Hardening Recommendations                          │
│  • Best Practice Guidelines                                │
│  • Automated Patch Generation (Stage II/III)               │
└─────────────────────────────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────┐
│                    Reporting Layer                          │
│                                                             │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │  Excel   │  │   JSON   │  │   HTML   │  │   PDF    │   │
│  │  Report  │  │  Report  │  │  Report  │  │  Report  │   │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘   │
└─────────────────────────────────────────────────────────────┘
```

## Key Components

### 1. Language Parsers
- Tree-sitter based parsing for multiple languages
- AST generation and analysis
- Code tokenization for LLM processing

### 2. Detection Modules
- **LLM-Based Detection**: Fine-tuned CodeBERT/GraphCodeBERT
- **Static Analysis**: Rule-based pattern matching
- **Dynamic Analysis**: Behavior simulation (Stage II)
- **Dependency Scanner**: Third-party library vulnerability check

### 3. Knowledge Base
- CVE Database integration
- CWE taxonomy mapping
- OWASP Top 10 patterns
- Custom vulnerability signatures

### 4. Mitigation Engine
- Fix recommendation system
- Code refactoring suggestions
- Security best practices
- Automated patching (future)

## Development Roadmap

### Phase 1: Foundation (Current - Oct 28)
- [x] Project structure setup
- [x] Configuration system
- [ ] Basic CLI interface
- [ ] Language parsers (Java, Python, C/C++, PHP)
- [ ] Dataset integration

### Phase 2: Core Detection (Oct 28 - Oct 30)
- [ ] LLM model integration (CodeBERT)
- [ ] Static analysis rules
- [ ] CVE/CWE mapping
- [ ] Severity classification
- [ ] Excel report generation

### Phase 3: Stage I Submission (Oct 31)
- [ ] Complete vulnerability detection
- [ ] Generate required Excel format
- [ ] Performance optimization
- [ ] Testing on benchmark datasets

### Phase 4: Enhancement (Stage II)
- [ ] Additional language support
- [ ] Mitigation suggestions
- [ ] Performance improvements
- [ ] UI/UX enhancements

### Phase 5: Advanced Features (Stage III)
- [ ] Automated patch generation
- [ ] IDE integration
- [ ] Collaborative features
- [ ] Scalability improvements

## Dataset Integration

### Training Datasets
1. **SARD** - Reference vulnerable code samples
2. **Devign** - GitHub vulnerability dataset
3. **CodeXGLUE** - Defect detection dataset
4. **Multi-language (2024)** - Modern multi-language dataset

### Evaluation Datasets
- Provided by competition (Oct 28, 2025)
- Holdout datasets for final evaluation

## Performance Targets

### Stage I
- **Accuracy**: F1 Score > 0.75
- **Speed**: < 1 second per KB of code
- **Languages**: Java, Python, C/C++, PHP
- **Detection**: Critical/High priority vulnerabilities

### Stage II
- **Accuracy**: F1 Score > 0.85
- **Mitigation**: 80%+ actionable suggestions
- **Explainability**: Clear reasoning for all detections

### Stage III
- **Scalability**: Handle enterprise-scale codebases
- **Usability**: Minimal learning curve
- **Documentation**: Comprehensive user manual
