"""
Remediation Engine for PatchScout
Provides secure code fixes and recommendations for detected vulnerabilities
"""

from typing import Dict, List, Any, Optional
import re


class RemediationEngine:
    """Generates remediation suggestions for detected vulnerabilities"""
    
    def __init__(self):
        """Initialize remediation engine with fix patterns"""
        self.remediation_patterns = self._load_remediation_patterns()
    
    def _load_remediation_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Load remediation patterns for each vulnerability type"""
        return {
            'SQL Injection': {
                'python': {
                    'description': 'Use parameterized queries or ORM to prevent SQL injection',
                    'secure_example': '''# Secure: Use parameterized queries
cursor.execute("SELECT * FROM users WHERE username = %s", (username,))

# Or use ORM (Django/SQLAlchemy)
User.objects.filter(username=username)''',
                    'explanation': 'Parameterized queries separate SQL code from data, preventing injection attacks.',
                    'recommendations': [
                        'Use parameterized queries with placeholders (%s, ?, :name)',
                        'Use ORM frameworks (SQLAlchemy, Django ORM)',
                        'Validate and sanitize all user inputs',
                        'Use stored procedures with parameters',
                        'Implement least privilege database access'
                    ]
                },
                'java': {
                    'description': 'Use PreparedStatement instead of concatenating SQL queries',
                    'secure_example': '''// Secure: Use PreparedStatement
String query = "SELECT * FROM users WHERE username = ?";
PreparedStatement stmt = connection.prepareStatement(query);
stmt.setString(1, username);
ResultSet rs = stmt.executeQuery();''',
                    'explanation': 'PreparedStatement precompiles SQL and treats parameters as data, not executable code.',
                    'recommendations': [
                        'Always use PreparedStatement with placeholders',
                        'Never concatenate user input into SQL strings',
                        'Use JPA/Hibernate for database operations',
                        'Validate input against whitelist patterns',
                        'Apply principle of least privilege for DB users'
                    ]
                },
                'php': {
                    'description': 'Use PDO prepared statements or mysqli prepared statements',
                    'secure_example': '''// Secure: Use PDO prepared statements
$stmt = $pdo->prepare("SELECT * FROM users WHERE username = :username");
$stmt->execute(['username' => $username]);

// Or mysqli prepared statements
$stmt = $mysqli->prepare("SELECT * FROM users WHERE username = ?");
$stmt->bind_param("s", $username);
$stmt->execute();''',
                    'explanation': 'Prepared statements bind parameters safely, preventing SQL code injection.',
                    'recommendations': [
                        'Use PDO or mysqli prepared statements',
                        'Never use mysql_* functions (deprecated)',
                        'Validate and sanitize user inputs',
                        'Use parameterized stored procedures',
                        'Implement input validation on server-side'
                    ]
                },
                'c': {
                    'description': 'Use parameterized queries with SQLite or PostgreSQL prepared statements',
                    'secure_example': '''// Secure: Use SQLite prepared statements
sqlite3_stmt *stmt;
sqlite3_prepare_v2(db, "SELECT * FROM users WHERE username = ?", -1, &stmt, NULL);
sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
sqlite3_step(stmt);''',
                    'explanation': 'Prepared statements prevent SQL injection by separating SQL logic from data.',
                    'recommendations': [
                        'Use sqlite3_prepare_v2 and bind functions',
                        'Never use sprintf/strcat to build queries',
                        'Validate input length and format',
                        'Use whitelist validation for inputs',
                        'Implement proper error handling'
                    ]
                }
            },
            
            'Cross-Site Scripting (XSS)': {
                'python': {
                    'description': 'Use template auto-escaping and sanitize user input',
                    'secure_example': '''# Secure: Flask/Django auto-escape (enabled by default)
# Flask/Jinja2
return render_template('page.html', user_input=user_data)

# Django
from django.utils.html import escape
safe_output = escape(user_input)

# Or use bleach for HTML sanitization
import bleach
clean_html = bleach.clean(user_html)''',
                    'explanation': 'Auto-escaping converts special characters to HTML entities, preventing script execution.',
                    'recommendations': [
                        'Use framework auto-escaping (Flask, Django)',
                        'Use bleach library for HTML sanitization',
                        'Implement Content Security Policy (CSP)',
                        'Validate input against expected format',
                        'Use HTTPOnly and Secure flags for cookies'
                    ]
                },
                'java': {
                    'description': 'Use OWASP Java Encoder or ESAPI for output encoding',
                    'secure_example': '''// Secure: Use OWASP Java Encoder
import org.owasp.encoder.Encode;

String safe = Encode.forHtml(userInput);
out.println("<div>" + safe + "</div>");

// Or use JSTL with escapeXml
<c:out value="${userInput}" escapeXml="true"/>''',
                    'explanation': 'Encoding converts special characters to safe HTML entities, preventing XSS.',
                    'recommendations': [
                        'Use OWASP Java Encoder or ESAPI',
                        'Use JSTL <c:out> with escapeXml="true"',
                        'Implement Content Security Policy',
                        'Validate input on server-side',
                        'Use HTTPOnly and Secure cookies'
                    ]
                },
                'php': {
                    'description': 'Use htmlspecialchars() or htmlentities() for output escaping',
                    'secure_example': '''// Secure: Use htmlspecialchars()
echo htmlspecialchars($user_input, ENT_QUOTES, 'UTF-8');

// For HTML attributes
echo '<input value="' . htmlspecialchars($value, ENT_QUOTES, 'UTF-8') . '">';

// Or use template engine with auto-escaping (Twig, Blade)''',
                    'explanation': 'htmlspecialchars converts special characters to HTML entities, preventing script execution.',
                    'recommendations': [
                        'Use htmlspecialchars() with ENT_QUOTES flag',
                        'Use template engines with auto-escaping',
                        'Implement Content Security Policy',
                        'Validate input against whitelist',
                        'Set HTTPOnly and Secure cookie flags'
                    ]
                }
            },
            
            'Command Injection': {
                'python': {
                    'description': 'Avoid shell=True and validate input, or use safer alternatives',
                    'secure_example': '''# Secure: Use array form without shell=True
import subprocess
# Good - no shell interpretation
subprocess.run(['ls', '-l', directory])

# Better - use specific libraries instead of shell commands
import os
files = os.listdir(directory)

# If shell needed, use shlex.quote()
import shlex
safe_arg = shlex.quote(user_input)
subprocess.run(f'ls {safe_arg}', shell=True)''',
                    'explanation': 'Using array form without shell=True prevents shell interpretation of metacharacters.',
                    'recommendations': [
                        'Never use shell=True with user input',
                        'Use list/array form for subprocess calls',
                        'Use shlex.quote() if shell is necessary',
                        'Use specific Python libraries instead of shell',
                        'Validate input against strict whitelist'
                    ]
                },
                'java': {
                    'description': 'Validate input and use ProcessBuilder with separate arguments',
                    'secure_example': '''// Secure: Use ProcessBuilder with separate arguments
ProcessBuilder pb = new ProcessBuilder("ls", "-l", directory);
Process p = pb.start();

// Validate input first
if (!directory.matches("[a-zA-Z0-9_/]+")) {
    throw new IllegalArgumentException("Invalid directory");
}''',
                    'explanation': 'ProcessBuilder with separate arguments prevents shell interpretation.',
                    'recommendations': [
                        'Use ProcessBuilder with argument array',
                        'Never concatenate user input into commands',
                        'Validate input against strict whitelist',
                        'Use Java libraries instead of shell commands',
                        'Implement least privilege for execution'
                    ]
                },
                'php': {
                    'description': 'Use escapeshellarg() or avoid shell execution entirely',
                    'secure_example': '''// Secure: Use escapeshellarg()
$safe_arg = escapeshellarg($user_input);
exec("ls " . $safe_arg);

// Better: Use PHP functions instead of shell
$files = scandir($directory);

// Best: Avoid exec/system/shell_exec entirely''',
                    'explanation': 'escapeshellarg() properly escapes arguments for safe shell usage.',
                    'recommendations': [
                        'Use PHP built-in functions instead of shell',
                        'Use escapeshellarg() for all arguments',
                        'Validate input against strict whitelist',
                        'Avoid exec/system/shell_exec if possible',
                        'Implement input length limits'
                    ]
                }
            },
            
            'Buffer Overflow': {
                'c': {
                    'description': 'Use safe string functions with bounds checking',
                    'secure_example': '''// Secure: Use safe string functions
// Instead of strcpy
strncpy(dest, src, sizeof(dest) - 1);
dest[sizeof(dest) - 1] = '\\0';

// Instead of strcat
strncat(dest, src, sizeof(dest) - strlen(dest) - 1);

// Instead of gets
fgets(buffer, sizeof(buffer), stdin);

// Instead of sprintf
snprintf(buffer, sizeof(buffer), "User: %s", username);''',
                    'explanation': 'Bounded string functions prevent writing beyond buffer limits.',
                    'recommendations': [
                        'Use strncpy, strncat, snprintf instead of unsafe versions',
                        'Always null-terminate strings after strncpy',
                        'Use fgets instead of gets',
                        'Validate buffer sizes before operations',
                        'Consider using safer C++ string class',
                        'Enable compiler flags: -fstack-protector-all'
                    ]
                },
                'cpp': {
                    'description': 'Use C++ std::string and avoid C-style string functions',
                    'secure_example': '''// Secure: Use C++ string class
std::string dest = src;  // Safe, automatic memory management
dest += more_data;       // Safe concatenation

// Or use std::vector for buffers
std::vector<char> buffer(size);
std::copy_n(src, std::min(size, src_len), buffer.begin());

// Use std::string_view for read-only operations''',
                    'explanation': 'C++ std::string handles memory automatically and prevents overflows.',
                    'recommendations': [
                        'Use std::string instead of char arrays',
                        'Use std::vector for dynamic buffers',
                        'Avoid C-style string functions',
                        'Use smart pointers for memory management',
                        'Enable modern C++ compiler warnings'
                    ]
                }
            },
            
            'Path Traversal': {
                'python': {
                    'description': 'Validate and sanitize file paths, use os.path functions',
                    'secure_example': '''# Secure: Validate and normalize paths
import os
from pathlib import Path

# Validate path is within allowed directory
base_dir = '/var/www/uploads'
user_path = os.path.normpath(user_input)
full_path = os.path.join(base_dir, user_path)

if not full_path.startswith(base_dir):
    raise ValueError("Invalid path")

# Or use pathlib for safer path handling
base = Path('/var/www/uploads')
requested = (base / user_input).resolve()
if base not in requested.parents:
    raise ValueError("Path traversal detected")''',
                    'explanation': 'Path validation ensures files can only be accessed within allowed directories.',
                    'recommendations': [
                        'Use os.path.normpath() to normalize paths',
                        'Check resolved path starts with base directory',
                        'Use pathlib for modern path handling',
                        'Implement whitelist of allowed files',
                        'Never directly use user input in file paths'
                    ]
                },
                'java': {
                    'description': 'Validate paths and use canonical path checking',
                    'secure_example': '''// Secure: Validate canonical paths
File baseDir = new File("/var/www/uploads");
File requestedFile = new File(baseDir, userInput);

String canonicalBase = baseDir.getCanonicalPath();
String canonicalRequested = requestedFile.getCanonicalPath();

if (!canonicalRequested.startsWith(canonicalBase)) {
    throw new SecurityException("Path traversal detected");
}''',
                    'explanation': 'Canonical path checking prevents directory traversal attacks.',
                    'recommendations': [
                        'Use getCanonicalPath() for validation',
                        'Check file is within allowed directory',
                        'Implement whitelist of allowed files',
                        'Validate filename against pattern',
                        'Use security manager for file access'
                    ]
                },
                'php': {
                    'description': 'Use realpath() and validate paths',
                    'secure_example': '''// Secure: Validate real paths
$base_dir = '/var/www/uploads';
$requested = realpath($base_dir . '/' . basename($user_input));

if ($requested === false || strpos($requested, $base_dir) !== 0) {
    die("Invalid path");
}

// Use basename to strip directory components
$safe_filename = basename($user_input);''',
                    'explanation': 'realpath() resolves paths and basename() strips directory components.',
                    'recommendations': [
                        'Use realpath() to resolve actual path',
                        'Use basename() to strip directories',
                        'Check resolved path is within base directory',
                        'Implement file whitelist validation',
                        'Never trust user-supplied paths'
                    ]
                }
            },
            
            'Hardcoded Credentials': {
                'python': {
                    'description': 'Use environment variables or secure vaults for credentials',
                    'secure_example': '''# Secure: Use environment variables
import os
from dotenv import load_dotenv

load_dotenv()
password = os.getenv('DB_PASSWORD')
api_key = os.getenv('API_KEY')

# Better: Use secret management service
# AWS Secrets Manager, Azure Key Vault, HashiCorp Vault
import boto3

client = boto3.client('secretsmanager')
secret = client.get_secret_value(SecretId='db-password')''',
                    'explanation': 'Environment variables and vaults keep secrets out of source code.',
                    'recommendations': [
                        'Use environment variables via python-dotenv',
                        'Use secret management services (AWS, Azure, Vault)',
                        'Add .env to .gitignore',
                        'Rotate credentials regularly',
                        'Use different credentials per environment'
                    ]
                },
                'java': {
                    'description': 'Use configuration files or secret management',
                    'secure_example': '''// Secure: Use properties file or environment
String password = System.getenv("DB_PASSWORD");

// Or use properties file (excluded from git)
Properties props = new Properties();
props.load(new FileInputStream("config.properties"));
String apiKey = props.getProperty("api.key");

// Better: Use secret management
// AWS SDK, Azure SDK, or Spring Cloud Config''',
                    'explanation': 'External configuration keeps secrets out of compiled code.',
                    'recommendations': [
                        'Use properties files outside source control',
                        'Use environment variables',
                        'Use secret management services',
                        'Implement credential rotation',
                        'Use Spring Cloud Config for Spring apps'
                    ]
                },
                'php': {
                    'description': 'Use environment variables or configuration files',
                    'secure_example': '''// Secure: Use environment variables
$password = getenv('DB_PASSWORD');
$apiKey = $_ENV['API_KEY'];

// Or use configuration file (outside webroot)
$config = parse_ini_file('/etc/myapp/config.ini');
$password = $config['db_password'];

// Better: Use vault service
// HashiCorp Vault, AWS Secrets Manager''',
                    'explanation': 'Environment variables keep secrets separate from code.',
                    'recommendations': [
                        'Use getenv() or $_ENV for secrets',
                        'Store config files outside webroot',
                        'Add config files to .gitignore',
                        'Use secret management services',
                        'Rotate credentials regularly'
                    ]
                }
            },
            
            'Weak Cryptography': {
                'python': {
                    'description': 'Use strong cryptographic algorithms',
                    'secure_example': '''# Secure: Use SHA-256 or better for hashing
import hashlib
hash_value = hashlib.sha256(data.encode()).hexdigest()

# For passwords, use bcrypt or Argon2
import bcrypt
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

# For encryption, use AES with proper mode
from cryptography.fernet import Fernet
key = Fernet.generate_key()
f = Fernet(key)
encrypted = f.encrypt(data.encode())''',
                    'explanation': 'Modern algorithms like SHA-256, bcrypt, and AES provide adequate security.',
                    'recommendations': [
                        'Use SHA-256 or SHA-3 for hashing',
                        'Use bcrypt/Argon2 for password hashing',
                        'Use AES-256-GCM for encryption',
                        'Avoid MD5, SHA1, DES, 3DES',
                        'Use cryptography library in Python'
                    ]
                },
                'java': {
                    'description': 'Use strong cryptographic APIs',
                    'secure_example': '''// Secure: Use SHA-256 or better
MessageDigest digest = MessageDigest.getInstance("SHA-256");
byte[] hash = digest.digest(data.getBytes());

// For passwords, use BCrypt
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
String hashed = encoder.encode(password);

// For encryption, use AES-GCM
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");''',
                    'explanation': 'Strong algorithms provide adequate protection against attacks.',
                    'recommendations': [
                        'Use SHA-256 or SHA-3',
                        'Use BCrypt for passwords',
                        'Use AES/GCM mode for encryption',
                        'Avoid MD5, SHA1, DES',
                        'Use Java security provider'
                    ]
                }
            },
            
            'Insecure Deserialization': {
                'python': {
                    'description': 'Avoid pickle, use JSON or validate deserialized data',
                    'secure_example': '''# Secure: Use JSON instead of pickle
import json
data = json.loads(untrusted_data)

# If pickle needed, use HMAC to verify data integrity
import hmac
import pickle

def secure_pickle_loads(data, secret_key):
    signature, pickled = data.split(b':', 1)
    if not hmac.compare_digest(signature, 
        hmac.new(secret_key, pickled, 'sha256').digest()):
        raise ValueError("Invalid signature")
    return pickle.loads(pickled)''',
                    'explanation': 'JSON is safe for untrusted data; HMAC verification prevents tampering.',
                    'recommendations': [
                        'Use JSON instead of pickle for untrusted data',
                        'Use HMAC to verify pickle integrity',
                        'Validate deserialized object types',
                        'Use yaml.safe_load() instead of yaml.load()',
                        'Implement input validation after deserialization'
                    ]
                },
                'java': {
                    'description': 'Validate deserialized objects or use JSON',
                    'secure_example': '''// Secure: Use JSON instead of native serialization
import com.fasterxml.jackson.databind.ObjectMapper;
ObjectMapper mapper = new ObjectMapper();
MyObject obj = mapper.readValue(jsonString, MyObject.class);

// If serialization needed, implement validation
class SecureObjectInputStream extends ObjectInputStream {
    @Override
    protected Class<?> resolveClass(ObjectStreamClass desc) 
            throws IOException, ClassNotFoundException {
        if (!isAllowedClass(desc.getName())) {
            throw new InvalidClassException("Unauthorized class");
        }
        return super.resolveClass(desc);
    }
}''',
                    'explanation': 'JSON parsing is safer; whitelisting classes prevents malicious deserialization.',
                    'recommendations': [
                        'Use JSON libraries instead of serialization',
                        'Implement class whitelisting for deserialization',
                        'Use look-ahead deserialization filters',
                        'Validate object state after deserialization',
                        'Keep deserialization libraries updated'
                    ]
                }
            },
            
            'Code Injection': {
                'python': {
                    'description': 'Avoid eval/exec, use AST or safer alternatives',
                    'secure_example': '''# Secure: Use ast.literal_eval for safe evaluation
import ast
data = ast.literal_eval(user_input)  # Only evaluates literals

# For math expressions, use simpleeval
from simpleeval import simple_eval
result = simple_eval(expression, names={"x": 10})

# Avoid eval/exec entirely if possible''',
                    'explanation': 'ast.literal_eval safely evaluates only Python literals, preventing code execution.',
                    'recommendations': [
                        'Use ast.literal_eval() for data structures',
                        'Use simpleeval for math expressions',
                        'Never use eval/exec with user input',
                        'Implement strict input validation',
                        'Use template engines for dynamic content'
                    ]
                },
                'java': {
                    'description': 'Avoid dynamic code execution, use Expression Language safely',
                    'secure_example': '''// Secure: Use JSR-223 with sandboxing
ScriptEngineManager manager = new ScriptEngineManager();
ScriptEngine engine = manager.getEngineByName("javascript");

// Set security manager
System.setSecurityManager(new SecurityManager());

// Or use Spring Expression Language with restrictions
StandardEvaluationContext context = new StandardEvaluationContext();
context.setRootObject(allowedObject);''',
                    'explanation': 'Security manager and restricted contexts limit what code can do.',
                    'recommendations': [
                        'Avoid reflection and dynamic code execution',
                        'Use SecurityManager for scripting',
                        'Restrict Spring EL contexts',
                        'Validate expressions before execution',
                        'Use whitelisting for allowed operations'
                    ]
                }
            }
        }
    
    def get_remediation(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """
        Get remediation advice for a detected vulnerability
        
        Args:
            vulnerability: Vulnerability dictionary from detector
            
        Returns:
            Dictionary with remediation information
        """
        vuln_type = vulnerability.get('type', 'Unknown')
        language = vulnerability.get('language', 'python').lower()
        
        # Get remediation pattern
        patterns = self.remediation_patterns.get(vuln_type, {})
        
        # Try to find language-specific remediation
        remediation = patterns.get(language)
        
        # Fallback to first available language if specific one not found
        if not remediation and patterns:
            remediation = next(iter(patterns.values()))
        
        if remediation:
            return {
                'vulnerability_type': vuln_type,
                'language': language,
                'description': remediation['description'],
                'secure_example': remediation['secure_example'],
                'explanation': remediation['explanation'],
                'recommendations': remediation['recommendations'],
                'original_code': vulnerability.get('code_snippet', ''),
                'file_path': vulnerability.get('file_path', ''),
                'line_number': vulnerability.get('line_number', 'N/A')
            }
        else:
            # Generic remediation for unknown vulnerability types
            return {
                'vulnerability_type': vuln_type,
                'language': language,
                'description': 'Follow secure coding practices',
                'secure_example': 'No specific example available',
                'explanation': 'Review OWASP guidelines for this vulnerability type',
                'recommendations': [
                    'Review OWASP Top 10 guidelines',
                    'Implement input validation',
                    'Use security linters and SAST tools',
                    'Follow principle of least privilege',
                    'Keep dependencies updated'
                ],
                'original_code': vulnerability.get('code_snippet', ''),
                'file_path': vulnerability.get('file_path', ''),
                'line_number': vulnerability.get('line_number', 'N/A')
            }
    
    def generate_remediation_report(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Generate remediation suggestions for all vulnerabilities
        
        Args:
            vulnerabilities: List of detected vulnerabilities
            
        Returns:
            List of remediation suggestions
        """
        remediations = []
        
        for vuln in vulnerabilities:
            remediation = self.get_remediation(vuln)
            remediations.append(remediation)
        
        return remediations
    
    def generate_remediation_summary(self, remediations: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate summary statistics for remediation report
        
        Args:
            remediations: List of remediation suggestions
            
        Returns:
            Summary dictionary
        """
        total = len(remediations)
        
        # Count by vulnerability type
        vuln_counts = {}
        for rem in remediations:
            vuln_type = rem['vulnerability_type']
            vuln_counts[vuln_type] = vuln_counts.get(vuln_type, 0) + 1
        
        # Count by language
        lang_counts = {}
        for rem in remediations:
            lang = rem['language']
            lang_counts[lang] = lang_counts.get(lang, 0) + 1
        
        return {
            'total_vulnerabilities': total,
            'by_type': vuln_counts,
            'by_language': lang_counts,
            'unique_types': len(vuln_counts),
            'languages_affected': len(lang_counts)
        }
