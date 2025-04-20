# Vulnerability-auditor

A comprehensive tool for simulating and testing various types of cyber attacks in a controlled environment.

## Features

- Technology Scanning
- Vulnerability Testing
  - XSS (Cross-Site Scripting)
  - SQL Injection
  - CMS Vulnerabilities
- Interactive UI
- Detailed Reports

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/cyberattack-simulator.git
cd cyberattack-simulator
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### XSS Vulnerability Testing
```bash
python tests/xss_vulnerability_test.py --target http://localhost:5001
```

The XSS target application includes:
- Reflected XSS in search functionality
- Stored XSS in comments
- DOM-based XSS in URL handling
- API endpoint XSS

### SQL Injection Testing
```bash
python tests/sql_vulnerability_test.py --target http://localhost:5002
```

The SQL injection target application includes:
- Login form with vulnerable authentication
- Product search with UNION-based injection
- API endpoint with numeric parameter injection

## Target Applications

### XSS Target (Port 5001)
A Flask application designed to demonstrate various XSS vulnerabilities:
- Reflected XSS: Search functionality without input sanitization
- Stored XSS: Comment system storing and displaying unsanitized input
- DOM XSS: Client-side URL fragment manipulation
- API XSS: JSON responses containing unsanitized HTML

### SQL Injection Target (Port 5002)
A Flask application with SQLite database demonstrating SQL injection vulnerabilities:
- Database Schema:
  - users table (id, username, password, email)
  - products table (id, name, price, stock)
- Vulnerable Endpoints:
  - Login form with string interpolation
  - Product search with LIKE queries
  - API endpoint with numeric parameters

## Project Structure

```
cyberattack-simulator/
├── targets/               # Vulnerable target applications
│   ├── xss_target.py     # XSS vulnerable application
│   └── sql_target.py     # SQL injection vulnerable application
├── tests/                # Test scripts
│   ├── xss_vulnerability_test.py
│   └── sql_vulnerability_test.py
├── utils/                # Utility modules
│   └── display_utils.py  # Common display functions
├── pages/                # Streamlit pages
│   ├── 2_XSS_Vulnerability_Test.py
│   └── 3_SQL_Vulnerability_Test.py
├── reports/              # Generated test reports
├── requirements.txt      # Python dependencies
└── README.md            # This file
```

## Security Note

This tool is designed for educational purposes only. Always obtain proper authorization before testing any system. The target applications are intentionally vulnerable and should only be run in a controlled environment.

## License

MIT License
