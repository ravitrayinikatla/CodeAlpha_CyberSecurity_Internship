# CodeAlpha_CyberSecurity_Internship
Cyber Security Internship tasks completed for CodeAlpha, including Basic Network Sniffer, Phishing Awareness Training, and Secure Coding Review.

# Objective

Perform a secure code review of a Python Flask web application to identify security vulnerabilities and recommend remediation measures.

# Programming Language

* Python

# Application Audited

* Flask Login Application (`vulnerable_app.py`)

# Methodology

* Manual Code Inspection
* Static Analysis using Bandit
* Reference Framework: OWASP Top 10 (2021)

# Vulnerabilities Identified

1. SQL Injection
2. Cross-Site Scripting (XSS)
3. Hardcoded Credentials
4. Weak Password Hashing (MD5)
5. Missing Authentication
6. Missing Authorization
7. Insecure File Upload
8. Debug Mode Enabled
9. Hardcoded Secret Key
10. Server Exposed on All Interfaces

# Files Included

* `vulnerable_app.py` – Intentionally vulnerable Flask application.
* `security_review_report.pdf` – Detailed security review report.
* `output.png` – Screenshots and execution results.

# Tools Used

* Python
* Flask
* Bandit (SAST Tool)
* VS Code

# References

* OWASP Top 10 (2021)
* OWASP Testing Guide
* Flask Security Documentation

# Outcome

Successfully performed a secure coding review, documented vulnerabilities, and provided recommendations and remediation steps for safer code.

# Author

Katla Ravitrayini:https://github.com/ravitrayinikatla


