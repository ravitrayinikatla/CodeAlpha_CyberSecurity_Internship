# Task 3: Secure Coding Review

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

* `README.md` – Documentation describing the objective, methodology, identified vulnerabilities, tools used, and outcomes of the secure coding review.

* `vulnerable_app.py` – Intentionally vulnerable Flask application used for performing the security assessment.

* `security_review_report.docx` – Detailed report containing identified vulnerabilities, severity levels, recommendations, and remediation steps.

* `Secure_coding_output.png` – Screenshot showing the execution output of the vulnerable application and security analysis results.

* `securecodingpic.png` – Additional screenshot demonstrating the application interface and findings during the secure code review.

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



