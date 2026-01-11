# Secure Password Manager (Python)

A simple command line password manager built in Python that demonstrates secure password handling using hashing, salting, and account lockout mechanisms.

## Features
- Secure password hashing with SHA-256 and random salt
- Password strength validation
- Hidden password input (getpass)
- Account lockout after multiple failed attempts
- User data stored securely in JSON format

## Technologies Used
- Python
- hashlib
- secrets
- getpass
- json
- regex

## Security Considerations
- Passwords are never stored in plaintext
- Each password is salted before hashing
- Account lockout mitigates brute force attacks
- Sensitive credential files are excluded from version control

## How to Run
```bash
python password_manager.py
