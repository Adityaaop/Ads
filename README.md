# Application and Data Security - Assignment 1

**Student Name:** Aditya Ranjan Kumar  
**Roll No:** CS-2341901  
**Section:** 4CSE9  
**Submitted to:** Dr. Ajay Prasad  
**Submission Date:** 15-10-2026  

---

## About This Project

This is my submission for Assignment-1 of the Application and Data Security (ADS) course.

I chose **OWASP Category A01:2021 – Broken Access Control**, specifically focusing on:
- **CWE-22:** Path Traversal
- **CWE-284:** Improper Access Control
- **CWE-639:** Insecure Direct Object Reference (IDOR)

I created a dummy Flask web app to show how an attacker can use `../` directory traversal to leak sensitive server files and database credentials from `.env`. Then, I built a secured version of the app to fix the vulnerability using canonical path checking (`os.path.realpath` / `os.path.commonpath`), indirect object tokens, and input allowlisting.

---

## Project Files

- `vulnerable_app/` - The vulnerable Flask web app (runs on port 5000)
- `secure_app/` - The fixed and hardened Flask web app (runs on port 5001)
- `scripts/test_suite.py` - Automated Python unit test suite (17 tests covering CWE-22, CWE-35, and CWE-639)
- `scripts/exploit_demo.py` - Script showing the exploits in action
- `Assignment_Report.md` - My full assignment report with STRIDE, per-threat DREAD, exploit steps, and code diff
- `Assignment_Report.html` - Formatted printable HTML version of the report
- `CS2341901_Aditya_Ranjan_Kumar_ADS_Assignment_1.docx` - Formatted submission report in Word format
- `CS2341901_Aditya_Ranjan_Kumar_ADS_Assignment_1.pdf` - Compiled PDF version of the report
- `requirements.txt` - Python dependencies (Flask, requests, python-docx)

---

## How to Run

### 1. Install Requirements
```bash
pip install -r requirements.txt
```

### 2. Run the Automated Tests (Fastest check)
Run the 17 unit tests:
```bash
python3 scripts/test_suite.py
```
All 17 tests will run and pass, confirming that the exploits work on the vulnerable routes and are blocked on the secure routes.

### 3. Run the Live Demo

**Terminal 1 (Start Vulnerable App):**
```bash
python3 vulnerable_app/app.py
```
Runs at `http://127.0.0.1:5000`.

**Terminal 2 (Start Secure App):**
```bash
python3 secure_app/app.py
```
Runs at `http://127.0.0.1:5001`.

**Terminal 3 (Run Exploit Demonstration):**
```bash
python3 scripts/exploit_demo.py
```

---

## Manual Testing with curl

### Vulnerable App (Port 5000):
```bash
# Normal file
curl "http://127.0.0.1:5000/download?file=syllabus_cs2341901.txt"

# Steal database credentials
curl "http://127.0.0.1:5000/download?file=../confidential/admin_db_credentials.env"

# Steal root .env
curl "http://127.0.0.1:5000/download?file=../../.env"

# Bypass naive filter using ....//
curl "http://127.0.0.1:5000/download_naive?file=....//confidential/admin_db_credentials.env"
```

### Secure App (Port 5001):
```bash
# Legitimate download using token ID (200 OK)
curl "http://127.0.0.1:5001/download_secure?doc_id=doc_01"

# Traversal attempt (Blocked - 403 Forbidden)
curl "http://127.0.0.1:5001/download_secure?doc_id=../confidential/admin_db_credentials.env"
```
