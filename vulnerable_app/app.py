"""
Application and Data Security - Assignment 1
Student: Aditya Ranjan Kumar
Roll No: CS-2341901
Section: 4CSE9
Submitted to: Dr. Ajay Prasad

Target OWASP: A01:2021 - Broken Access Control
Mapped CWE(s): CWE-22 (Improper Limitation of a Pathname to a Restricted Directory / Path Traversal)
               CWE-284 (Improper Access Control)

Description:
This dummy application simulates an academic document distribution portal.
It demonstrates an arbitrary file read / path traversal vulnerability where user input
is concatenated directly into a filesystem path without canonicalization or validation.
"""

import os
from flask import Flask, request, send_file, render_template, abort

app = Flask(__name__)

# Base directories
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PUBLIC_DOCS_DIR = os.path.join(BASE_DIR, "storage", "public_docs")
CONFIDENTIAL_DIR = os.path.join(BASE_DIR, "storage", "confidential")


@app.route("/")
def index():
    """Display list of authorized public course documents."""
    files = []
    if os.path.exists(PUBLIC_DOCS_DIR):
        files = [f for f in os.listdir(PUBLIC_DOCS_DIR) if not f.startswith(".")]
    return render_template("index.html", files=files)


@app.route("/download")
def download_vulnerable():
    """
    VULNERABLE ENDPOINT: Demonstrates CWE-22 / CWE-284.
    
    Flaw:
    The user-supplied 'file' query parameter is passed straight to os.path.join().
    os.path.join() does NOT resolve or block relative path components like '../'.
    Supplying `../../confidential/admin_db_credentials.env` resolves to a sensitive
    server file outside of PUBLIC_DOCS_DIR.
    """
    filename = request.args.get("file")
    if not filename:
        return "Error: Missing 'file' parameter. Example: /download?file=syllabus_cs2341901.txt", 400

    # INSECURE PATH RESOLUTION:
    file_path = os.path.join(PUBLIC_DOCS_DIR, filename)

    print(f"[VULNERABLE_APP LOG] Requested: {filename} -> Target Path: {file_path}")

    # Check if file exists on disk
    if not os.path.exists(file_path):
        return f"File not found: {filename}", 404

    # Returning file content directly to user without verifying base boundary
    try:
        return send_file(file_path, as_attachment=False)
    except Exception as e:
        return f"Internal Server Error: {str(e)}", 500


@app.route("/download_naive")
def download_naive_filter():
    """
    NAIVE MITIGATION ENDPOINT (Common flawed defense):
    Attempts to remove '../' using a single string replacement:
        filename = filename.replace('../', '')
        
    Why this fails:
    Attacker can supply nested sequences like '....//'.
    When '../' is removed from '....//', it leaves '../' intact!
    Example: '....//confidential/admin_db_credentials.env' -> '../../confidential/admin_db_credentials.env'
    """
    raw_filename = request.args.get("file", "")
    if not raw_filename:
        return "Error: Missing 'file' parameter", 400

    # FLAWED ATTEMPT: Non-recursive single-pass replacement
    filtered_filename = raw_filename.replace("../", "")

    file_path = os.path.join(PUBLIC_DOCS_DIR, filtered_filename)
    print(f"[NAIVE_APP LOG] Raw: {raw_filename} -> Filtered: {filtered_filename} -> Path: {file_path}")

    if not os.path.exists(file_path):
        return f"File not found: {filtered_filename}", 404

    try:
        return send_file(file_path, as_attachment=False)
    except Exception as e:
        return f"Internal Server Error: {str(e)}", 500


@app.route("/api/health")
def health():
    return {"status": "running", "mode": "vulnerable_demo", "port": 5000}


if __name__ == "__main__":
    print("=" * 65)
    print("Starting Vulnerable Dummy Server on http://127.0.0.1:5000")
    print("Student: Aditya Ranjan Kumar | CS-2341901 | 4CSE9")
    print("Instructor: Dr. Ajay Prasad | Application and Data Security")
    print("=" * 65)
    app.run(host="127.0.0.1", port=5000, debug=False)
