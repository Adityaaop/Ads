"""
Application and Data Security - Assignment 1
Student: Aditya Ranjan Kumar
Roll No: CS-2341901
Section: 4CSE9
Submitted to: Dr. Ajay Prasad

Target OWASP: A01:2021 - Broken Access Control
Remediated CWE(s): CWE-22 (Path Traversal), CWE-284 (Improper Access Control), CWE-639 (IDOR)

Description:
This hardened version of the application implements Defense-in-Depth mitigations:
1. Canonical Path Resolution (os.path.realpath / commonpath checking)
2. Indirect Object Referencing (Map IDs to authorized filenames)
3. Input sanitization (secure_filename stripping traversal sequences)
4. Principle of Least Privilege and safe error responses (HTTP 403 Forbidden without path leaks)
"""

import os
import re
from flask import Flask, request, send_file, render_template, abort
from werkzeug.utils import secure_filename

app = Flask(__name__)

# Base directories
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# Resolving canonical root of storage to prevent symbolic link and relative traversal escapes
PUBLIC_DOCS_DIR = os.path.realpath(os.path.join(BASE_DIR, "storage", "public_docs"))

# Indirect Object Reference (IDOR mitigation):
# Instead of client requesting raw filenames or paths, client requests an ID.
AUTHORIZED_DOCUMENTS = {
    "doc_01": {
        "filename": "syllabus_cs2341901.txt",
        "title": "Course Syllabus - CS4021 ADS"
    },
    "doc_02": {
        "filename": "assignment1_guidelines.txt",
        "title": "Assignment-1 Guidelines and Rubric"
    }
}


def is_safe_path(base_dir: str, requested_path: str) -> bool:
    """
    Core Canonical Path Check:
    Resolves the canonical, absolute path of both the base directory and the target path.
    Verifies that the target path is strictly contained within base_dir.
    """
    base_dir_real = os.path.realpath(base_dir)
    target_path_real = os.path.realpath(requested_path)

    # commonpath ensures target_path_real starts with base_dir_real and handles path separators properly
    try:
        common = os.path.commonpath([base_dir_real, target_path_real])
        return common == base_dir_real and os.path.isfile(target_path_real)
    except ValueError:
        # Happens if paths are on different drives/mounts
        return False


@app.route("/")
def index():
    """Display authorized documents mapped via secure tokens."""
    return render_template("index.html", documents=AUTHORIZED_DOCUMENTS)


@app.route("/download_secure")
def download_secure():
    """
    SECURE ENDPOINT 1 (Indirect Object Reference / Tokenized download):
    Client supplies a 'doc_id'. If ID does not exist, access is denied immediately.
    Client never has control over filesystem path or filename.
    """
    doc_id = request.args.get("doc_id")
    if not doc_id:
        return "Error: Missing 'doc_id' parameter. Example: /download_secure?doc_id=doc_01", 400

    if doc_id not in AUTHORIZED_DOCUMENTS:
        # Access denied without leaking internal server information
        return "Access Denied: Invalid or unauthorized document identifier.", 403

    safe_name = AUTHORIZED_DOCUMENTS[doc_id]["filename"]
    full_path = os.path.join(PUBLIC_DOCS_DIR, safe_name)

    if not is_safe_path(PUBLIC_DOCS_DIR, full_path):
        return "Security Violation: Access outside designated directory is prohibited.", 403

    return send_file(full_path, as_attachment=False)


@app.route("/download_by_name")
def download_by_name():
    """
    SECURE ENDPOINT 2 (Direct Name with Canonical Path & Sanitization Check):
    Allows downloading by name ONLY if:
    1. Input passes regex allowlist [a-zA-Z0-9._-]
    2. secure_filename sanitizes the value (strips slashes and ../)
    3. Resolved realpath is confirmed to be inside PUBLIC_DOCS_DIR
    """
    raw_filename = request.args.get("file")
    if not raw_filename:
        return "Error: Missing 'file' parameter", 400

    # Defense 1: Reject path traversal sequences explicitly
    if "../" in raw_filename or "..\\" in raw_filename or "/" in raw_filename or "\\" in raw_filename:
        print(f"[SECURITY ALERT] Path traversal attempt detected: {raw_filename}")
        return "Access Denied: Directory traversal sequences are forbidden.", 403

    # Defense 2: Whitelist pattern validation
    if not re.match(r"^[a-zA-Z0-9_\-\.]+$", raw_filename):
        return "Access Denied: Filename contains invalid characters.", 400

    # Defense 3: secure_filename sanitization
    clean_name = secure_filename(raw_filename)
    candidate_path = os.path.join(PUBLIC_DOCS_DIR, clean_name)

    # Defense 4: Canonical verification
    if not is_safe_path(PUBLIC_DOCS_DIR, candidate_path):
        print(f"[SECURITY ALERT] Path escape blocked: {candidate_path}")
        return "Access Denied: Path escapes authorized boundary.", 403

    return send_file(candidate_path, as_attachment=False)


@app.route("/api/health")
def health():
    return {"status": "running", "mode": "hardened_secure", "port": 5001}


if __name__ == "__main__":
    print("=" * 65)
    print("Starting Secure Hardened Server on http://127.0.0.1:5001")
    print("Student: Aditya Ranjan Kumar | CS-2341901 | 4CSE9")
    print("Instructor: Dr. Ajay Prasad | Application and Data Security")
    print("=" * 65)
    app.run(host="127.0.0.1", port=5001, debug=False)
