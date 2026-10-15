"""
Application and Data Security - Assignment 1
Student: Aditya Ranjan Kumar
Roll No: CS-2341901
Section: 4CSE9
Submitted to: Dr. Ajay Prasad

Target OWASP: A01:2021 - Broken Access Control
Mapped CWE(s): CWE-22 (Path Traversal), CWE-284 (Improper Access Control), CWE-639 (IDOR)

Description:
This dummy application simulates an academic document portal for our university course.
It contains two real broken access control vulnerabilities:
1. Path Traversal (CWE-22) in /download where user input is passed directly to os.path.join()
2. Insecure Direct Object Reference (IDOR / CWE-639) in /api/document/<doc_id> where any user
   can fetch any student's records by ID without ownership checks.
"""

import os
from flask import Flask, request, send_file, render_template, abort

app = Flask(__name__)

# Base directories
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PUBLIC_DOCS_DIR = os.path.join(BASE_DIR, "storage", "public_docs")
CONFIDENTIAL_DIR = os.path.join(BASE_DIR, "storage", "confidential")

# Simulated database of student documents (for demonstrating CWE-639 IDOR)
DOCUMENTS_DB = {
    "doc_01": {
        "title": "Aditya's Course Syllabus & Study Plan",
        "owner": "aditya",
        "filename": "syllabus_cs2341901.txt"
    },
    "doc_02": {
        "title": "Assignment-1 Guidelines & Rubric",
        "owner": "aditya",
        "filename": "assignment1_guidelines.txt"
    },
    "doc_03": {
        "title": "Bob Smith's Confidential Academic & Fee Record",
        "owner": "bob",
        "filename": "student_records_bob.txt"
    }
}


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
    VULNERABLE ENDPOINT (CWE-22 / CWE-284):
    Flaw:
    The file query parameter is passed straight to os.path.join().
    os.path.join() does NOT stop '../' path components.
    Passing '../../confidential/admin_db_credentials.env' allows an attacker
    to escape public_docs and steal private server files.
    """
    filename = request.args.get("file")
    if not filename:
        return "Error: Missing 'file' parameter. Example: /download?file=syllabus_cs2341901.txt", 400

    # Insecure concatenation - does not normalize or check root boundary
    file_path = os.path.join(PUBLIC_DOCS_DIR, filename)
    print(f"[VULNERABLE_APP LOG] Requested: {filename} -> Target Path: {file_path}")

    if not os.path.exists(file_path):
        return f"File not found: {filename}", 404

    try:
        return send_file(file_path, as_attachment=False)
    except Exception as e:
        return f"Internal Server Error: {str(e)}", 500


@app.route("/download_naive")
def download_naive_filter():
    """
    NAIVE MITIGATION ENDPOINT (CWE-35):
    Developers often try to fix path traversal with simple string replacement:
        filtered = filename.replace('../', '')
    
    Why this fails:
    Python's .replace() is non-recursive. If an attacker passes nested sequences:
        ....//confidential/admin_db_credentials.env
    The inner '../' gets stripped out, leaving '../' intact behind it.
    """
    raw_filename = request.args.get("file", "")
    if not raw_filename:
        return "Error: Missing 'file' parameter", 400

    filtered_filename = raw_filename.replace("../", "")
    file_path = os.path.join(PUBLIC_DOCS_DIR, filtered_filename)
    print(f"[NAIVE_APP LOG] Raw: {raw_filename} -> Filtered: {filtered_filename} -> Path: {file_path}")

    if not os.path.exists(file_path):
        return f"File not found: {filtered_filename}", 404

    try:
        return send_file(file_path, as_attachment=False)
    except Exception as e:
        return f"Internal Server Error: {str(e)}", 500


@app.route("/api/document/<doc_id>")
def get_document_vulnerable(doc_id):
    """
    VULNERABLE IDOR ENDPOINT (CWE-639):
    Flaw:
    Returns document data based solely on the {doc_id} in the URL.
    There is NO check to see if the requester actually owns the resource.
    Student 'aditya' can request /api/document/doc_03 and view Bob's confidential grades.
    """
    if doc_id not in DOCUMENTS_DB:
        return {"status": "error", "message": f"Document '{doc_id}' not found."}, 404

    doc = DOCUMENTS_DB[doc_id]
    file_path = os.path.join(PUBLIC_DOCS_DIR, doc["filename"])
    content = ""
    if os.path.exists(file_path):
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()

    print(f"[VULNERABLE_IDOR LOG] Accessing: {doc_id} (Owner: {doc['owner']})")
    return {
        "status": "success",
        "doc_id": doc_id,
        "title": doc["title"],
        "owner": doc["owner"],
        "content": content
    }, 200


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
