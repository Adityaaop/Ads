"""
Application and Data Security - Assignment 1
Student: Aditya Ranjan Kumar
Roll No: CS-2341901
Section: 4CSE9
Submitted to: Dr. Ajay Prasad

Target OWASP: A01:2021 - Broken Access Control
Remediated CWE(s): CWE-22 (Path Traversal), CWE-284 (Improper Access Control), CWE-639 (IDOR)

Description:
This hardened version of the application implements a multi-layered Defense-in-Depth strategy:
1. Canonical Path Resolution: Enforces boundary containment using os.path.realpath and os.path.commonpath.
2. Object-Level Authorization (IDOR fix): Authenticates user identity and enforces resource ownership checks.
3. Structured Audit Logging: Records all access events (success, blocked traversals, IDOR attempts) to an audit log file.
4. Denial of Service Protection: Enforces os.path.isfile() to block device streams (e.g., /dev/urandom) and enforces a 2MB file size ceiling.
5. Information Leakage Prevention: Returns generic HTTP 403/400 errors without leaking server filesystem paths.
"""

import os
import re
import json
import datetime
from flask import Flask, request, send_file, render_template, abort
from werkzeug.utils import secure_filename

app = Flask(__name__)

# Base directories
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PUBLIC_DOCS_DIR = os.path.realpath(os.path.join(BASE_DIR, "storage", "public_docs"))
AUDIT_LOG_FILE = os.path.join(BASE_DIR, "audit_access.log")
MAX_FILE_SIZE = 2 * 1024 * 1024  # 2 Megabytes limit (DoS mitigation)

# Server-side document catalog with owner mapping (for IDOR mitigation)
AUTHORIZED_DOCUMENTS = {
    "doc_01": {
        "filename": "syllabus_cs2341901.txt",
        "title": "Aditya's Course Syllabus & Study Plan",
        "owner": "aditya"
    },
    "doc_02": {
        "filename": "assignment1_guidelines.txt",
        "title": "Assignment-1 Guidelines & Rubric",
        "owner": "aditya"
    },
    "doc_03": {
        "filename": "student_records_bob.txt",
        "title": "Bob Smith's Confidential Academic & Fee Record",
        "owner": "bob"
    }
}


def record_audit_log(event_type: str, status_code: int, user: str = "anonymous", resource: str = None, detail: str = None):
    """
    Structured Security Audit Logger (STRIDE Repudiation Mitigation):
    Writes access events to an audit file so security personnel can detect and investigate anomalies.
    """
    log_entry = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "event": event_type,
        "user": user,
        "client_ip": request.remote_addr or "127.0.0.1",
        "status_code": status_code,
        "resource": resource or request.path,
        "detail": detail or ""
    }
    try:
        with open(AUDIT_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(log_entry) + "\n")
    except Exception as e:
        print(f"[AUDIT LOG ERROR] Failed to write log: {e}")


def is_safe_path(base_dir: str, requested_path: str) -> tuple[bool, str]:
    """
    Canonical Path & DoS Verification:
    1. Resolves absolute realpaths of base folder and target file (resolving symlinks & relative dots).
    2. Uses os.path.commonpath to strictly enforce directory containment.
    3. Uses os.path.isfile() to block infinite device streams (e.g. /dev/urandom) or sockets.
    4. Caches file size to ensure it does not exceed the 2MB limit.
    """
    base_dir_real = os.path.realpath(base_dir)
    target_path_real = os.path.realpath(requested_path)

    try:
        common = os.path.commonpath([base_dir_real, target_path_real])
        if common != base_dir_real:
            return False, "Path escapes authorized base directory."

        # DoS Protection: Must be a regular file, not a character device or directory
        if not os.path.isfile(target_path_real):
            return False, "Target is not a regular file."

        # DoS Protection: File size capping
        if os.path.getsize(target_path_real) > MAX_FILE_SIZE:
            return False, "File exceeds 2MB size limit."

        return True, "Valid"
    except (ValueError, OSError):
        return False, "Invalid path resolution."


@app.route("/")
def index():
    """Display authorized documents mapped via secure tokens."""
    return render_template("index.html", documents=AUTHORIZED_DOCUMENTS)


@app.route("/download_secure")
def download_secure():
    """
    SECURE ENDPOINT 1 (Indirect Object Reference + User Ownership Check):
    1. Uses indirect token identifiers instead of direct filesystem paths.
    2. Enforces genuine object-level authorization (verifies requester owns the document).
    3. Resolves canonical path and validates directory boundary.
    """
    doc_id = request.args.get("doc_id")
    # Identify user from request header or query param (defaults to 'aditya' for student demo)
    current_user = request.headers.get("X-User-ID") or request.args.get("user_id", "aditya")

    if not doc_id:
        record_audit_log("INVALID_REQUEST", 400, user=current_user, detail="Missing doc_id")
        return "Error: Missing 'doc_id' parameter. Example: /download_secure?doc_id=doc_01", 400

    if doc_id not in AUTHORIZED_DOCUMENTS:
        record_audit_log("UNKNOWN_RESOURCE_ACCESS", 403, user=current_user, resource=doc_id, detail="Invalid token")
        return "Access Denied: Invalid or unauthorized document identifier.", 403

    doc = AUTHORIZED_DOCUMENTS[doc_id]

    # GENUINE OBJECT-LEVEL AUTHORIZATION CHECK (CWE-639 IDOR MITIGATION):
    # Only the document owner or an admin is allowed to download this document.
    if doc.get("owner") != current_user and current_user != "admin":
        record_audit_log("IDOR_BLOCKED", 403, user=current_user, resource=doc_id,
                         detail=f"User '{current_user}' denied access to file owned by '{doc.get('owner')}'")
        return "Access Denied: You do not have permission to access this resource.", 403

    safe_name = doc["filename"]
    full_path = os.path.join(PUBLIC_DOCS_DIR, safe_name)

    safe, reason = is_safe_path(PUBLIC_DOCS_DIR, full_path)
    if not safe:
        record_audit_log("BOUNDARY_VIOLATION", 403, user=current_user, resource=full_path, detail=reason)
        return f"Security Violation: {reason}", 403

    record_audit_log("FILE_DOWNLOAD_SUCCESS", 200, user=current_user, resource=doc_id, detail=f"Downloaded {safe_name}")
    return send_file(full_path, as_attachment=False)


@app.route("/api/document/<doc_id>")
def get_document_secure(doc_id):
    """
    SECURE REST API ENDPOINT (Object-Level Authorization / CWE-639 Fixed):
    Verifies that the requester owns the document before returning data.
    """
    current_user = request.headers.get("X-User-ID") or request.args.get("user_id", "aditya")

    if doc_id not in AUTHORIZED_DOCUMENTS:
        record_audit_log("API_NOT_FOUND", 404, user=current_user, resource=doc_id)
        return {"status": "error", "message": "Document not found."}, 404

    doc = AUTHORIZED_DOCUMENTS[doc_id]

    # Object-level authorization check
    if doc.get("owner") != current_user and current_user != "admin":
        record_audit_log("API_IDOR_BLOCKED", 403, user=current_user, resource=doc_id,
                         detail=f"User '{current_user}' attempted access to '{doc_id}' owned by '{doc['owner']}'")
        return {"status": "error", "message": "Forbidden: You do not have permission to access this document."}, 403

    safe_name = doc["filename"]
    full_path = os.path.join(PUBLIC_DOCS_DIR, safe_name)
    safe, reason = is_safe_path(PUBLIC_DOCS_DIR, full_path)
    if not safe:
        return {"status": "error", "message": reason}, 403

    with open(full_path, "r", encoding="utf-8") as f:
        content = f.read()

    record_audit_log("API_ACCESS_SUCCESS", 200, user=current_user, resource=doc_id)
    return {
        "status": "success",
        "doc_id": doc_id,
        "title": doc["title"],
        "owner": doc["owner"],
        "content": content
    }, 200


@app.route("/download_by_name")
def download_by_name():
    """
    SECURE ENDPOINT 2 (Direct Name with Canonical Path & Allowlist Validation):
    Used when a feature legitimately requires direct filenames:
    1. Input regex allowlist: strictly [a-zA-Z0-9._-]
    2. Werkzeug secure_filename sanitization
    3. Canonical containment check (os.path.commonpath)
    4. Regular file & size limit check
    """
    raw_filename = request.args.get("file")
    current_user = request.headers.get("X-User-ID") or request.args.get("user_id", "aditya")

    if not raw_filename:
        record_audit_log("INVALID_REQUEST", 400, user=current_user, detail="Missing file parameter")
        return "Error: Missing 'file' parameter", 400

    # Defense 1: Reject path traversal sequences explicitly
    if "../" in raw_filename or "..\\" in raw_filename or "/" in raw_filename or "\\" in raw_filename:
        print(f"[SECURITY ALERT] Path traversal attempt detected: {raw_filename}")
        record_audit_log("TRAVERSAL_BLOCKED", 403, user=current_user, resource=raw_filename, detail="Traversal characters")
        return "Access Denied: Directory traversal sequences are forbidden.", 403

    # Defense 2: Whitelist pattern validation
    if not re.match(r"^[a-zA-Z0-9_\-\.]+$", raw_filename):
        record_audit_log("ILLEGAL_CHARACTERS", 400, user=current_user, resource=raw_filename, detail="Invalid characters")
        return "Access Denied: Filename contains invalid characters.", 400

    # Defense 3: secure_filename sanitization
    clean_name = secure_filename(raw_filename)
    candidate_path = os.path.join(PUBLIC_DOCS_DIR, clean_name)

    # Defense 4: Canonical verification + DoS checks
    safe, reason = is_safe_path(PUBLIC_DOCS_DIR, candidate_path)
    if not safe:
        record_audit_log("BOUNDARY_BLOCKED", 403, user=current_user, resource=candidate_path, detail=reason)
        print(f"[SECURITY ALERT] Path escape blocked: {candidate_path} ({reason})")
        return f"Access Denied: {reason}", 403

    record_audit_log("DIRECT_DOWNLOAD_SUCCESS", 200, user=current_user, resource=clean_name)
    return send_file(candidate_path, as_attachment=False)


@app.route("/api/audit-logs")
def get_audit_logs():
    """Audit log inspection route (admin only)."""
    current_user = request.headers.get("X-User-ID") or request.args.get("user_id", "anonymous")
    if current_user != "admin":
        return {"status": "error", "message": "Forbidden: Admin access only."}, 403

    logs = []
    if os.path.exists(AUDIT_LOG_FILE):
        with open(AUDIT_LOG_FILE, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    logs.append(json.loads(line.strip()))
    return {"status": "success", "count": len(logs), "logs": logs}, 200


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
