#!/usr/bin/env python3
"""
Application and Data Security - Assignment 1
Automated Security Test Suite
Student: Aditya Ranjan Kumar | CS-2341901 | 4CSE9
Instructor: Dr. Ajay Prasad

Validates:
1. Vulnerability reproduction on vulnerable endpoint (asserts 200 on traversal)
2. Flaw in naive blacklist filter (asserts bypass works on vulnerable endpoint)
3. Vulnerable IDOR reproduction (asserts unauthenticated access to Bob's records)
4. Robust defense verification on secure endpoint (asserts 400/403 on malicious payloads)
5. Genuine object-level authorization (asserts 403 on cross-user IDOR access)
6. Structured audit logging verification (asserts events logged in JSON format)
7. Normal operational integrity (asserts authorized files download cleanly)
"""

import os
import sys
import json
import unittest
import warnings

# Add project root to sys.path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from vulnerable_app.app import app as vuln_app
from secure_app.app import app as secure_app, AUDIT_LOG_FILE


class TestVulnerableApplication(unittest.TestCase):
    """Proves the existence of OWASP A01: CWE-22, CWE-35, and CWE-639 in vulnerable_app."""

    def setUp(self):
        warnings.simplefilter("ignore", ResourceWarning)
        self.client = vuln_app.test_client()

    def test_01_legitimate_download(self):
        """Verify normal user can access permitted course syllabus."""
        response = self.client.get("/download?file=syllabus_cs2341901.txt")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Aditya Ranjan Kumar", response.data)

    def test_02_path_traversal_confidential_env(self):
        """Demonstrate CWE-22: Traversal escapes public_docs to read confidential credentials."""
        response = self.client.get("/download?file=../confidential/admin_db_credentials.env")
        self.assertEqual(response.status_code, 200, "Vulnerability assertion: Traversal should succeed on vulnerable app")
        self.assertIn(b"SuperSecretP@ssw0rd2026!", response.data)
        self.assertIn(b"JWT_SECRET_KEY", response.data)

    def test_03_path_traversal_root_env(self):
        """Demonstrate CWE-22: Two-level traversal reads server root .env file."""
        response = self.client.get("/download?file=../../.env")
        self.assertEqual(response.status_code, 200, "Vulnerability assertion: Root .env should be readable")
        self.assertIn(b"MasterP@ss2026", response.data)

    def test_04_naive_filter_bypass(self):
        """Demonstrate why naive blacklist .replace('../', '') fails against nested sequences '....//'."""
        response = self.client.get("/download_naive?file=....//confidential/admin_db_credentials.env")
        self.assertEqual(response.status_code, 200, "Vulnerability assertion: Nested sequence bypasses naive replace")
        self.assertIn(b"DB_NAME=university_records", response.data)

    def test_05_missing_parameter(self):
        """Verify endpoint handles missing file parameter."""
        response = self.client.get("/download")
        self.assertEqual(response.status_code, 400)

    def test_06_idor_unauthorized_record_access(self):
        """Demonstrate CWE-639 (IDOR): Any user can read Bob's confidential records without authentication."""
        response = self.client.get("/api/document/doc_03")
        self.assertEqual(response.status_code, 200, "Vulnerability assertion: IDOR should leak records without auth")
        self.assertIn(b"Bob Smith", response.data)
        self.assertIn(b"3.82", response.data)


class TestSecureHardenedApplication(unittest.TestCase):
    """Proves that all mitigations reliably prevent unauthorized access in secure_app."""

    def setUp(self):
        warnings.simplefilter("ignore", ResourceWarning)
        self.client = secure_app.test_client()

    def test_01_authorized_token_download(self):
        """Verify authorized document download via token ID works for owner (aditya)."""
        response = self.client.get("/download_secure?doc_id=doc_01&user_id=aditya")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Aditya Ranjan Kumar", response.data)

    def test_02_tampered_doc_id_traversal(self):
        """Verify supplying traversal sequence in doc_id is rejected with 403 Forbidden."""
        response = self.client.get("/download_secure?doc_id=../confidential/admin_db_credentials.env")
        self.assertEqual(response.status_code, 403)
        self.assertNotIn(b"SuperSecretP@ssw0rd2026!", response.data)

    def test_03_tampered_doc_id_nonexistent(self):
        """Verify requesting non-existent ID fails with 403 without leaking file system details."""
        response = self.client.get("/download_secure?doc_id=doc_999")
        self.assertEqual(response.status_code, 403)

    def test_04_direct_name_path_traversal_blocked(self):
        """Verify /download_by_name blocks standard directory traversal sequences."""
        response = self.client.get("/download_by_name?file=../confidential/admin_db_credentials.env")
        self.assertEqual(response.status_code, 403)
        self.assertNotIn(b"SuperSecretP@ssw0rd2026!", response.data)

    def test_05_direct_name_nested_traversal_blocked(self):
        """Verify /download_by_name blocks nested traversal sequences ('....//')."""
        response = self.client.get("/download_by_name?file=....//confidential/admin_db_credentials.env")
        self.assertEqual(response.status_code, 403)
        self.assertNotIn(b"SuperSecretP@ssw0rd2026!", response.data)

    def test_06_direct_name_special_characters_blocked(self):
        """Verify filenames with invalid characters like semicolons or pipe symbols are rejected."""
        response = self.client.get("/download_by_name?file=test;cmd.txt")
        self.assertEqual(response.status_code, 400)

    def test_07_direct_name_legitimate_download(self):
        """Verify legitimate file can be fetched by direct name when safe."""
        response = self.client.get("/download_by_name?file=syllabus_cs2341901.txt")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Course: Application and Data Security", response.data)

    def test_08_idor_cross_user_access_blocked(self):
        """Verify Object-Level Authorization: User 'aditya' requesting Bob's doc_03 returns 403 Forbidden."""
        response = self.client.get("/download_secure?doc_id=doc_03&user_id=aditya")
        self.assertEqual(response.status_code, 403)
        self.assertNotIn(b"Bob Smith", response.data)

    def test_09_idor_owner_permitted_access(self):
        """Verify Object-Level Authorization: Bob requesting his own doc_03 returns 200 OK."""
        response = self.client.get("/download_secure?doc_id=doc_03&user_id=bob")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Bob Smith", response.data)

    def test_10_idor_api_endpoint_blocked(self):
        """Verify /api/document/<id> rejects unauthorized requester with 403 Forbidden."""
        response = self.client.get("/api/document/doc_03", headers={"X-User-ID": "aditya"})
        self.assertEqual(response.status_code, 403)
        data = json.loads(response.data)
        self.assertEqual(data.get("status"), "error")

    def test_11_structured_audit_logging_active(self):
        """Verify audit logger writes structured JSON events to audit log file."""
        self.assertTrue(os.path.exists(AUDIT_LOG_FILE), "Audit log file should exist after requests")
        with open(AUDIT_LOG_FILE, "r", encoding="utf-8") as f:
            lines = [l.strip() for l in f if l.strip()]
        self.assertGreater(len(lines), 0, "Audit log should contain recorded events")
        latest = json.loads(lines[-1])
        self.assertIn("timestamp", latest)
        self.assertIn("event", latest)
        self.assertIn("client_ip", latest)


if __name__ == "__main__":
    print("\n" + "=" * 70)
    print("RUNNING AUTOMATED SECURITY TEST SUITE (CS4021 - Assignment-1)")
    print("Student: Aditya Ranjan Kumar | CS-2341901 | 4CSE9")
    print("Instructor: Dr. Ajay Prasad")
    print("=" * 70 + "\n")
    unittest.main(verbosity=2)
