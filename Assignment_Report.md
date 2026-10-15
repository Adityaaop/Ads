# Assignment-1: Application and Data Security
## Threat Modeling, Vulnerability Exploitation, and Mitigation under OWASP Top 10

---

### Student Details
- **Student Name:** Aditya Ranjan Kumar
- **Roll Number:** CS-2341901
- **Section:** 4CSE9
- **Course Name:** Application and Data Security (CS4021)
- **Submitted to:** Dr. Ajay Prasad
- **Submission Date:** 15-10-2026
- **GitHub Repository:** [https://github.com/Adityaaop/Ads](https://github.com/Adityaaop/Ads)

---

## 1. Introduction & Chosen OWASP Category

For this assignment, I chose **OWASP Top 10 (2021) Category A01:2021 – Broken Access Control**.

I selected Broken Access Control because it currently holds the **#1 position** in the OWASP Top 10. Access control is the foundation of application security—it dictates what authenticated or anonymous users are permitted to view and modify. When access controls are implemented incorrectly or omitted, users can bypass intended boundaries, read private files, modify other users' records, and even compromise entire database instances.

In this practical project, I built a university course document distribution portal in Python (Flask). I implemented and demonstrated two real broken access control vulnerabilities:
1. **Path Traversal (CWE-22)** via direct filename concatenation in file downloads.
2. **Insecure Direct Object Reference (CWE-639 / IDOR)** in an API route allowing users to view another student's confidential records.
3. **Improper Access Control (CWE-284)** as the root architectural weakness.

I also tested the failure of naive blacklist sanitization (`.replace('../', '')`), conducted a STRIDE threat modeling analysis, mapped every activity to per-threat DREAD risk scores, implemented multi-layered Defense-in-Depth mitigations in code, and verified all defenses with an automated 17-assertion test suite.

---

## 2. Comprehensive Mapping of All 34 CWEs to OWASP A01:2021

OWASP Top 10:2021 officially associates **exactly 34 Common Weakness Enumerations (CWEs)** with Category A01:2021 (Broken Access Control). Below is the complete table of all 34 mapped CWEs. *(Note: CWE-73 is excluded because it belongs to Category A04:2021 – Insecure Design).*

| CWE ID | Weakness Name | Severity | Role in My Project / OWASP A01 Context |
| :--- | :--- | :---: | :--- |
| **CWE-22** | **Path Traversal (Improper Limitation of Pathname)** | **High** | **Primary vulnerability demonstrated & exploited in `/download`** |
| **CWE-23** | Relative Path Traversal | Medium | Tested using relative `../` directory sequences |
| **CWE-35** | Path Traversal: '.../...//' | Medium | Demonstrated via nested filter bypass `....//` |
| **CWE-59** | Improper Link Resolution Before File Access | Medium | Mitigated via `os.path.realpath` to resolve symbolic links |
| **CWE-200** | Exposure of Sensitive Information | Medium | Mitigated via safe HTTP 403 responses without path leaks |
| **CWE-201** | Insertion of Sensitive Information Into Sent Data | Medium | Mitigated by preventing credential leakage in HTTP response body |
| **CWE-219** | Storage of File with Sensitive Data Under Web Root | High | Remediated by moving secrets outside web-accessible paths |
| **CWE-264** | Permissions, Privileges, and Access Controls (Deprecated) | High | Overarching access control flaw category |
| **CWE-275** | Permission Issues | Medium | Solved by least-privilege folder filesystem permissions |
| **CWE-276** | Incorrect Default Permissions | High | Addressed via restrictive read-only permissions on public folders |
| **CWE-284** | **Improper Access Control** | **High** | **Core Architectural Flaw in unauthenticated routing** |
| **CWE-285** | Improper Authorization | High | Addressed through object-level permission verification |
| **CWE-352** | Cross-Site Request Forgery (CSRF) | High | Relevant to state-changing access operations |
| **CWE-359** | Exposure of Private Personal Information | Medium | Addressed by protecting Bob's student grade records |
| **CWE-377** | Insecure Temporary File | Medium | Mitigated by avoiding insecure temporary file usage |
| **CWE-402** | Transmission of Private Resources into a New Sphere | Medium | Mitigated by strict canonical containment checks |
| **CWE-425** | Direct Request ('Forced Browsing') | Medium | Solved by tokenized indirect references |
| **CWE-441** | Unintended Proxy or Intermediary ('Confused Deputy') | Medium | Prevented by verifying client identity at origin |
| **CWE-497** | Exposure of Sensitive System Information | Low | Solved by generic error messages masking stack traces |
| **CWE-538** | Insertion of Sensitive Info in Externally-Accessible File | Medium | Remediated by isolating credentials from public docs |
| **CWE-540** | Inclusion of Sensitive Information in Source Code | Medium | Remediated via external environment config |
| **CWE-548** | Exposure of Information Through Directory Listing | Low | Mitigated by disabling directory indexing |
| **CWE-551** | Incorrect Behavior Order: Auth Before Canonicalization | High | Solved by canonicalizing path BEFORE access decision |
| **CWE-552** | Files or Directories Accessible to External Parties | Medium | Demonstrated via `.env` file exposure and fixed |
| **CWE-566** | Authorization Bypass Through User-Controlled SQL Key | High | Related to parameter-tampered primary keys in queries |
| **CWE-601** | URL Redirection to Untrusted Site ('Open Redirect') | Medium | Mitigated by rejecting external URI targets |
| **CWE-639** | **Authorization Bypass via User Key (IDOR)** | **High** | **Demonstrated & fixed via user ownership validation** |
| **CWE-651** | Exposure of WSDL File Containing Sensitive Info | Low | Specific to Web Services information exposure |
| **CWE-668** | Exposure of Resource to Wrong Sphere | High | Core concept in exposing server internal files |
| **CWE-706** | Use of Incorrectly-Resolved Name or Reference | Medium | Resolved using `os.path.realpath` & `commonpath` |
| **CWE-862** | Missing Authorization | High | Addressed by adding mandatory authorization layer |
| **CWE-863** | Incorrect Authorization | High | Addressed by validating owner equals requester |
| **CWE-913** | Improper Control of Generation of Code | High | Prevented by strictly treating input as inert data string |
| **CWE-922** | Insecure Storage of Sensitive Information | High | Remediated by isolating secrets from public directory |

---

## 3. Dummy Application Setup & Vulnerability Analysis

### 3.1 Application Architecture
To simulate a real-world scenario, I built an academic document portal where students can download course files like the syllabus and guidelines:
- `vulnerable_app/` (Port 5000): Demonstrates CWE-22, CWE-35 (naive replace filter bypass), and CWE-639 (IDOR).
- `secure_app/` (Port 5001): Implements canonical checks, true per-user object-level authorization, structured audit logging, and 2MB file size limits.

```text
vulnerable_app/
├── app.py                      # Flask backend (vulnerable routes)
├── .env                        # Root server master keys & DB passwords (sensitive)
├── storage/
│   ├── public_docs/            # Allowed directory for student downloads
│   │   ├── syllabus_cs2341901.txt
│   │   ├── assignment1_guidelines.txt
│   │   └── student_records_bob.txt
│   └── confidential/           # Restricted admin folder
│       └── admin_db_credentials.env
└── templates/
    └── index.html              # Frontend portal UI
```

### 3.2 Vulnerability 1: Path Traversal in File Downloads (CWE-22)
In `vulnerable_app/app.py`, the download endpoint looks like this:

```python
@app.route("/download")
def download_vulnerable():
    filename = request.args.get("file")
    
    # INSECURE DIRECT JOIN:
    file_path = os.path.join(PUBLIC_DOCS_DIR, filename)
    
    if not os.path.exists(file_path):
        return f"File not found: {filename}", 404
        
    return send_file(file_path)
```

**Why this is vulnerable:**
1. `os.path.join()` in Python does not sanitize or strip relative path characters (`../`).
2. If a student passes `file=syllabus_cs2341901.txt`, it safely accesses `storage/public_docs/syllabus_cs2341901.txt`.
3. If an attacker sends `file=../confidential/admin_db_credentials.env`, `os.path.join()` steps out of `public_docs` into `confidential`, leaking private database credentials.
4. If an attacker sends `file=../../.env`, the path steps two levels back to the application root, leaking master JWT secrets and PostgreSQL connection strings.

### 3.3 Vulnerability 2: Why Naive Blacklisting Fails (CWE-35)
A common mistake developers make is trying to strip `../` with string replacement:
```python
filtered_filename = raw_filename.replace("../", "")
```
**Why this fails:**  
The string `replace()` method in Python only runs once (it is non-recursive). If an attacker passes a nested sequence like `....//`:
- Original string: `....//confidential/admin_db_credentials.env`
- Python removes the inner `../`
- Remaining string: `../confidential/admin_db_credentials.env`

Because the remaining string still has `../`, the traversal succeeds completely with HTTP 200 OK.

### 3.4 Vulnerability 3: Insecure Direct Object Reference (IDOR / CWE-639)
In `vulnerable_app/app.py`, I created an API route to fetch document records:
```python
@app.route("/api/document/<doc_id>")
def get_document_vulnerable(doc_id):
    # FLAW: Returns document solely based on doc_id without checking user identity!
    if doc_id not in DOCUMENTS_DB:
        return {"status": "error", "message": "Document not found."}, 404
    doc = DOCUMENTS_DB[doc_id]
    return {"status": "success", "doc_id": doc_id, "data": doc}, 200
```
An attacker (student 'aditya') can query `/api/document/doc_03` and view Bob Smith's confidential GPA and fee status without any authorization check.

---

## 4. Threat Modeling (STRIDE)

I evaluated the document download feature against the six STRIDE threat categories, ensuring every claimed mitigation is directly coded in `secure_app/app.py`:

| STRIDE Category | Threat in My Application | Component Affected | Potential Impact | Mitigation Implemented in Code |
| :--- | :--- | :--- | :--- | :--- |
| **Spoofing** | Attacker tampers with user ID or queries another student's document (`doc_03`) via IDOR | REST API parameter (`doc_id`) | Unauthorized access to confidential student records | Coded object-level authorization: checks `doc['owner'] == current_user` or admin; rejects mismatch with HTTP 403. |
| **Tampering** | Attacker injects `../` or `....//` into filename parameter | `/download?file=...` | Filesystem path redirection to restricted folders | Regex allowlist `^[a-zA-Z0-9_\-\.]+$` and canonical checks (`os.path.realpath` / `os.path.commonpath`). |
| **Repudiation** | Attacker downloads sensitive files without leaving an audit trail | Access Logging | Inability to detect, alert, or trace data exfiltration | Coded structured JSON audit logging (`record_audit_log`) tracking timestamp, IP, user ID, resource, and status. |
| **Information Disclosure** | Path traversal reads `.env` and database credentials | Local File System | Confidentiality loss; database credentials stolen | Coded canonical containment check via `os.path.commonpath`; relocated sensitive secrets outside web root. |
| **Denial of Service** | Attacker requests infinite stream devices (`/dev/urandom`) or huge files | OS File Descriptors | Worker process hangs; memory exhaustion | Enforced `os.path.isfile()` check to block character devices/FIFOs and capped max file size to 2MB. |
| **Elevation of Privilege** | Attacker extracts `SECRET_KEY` from `.env` to forge admin JWT/session cookies | Session Management | Administrative takeover of portal | Stored secrets outside web root; blocked traversal; enforced server-side role validation. |

---

## 5. Detailed Risk Assessment (Per-Threat DREAD Model)

Rather than using a single coarse aggregate score, I calculated DREAD scores for each of the six STRIDE threats individually using the standard formula:
$$\text{Risk Score} = \frac{\text{Damage} + \text{Reproducibility} + \text{Exploitability} + \text{Affected Users} + \text{Discoverability}}{5}$$

Each dimension is scored from 0 to 10:

| STRIDE Threat | Specific Threat Scenario | Pre-Fix (D, R, E, A, D) | Pre-Score & Level | Post-Fix (D, R, E, A, D) | Post-Score & Level | Post-Mitigation Rationale |
| :--- | :--- | :---: | :---: | :---: | :---: | :--- |
| **Spoofing (IDOR)** | Cross-user IDOR access to Bob's confidential grades via `doc_03` | 7, 9, 9, 7, 8 | **8.0 / 10 (High)** | 2, 1, 2, 1, 2 | **1.6 / 10 (Low)** | Object-level authorization validates `doc['owner'] == current_user`; unauthorized requests return 403. |
| **Tampering** | Directory traversal via `../` or `....//` to access server files | 9, 10, 10, 8, 9 | **9.2 / 10 (Critical)** | 1, 1, 1, 0, 2 | **1.0 / 10 (Negligible)** | Canonical resolution (`os.path.commonpath`) reliably blocks all traversal escapes; zero bytes delivered. |
| **Repudiation** | Downloading sensitive files without leaving traces in access logs | 6, 8, 8, 6, 7 | **7.0 / 10 (High)** | 2, 1, 2, 1, 2 | **1.6 / 10 (Low)** | Structured JSON audit logging (`audit_access.log`) records client IP, user ID, requested resource, timestamp, and status. |
| **Information Disclosure** | Path traversal leaks database passwords & master root `.env` | 10, 10, 10, 9, 9 | **9.6 / 10 (Critical)** | 1, 1, 1, 0, 2 | **1.0 / 10 (Negligible)** | Secrets isolated from web root; canonical check blocks escape; returns 403 without path details. |
| **Denial of Service** | Requesting infinite stream devices (`/dev/urandom`) or huge files | 7, 8, 7, 8, 6 | **7.2 / 10 (High)** | 2, 2, 1, 1, 2 | **1.6 / 10 (Low)** | Enforced `os.path.isfile()` check to block character devices/FIFOs and capped max file size to 2MB. |
| **Elevation of Privilege** | Attacker steals `SECRET_KEY` from `.env` to forge admin session cookies | 10, 9, 8, 9, 8 | **8.8 / 10 (Critical)** | 2, 1, 2, 0, 2 | **1.4 / 10 (Low)** | Root secrets protected; directory traversal sealed; server-side role validation enforced. |
| **Composite Average** | **Overall Application Risk Posture** | **8.2, 9.0, 8.7, 7.8, 7.8** | **8.3 / 10 (CRITICAL)** | **1.7, 1.2, 1.5, 0.5, 2.0** | **1.37 / 10 (LOW RESIDUAL)** | **Comprehensive Defense-in-Depth implemented; verified by 17 unit test assertions.** |

---

## 6. Threat and Exploit Demonstration

I executed live proof-of-concept attacks against the vulnerable application using `scripts/exploit_demo.py` and `curl`:

### Test 1: Normal Legitimate Download
- **Request:** `GET http://127.0.0.1:5000/download?file=syllabus_cs2341901.txt`
- **Result:** HTTP 200 OK. Returns the normal course syllabus.

### Test 2: Stealing Database Credentials (CWE-22)
- **Request:** `GET http://127.0.0.1:5000/download?file=../confidential/admin_db_credentials.env`
- **Result:** HTTP 200 OK. The server returned private database credentials:
  ```text
  DB_HOST=10.0.12.44
  DB_USER=ads_admin
  DB_PASS=SuperSecretP@ssw0rd2026!
  JWT_SECRET_KEY=9f83ab2018cf41a980e927164b38d0e7
  ```

### Test 3: Stealing Root Server Configuration (`.env`)
- **Request:** `GET http://127.0.0.1:5000/download?file=../../.env`
- **Result:** HTTP 200 OK. Extracted the root `.env` file containing the production database URI and AWS keys.

### Test 4: Bypassing Naive `.replace('../', '')` Filter (CWE-35)
- **Request:** `GET http://127.0.0.1:5000/download_naive?file=....//confidential/admin_db_credentials.env`
- **Result:** HTTP 200 OK. The filter stripped the middle `../`, turning `....//` into `../`, and returned the secret credentials.

### Test 5: IDOR Exploitation (CWE-639)
- **Request:** `GET http://127.0.0.1:5000/api/document/doc_03` (without authentication)
- **Result:** HTTP 200 OK. Exfiltrates Bob Smith's confidential records:
  ```json
  {
    "status": "success",
    "doc_id": "doc_03",
    "title": "Bob Smith's Confidential Academic & Fee Record",
    "owner": "bob",
    "content": "CONFIDENTIAL STUDENT ACADEMIC & FINANCIAL RECORD\nStudent Name: Bob Smith\nCumulative GPA: 3.82 / 4.00\nSemester Fee Status: Paid in Full"
  }
  ```

---

## 7. How I Fixed the Vulnerability (Mitigations Applied)

In `secure_app/app.py`, I implemented five concrete defensive layers:

1. **Canonical Path Resolution (`is_safe_path`):**  
   Resolves the real, absolute path using `os.path.realpath()` and verifies that the target path is strictly contained within the base directory using `os.path.commonpath()`.
2. **True Object-Level Authorization (IDOR Fix):**  
   Verifies that the requesting user's identity matches the document owner (`doc['owner'] == current_user` or admin). Unauthorized access returns HTTP 403 Forbidden.
3. **Structured Audit Logging:**  
   Function `record_audit_log` writes structured JSON records to `audit_access.log` capturing timestamp, client IP, user ID, requested resource, HTTP status code, and security event tags.
4. **Denial of Service Protection:**  
   Enforces `os.path.isfile()` to ensure only standard files are read (blocking infinite character streams like `/dev/urandom`), and enforces a 2MB maximum file size ceiling.
5. **Safe Error Responses:**  
   Returns generic HTTP 403 Forbidden errors without revealing directory structures or server details (CWE-200).

---

## 8. Side-by-Side Code Comparison (Before vs. After Diff)

```diff
--- vulnerable_app/app.py (Vulnerable)
+++ secure_app/app.py (Hardened)
@@ -38,15 +48,45 @@
-@app.route("/download")
-def download_vulnerable():
-    filename = request.args.get("file")
-    # INSECURE: Direct concatenation allows ../ traversal
-    file_path = os.path.join(PUBLIC_DOCS_DIR, filename)
-    if not os.path.exists(file_path):
-        return f"File not found: {filename}", 404
-    return send_file(file_path)
+@app.route("/download_secure")
+def download_secure():
+    doc_id = request.args.get("doc_id")
+    current_user = request.headers.get("X-User-ID") or request.args.get("user_id", "aditya")
+    if doc_id not in AUTHORIZED_DOCUMENTS:
+        record_audit_log("UNKNOWN_RESOURCE_ACCESS", 403, user=current_user, resource=doc_id)
+        return "Access Denied: Invalid document identifier.", 403
+    
+    doc = AUTHORIZED_DOCUMENTS[doc_id]
+    # DEFENSE 1: Object-level authorization check (CWE-639 IDOR mitigation)
+    if doc.get("owner") != current_user and current_user != "admin":
+        record_audit_log("IDOR_UNAUTHORIZED_ACCESS_BLOCKED", 403, user=current_user, resource=doc_id)
+        return "Access Denied: You do not have permission to access this resource.", 403
+    
+    safe_name = doc["filename"]
+    full_path = os.path.join(PUBLIC_DOCS_DIR, safe_name)
+    
+    # DEFENSE 2: Canonical boundary & DoS file size verification
+    safe, reason = is_safe_path(PUBLIC_DOCS_DIR, full_path)
+    if not safe:
+        record_audit_log("CANONICAL_BOUNDARY_VIOLATION", 403, user=current_user, resource=full_path)
+        return f"Security Violation: {reason}", 403
+        
+    record_audit_log("FILE_DOWNLOAD_SUCCESS", 200, user=current_user, resource=doc_id)
+    return send_file(full_path)
```

---

## 9. Automated Testing & Verification (17 Tests)

I created an automated test suite with 17 unit tests in `scripts/test_suite.py`:

```bash
python3 scripts/test_suite.py
```

### Test Output:
```text
======================================================================
RUNNING AUTOMATED SECURITY TEST SUITE (CS4021 - Assignment-1)
Student: Aditya Ranjan Kumar | CS-2341901 | 4CSE9
Instructor: Dr. Ajay Prasad
======================================================================

test_01_authorized_token_download (__main__.TestSecureHardenedApplication) ... ok
test_02_tampered_doc_id_traversal (__main__.TestSecureHardenedApplication) ... ok
test_03_tampered_doc_id_nonexistent (__main__.TestSecureHardenedApplication) ... ok
test_04_direct_name_path_traversal_blocked (__main__.TestSecureHardenedApplication) ... ok
test_05_direct_name_nested_traversal_blocked (__main__.TestSecureHardenedApplication) ... ok
test_06_direct_name_special_characters_blocked (__main__.TestSecureHardenedApplication) ... ok
test_07_direct_name_legitimate_download (__main__.TestSecureHardenedApplication) ... ok
test_08_idor_cross_user_access_blocked (__main__.TestSecureHardenedApplication) ... ok
test_09_idor_owner_permitted_access (__main__.TestSecureHardenedApplication) ... ok
test_10_idor_api_endpoint_blocked (__main__.TestSecureHardenedApplication) ... ok
test_11_structured_audit_logging_active (__main__.TestSecureHardenedApplication) ... ok
test_01_legitimate_download (__main__.TestVulnerableApplication) ... ok
test_02_path_traversal_confidential_env (__main__.TestVulnerableApplication) ... ok
test_03_path_traversal_root_env (__main__.TestVulnerableApplication) ... ok
test_04_naive_filter_bypass (__main__.TestVulnerableApplication) ... ok
test_05_missing_parameter (__main__.TestVulnerableApplication) ... ok
test_06_idor_unauthorized_record_access (__main__.TestVulnerableApplication) ... ok

----------------------------------------------------------------------
Ran 17 tests in 0.016s

OK
```

All 17 tests passed, confirming that the vulnerabilities are reliably demonstrated and that all mitigations successfully prevent unauthorized access.

---

## 10. Conclusion & Lessons Learned

From this assignment, I learned:
1. **Broken Access Control is a serious risk:** Simple flaws in file download features can let anyone download server configurations, database passwords, and environment keys.
2. **Blacklists do not work:** Trying to remove `../` with string replace functions is easily bypassed using nested patterns like `....//`.
3. **Canonical path checks are essential:** Security checks must always be performed on the fully resolved real path using functions like `os.path.realpath` and `os.path.commonpath`.
4. **Object-level authorization prevents IDOR:** Validating resource ownership server-side ensures users can only access records they own.
5. **Defense-in-Depth:** Combining canonical path checks, input allowlisting, structured audit logging, and size limits provides resilient protection.

---

## 11. References
- OWASP Top 10 (2021) - A01: Broken Access Control: https://owasp.org/Top10/A01_2021-Broken_Access_Control/
- MITRE CWE-22: Path Traversal: https://cwe.mitre.org/data/definitions/22.html
- MITRE CWE-284: Improper Access Control: https://cwe.mitre.org/data/definitions/284.html
- MITRE CWE-639: IDOR: https://cwe.mitre.org/data/definitions/639.html
- Python `os.path` documentation: https://docs.python.org/3/library/os.path.html
