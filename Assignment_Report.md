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

For this assignment, I selected **OWASP Top 10 (2021) Category A01:2021 – Broken Access Control**.

I picked Broken Access Control because it is currently ranked **#1** in the OWASP Top 10 list. Access control basically determines what a user is allowed to see or do. When an application doesn't properly verify these permissions, users can bypass restrictions and view private files, modify other people's data, or access server-level files.

In this assignment, I focused specifically on **Path Traversal (CWE-22)** and **Improper Access Control (CWE-284)** in a file download feature, and also applied **Insecure Direct Object Reference (CWE-639)** prevention.

---

## 2. Mapping of CWEs to OWASP A01:2021

OWASP maps multiple Common Weakness Enumerations (CWEs) under the Broken Access Control category. Below is my mapping of these weaknesses, highlighting the ones I selected and implemented in this assignment:

| CWE ID | Vulnerability Name | Severity | Status in my Project |
| :--- | :--- | :---: | :--- |
| **CWE-22** | **Path Traversal (Improper Limitation of a Pathname)** | **High** | **Primary vulnerability demonstrated & exploited** |
| **CWE-284** | **Improper Access Control** | **High** | **Underlying security flaw in download routing** |
| **CWE-639** | **Authorization Bypass Through User-Controlled Key (IDOR)** | **High** | **Demonstrated & fixed using indirect tokens** |
| **CWE-552** | Files or Directories Accessible to External Parties | Medium | Demonstrated by leaking `.env` secrets |
| **CWE-200** | Exposure of Sensitive Information to Unauthorized Actor | Medium | Observed when database passwords were leaked |
| **CWE-23** | Relative Path Traversal | Medium | Tested using `../` payloads |
| **CWE-73** | External Control of File Name or Path | Medium | Core issue in `/download?file=` parameter |
| **CWE-706** | Use of Incorrectly-Resolved Name or Reference | Medium | Resolved using `os.path.realpath` |
| **CWE-862** | Missing Authorization | High | Addressed in secure architecture |
| **CWE-276** | Incorrect Default Permissions | High | Addressed via least-privilege folder access |

*(Note: OWASP A01:2021 also includes related access control weaknesses such as CWE-285, CWE-352, CWE-425, CWE-566, CWE-863, and CWE-918).*

---

## 3. Dummy Application Setup & Vulnerability Analysis

### 3.1 Application Scenario
To demonstrate this vulnerability realistically, I built a simple student portal using Python and Flask. The application allows students to download course material like syllabi and assignment instructions.

The files are structured as follows:
```text
vulnerable_app/
├── app.py                      # Flask backend
├── .env                        # Server master keys & DB passwords (sensitive)
├── storage/
│   ├── public_docs/            # Allowed directory for student downloads
│   │   ├── syllabus_cs2341901.txt
│   │   └── assignment1_guidelines.txt
│   └── confidential/           # Faculty/admin folder (should never be accessible)
│       └── admin_db_credentials.env
└── templates/
    └── index.html              # Web page UI
```

### 3.2 Where the Vulnerability is in the Code
In `vulnerable_app/app.py`, the download endpoint looks like this:

```python
@app.route("/download")
def download_vulnerable():
    filename = request.args.get("file")
    
    # Insecure direct join:
    file_path = os.path.join(PUBLIC_DOCS_DIR, filename)
    
    if not os.path.exists(file_path):
        return f"File not found: {filename}", 404
        
    return send_file(file_path)
```

### 3.3 Why this is vulnerable:
1. `os.path.join()` in Python does not sanitize or remove `../` segments.
2. If a student passes `file=syllabus_cs2341901.txt`, it safely accesses `storage/public_docs/syllabus_cs2341901.txt`.
3. But if an attacker sends `file=../confidential/admin_db_credentials.env`, `os.path.join()` resolves it by stepping one folder back out of `public_docs` into `confidential`.
4. If an attacker sends `file=../../.env`, the path steps two levels back, landing in the application root directory and leaking the server's `.env` file containing secret keys and database passwords.

### 3.4 Why Naive Blacklisting (`.replace('../', '')`) Fails
I also wanted to test a common mistake developers make when trying to fix this: using simple string replacement to strip out `../`.

In `vulnerable_app/app.py`, I created a test route `/download_naive` that does:
```python
filtered_filename = raw_filename.replace("../", "")
```
**Why this fails:**  
The string `replace()` method in Python only runs once (it is not recursive). If an attacker passes a nested sequence like `....//`:
- Original string: `....//confidential/admin_db_credentials.env`
- Python removes the inner `../`
- Remaining string: `../confidential/admin_db_credentials.env`

Because the remaining string still contains `../`, the path traversal still works completely.

---

## 4. Threat Modeling (STRIDE)

I evaluated the download feature against the six STRIDE threat categories to see how an attacker could abuse the endpoint and what controls were needed:

| STRIDE Category | Threat in my Application | Component Affected | Potential Impact | How I Mitigated It |
| :--- | :--- | :--- | :--- | :--- |
| **Spoofing** | Attacker tampers with user identifier or requested file ID to pretend to be another student. | Query parameter (`doc_id`) | Unauthorized download of another student's submission. | Used server-side dictionary lookup (`AUTHORIZED_DOCUMENTS`) where user input cannot reference arbitrary IDs. |
| **Tampering** | Attacker inserts `../` or `....//` into the filename parameter. | URL parameter (`/download?file=...`) | Modifies the path pointer on the server file system. | Enforced strict regex character checks and canonical path resolution (`os.path.realpath`). |
| **Repudiation** | Attacker reads sensitive files without leaving traces in logs. | Server access logging | Administrator cannot tell who accessed confidential files. | Added request logging capturing client IP, timestamp, requested ID, and HTTP status code. |
| **Information Disclosure** | Path traversal allows reading `.env` and `admin_db_credentials.env`. | Server file system | Complete leak of database credentials and session secret keys. | Restricted file reads strictly inside `storage/public_docs` using `os.path.commonpath`. |
| **Denial of Service** | Attacker requests special OS device paths (like `/dev/urandom` or non-regular files). | OS file handling / Flask thread | Server worker thread hangs or runs out of memory. | Added `os.path.isfile()` check to ensure only standard regular files can be read. |
| **Elevation of Privilege** | Attacker reads `SECRET_KEY` from `.env`, signs their own admin cookie, and gets admin rights. | Application session handling | Full takeover of the application. | Kept sensitive files outside web-accessible paths and completely blocked directory escapes. |

---

## 5. Risk Assessment (DREAD Model)

To measure the risk before and after fixing the vulnerability, I calculated the DREAD score using the standard formula:

$$\text{Risk Score} = \frac{\text{Damage} + \text{Reproducibility} + \text{Exploitability} + \text{Affected Users} + \text{Discoverability}}{5}$$

Each category is rated on a scale of 1 to 10.

### 5.1 Pre-Mitigation (Vulnerable App)

| Category | Score | My Justification |
| :--- | :---: | :--- |
| **Damage Potential (D)** | **9 / 10** | Very high. Leaking `.env` exposes database passwords and cryptographic keys, which could lead to full database compromise. |
| **Reproducibility (R)** | **10 / 10** | 100% reproducible. Sending the same HTTP GET request with `../` returns the file every single time. |
| **Exploitability (E)** | **10 / 10** | Very easy. Can be done directly from any web browser URL bar or with a simple `curl` command without special hacker tools. |
| **Affected Users (A)** | **8 / 10** | If database credentials are leaked, all registered users and students in the system are impacted. |
| **Discoverability (D)** | **9 / 10** | Extremely easy to find. Automated scanners like OWASP ZAP or Burp Suite flag file download parameters immediately. |
| **Total Average** | **9.2 / 10** | **CRITICAL RISK** |

### 5.2 Post-Mitigation (Secure App)

| Category | Score | My Justification |
| :--- | :---: | :--- |
| **Damage Potential (D)** | **1 / 10** | Minimal. Traversal attempts return HTTP 403 Forbidden without leaking any file contents. |
| **Reproducibility (R)** | **1 / 10** | The vulnerability cannot be reproduced anymore because canonical path checks stop path escapes every time. |
| **Exploitability (E)** | **1 / 10** | Very difficult. Input is constrained to server-defined keys (`doc_id`), and paths are verified using `os.path.commonpath`. |
| **Affected Users (A)** | **0 / 10** | No users are affected because the vulnerability is closed. |
| **Discoverability (D)** | **2 / 10** | Scanners only get generic 403 / 400 responses with no file system or stack trace details disclosed. |
| **Total Average** | **1.0 / 10** | **LOW / NEGLIGIBLE RISK** |

---

## 6. Threat and Exploit Demonstration

To test the vulnerability, I wrote an exploit script ([scripts/exploit_demo.py](file:///Users/aditya/Ads/scripts/exploit_demo.py)) and also tested the routes manually using `curl`.

### Test 1: Normal Legitimate Download
- **Request:** `GET http://127.0.0.1:5000/download?file=syllabus_cs2341901.txt`
- **Result:** HTTP 200 OK. Returns the normal course syllabus.

### Test 2: Stealing Confidential Database Credentials
- **Request:** `GET http://127.0.0.1:5000/download?file=../confidential/admin_db_credentials.env`
- **Result:** HTTP 200 OK. The server returned the private credentials:
  ```text
  DB_HOST=10.0.12.44
  DB_USER=ads_admin
  DB_PASS=SuperSecretP@ssw0rd2026!
  JWT_SECRET_KEY=9f83ab2018cf41a980e927164b38d0e7
  ```

### Test 3: Stealing Root Server Configuration (`.env`)
- **Request:** `GET http://127.0.0.1:5000/download?file=../../.env`
- **Result:** HTTP 200 OK. Extracted the root `.env` file containing the production database URI and AWS keys.

### Test 4: Bypassing Naive `.replace('../', '')` Filter
- **Request:** `GET http://127.0.0.1:5000/download_naive?file=....//confidential/admin_db_credentials.env`
- **Result:** HTTP 200 OK. The filter stripped the middle `../`, turning `....//` into `../`, and returned the secret credentials.

---

## 7. How I Fixed the Vulnerability (Mitigation)

I implemented four layers of defense in [secure_app/app.py](file:///Users/aditya/Ads/secure_app/app.py):

### 1. Canonical Path Verification (`is_safe_path`)
Instead of trusting the user's string, I resolve the real, absolute path using `os.path.realpath()` and verify that the target path is strictly inside the allowed folder using `os.path.commonpath()`:

```python
def is_safe_path(base_dir: str, requested_path: str) -> bool:
    base_dir_real = os.path.realpath(base_dir)
    target_path_real = os.path.realpath(requested_path)
    try:
        common = os.path.commonpath([base_dir_real, target_path_real])
        return common == base_dir_real and os.path.isfile(target_path_real)
    except ValueError:
        return False
```
If an attacker tries to use `../`, `os.path.commonpath` detects that the resulting path is outside `base_dir_real`, and the request is immediately rejected with HTTP 403 Forbidden.

### 2. Indirect Object References (IDOR Prevention / CWE-639)
Instead of letting users pass direct filenames in the query string, I mapped allowed files to safe document IDs:
```python
AUTHORIZED_DOCUMENTS = {
    "doc_01": {"filename": "syllabus_cs2341901.txt", "title": "Course Syllabus"},
    "doc_02": {"filename": "assignment1_guidelines.txt", "title": "Assignment Guidelines"}
}
```
The user now requests `/download_secure?doc_id=doc_01`. Since the lookup happens against predefined keys on the server, the user has no direct control over the filesystem path.

### 3. Regex Allowlisting
For routes that accept filenames, I enforced an allowlist checking that only alphanumeric characters, underscores, hyphens, and single dots are permitted, blocking path separators (`/` or `\`).

### 4. Safe Error Responses
Instead of showing detailed error traces or path locations, the application returns generic messages like `403 Forbidden: Access Denied` to prevent information leakage (CWE-200).

---

## 8. Code Comparison (Before vs. After Diff)

```diff
--- vulnerable_app/app.py (Before Fix)
+++ secure_app/app.py (After Fix)
@@ -18,14 +18,34 @@
-@app.route("/download")
-def download_vulnerable():
-    filename = request.args.get("file")
-    # FLAW: Direct string joining allows ../ traversal
-    file_path = os.path.join(PUBLIC_DOCS_DIR, filename)
-    if not os.path.exists(file_path):
-        return f"File not found: {filename}", 404
-    return send_file(file_path)
+@app.route("/download_secure")
+def download_secure():
+    doc_id = request.args.get("doc_id")
+    # FIX 1: Indirect Object Reference mapping
+    if doc_id not in AUTHORIZED_DOCUMENTS:
+        return "Access Denied: Invalid document identifier.", 403
+    
+    safe_name = AUTHORIZED_DOCUMENTS[doc_id]["filename"]
+    full_path = os.path.join(PUBLIC_DOCS_DIR, safe_name)
+    
+    # FIX 2: Canonical boundary check
+    if not is_safe_path(PUBLIC_DOCS_DIR, full_path):
+        return "Access Denied: Path escapes boundary.", 403
+        
+    return send_file(full_path)
```

---

## 9. Automated Testing & Verification

To verify that my exploit worked on the vulnerable app and that my fixes properly stopped the attack on the secure app, I created an automated test suite with 12 unit tests in [scripts/test_suite.py](file:///Users/aditya/Ads/scripts/test_suite.py).

### Running the Test Suite:
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
test_01_legitimate_download (__main__.TestVulnerableApplication) ... ok
test_02_path_traversal_confidential_env (__main__.TestVulnerableApplication) ... ok
test_03_path_traversal_root_env (__main__.TestVulnerableApplication) ... ok
test_04_naive_filter_bypass (__main__.TestVulnerableApplication) ... ok
test_05_missing_parameter (__main__.TestVulnerableApplication) ... ok

----------------------------------------------------------------------
Ran 12 tests in 0.014s

OK
```

All 12 tests passed, confirming that the vulnerability is reliably demonstrated and that the mitigations successfully prevent directory traversal.

---

## 10. Conclusion

From this assignment, I learned:
1. **Broken Access Control is a serious risk:** Simple flaws in file download features can let anyone download server configurations, database passwords, and environment keys.
2. **Blacklists do not work:** Trying to remove `../` with string replace functions is easily bypassed using nested patterns like `....//`.
3. **Canonical path checks are essential:** Security checks must always be performed on the fully resolved real path using functions like `os.path.realpath` and `os.path.commonpath`.
4. **Indirect references make code much safer:** Using ID tokens (`doc_id=doc_01`) prevents users from directly interacting with filesystem paths.

---

## 11. References
- OWASP Top 10 (2021) - A01: Broken Access Control: https://owasp.org/Top10/A01_2021-Broken_Access_Control/
- MITRE CWE-22: Path Traversal: https://cwe.mitre.org/data/definitions/22.html
- MITRE CWE-284: Improper Access Control: https://cwe.mitre.org/data/definitions/284.html
- Python `os.path` documentation: https://docs.python.org/3/library/os.path.html
