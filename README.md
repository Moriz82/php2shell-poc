# PHP2Shell local patch lab

`exploit.py` is one entry point for **local Docker regression checks** of the PHP releases for CVE-2026-109618 and CVE-2026-109619. It does not attempt code execution or scan a URL. The output distinguishes an upstream version verdict from ordinary request handling; passing HTTP cases alone does not prove a backported build is fixed.

The default matrix uses the three locally cached images identified in Docker Desktop: `php:8.4.26-apache`, `php:8.4.27-apache`, and `php:8.3-cli`. The two Apache images receive the same nine small HTTP cases in three configuration profiles: image default, 8 MB memory limit, and upload progress disabled. Cases cover URL-encoded input, standard multipart, empty file, nested and duplicate fields, an extra part header, chunked transfer without `Content-Length`, and an upload-progress field. The CLI image gets a runtime version check only.

Run from this directory:

```sh
python3 -m unittest -q
python3 exploit.py --output reports/local-docker.json
python3 exploit.py --image php:8.4.27-apache --require-patched --output reports/patched-image.json
```

Use `--image php:8.4.27-apache` to run one cached image. Images are never pulled automatically. Apache containers are temporary, limited to 512 MB, published only on `127.0.0.1`, and attached to a temporary Docker bridge network. The script removes them and that network after testing. No existing containers or images are modified.

`below-upstream-fix` for an official image tag means the PHP release predates the upstream fix; it does not prove an exploit would succeed in that profile. `at-or-above-upstream-fix` means the official tag and runtime match a release at or above PHP's patch floor. `unknown-build-or-backport` requires vendor package evidence. `all_cases_pass` concerns normal request behavior only. `--require-patched` returns exit code 2 when any image is below the upstream fix or unverified. The PHP project says the first fixed upstream releases are 8.2.35, 8.3.36, 8.4.27, and 8.5.12; configuration changes alone are incomplete mitigations.

Sources: [PHP security notice](https://www.php.net/archive/2026.php#2026-10-21-5), [OOM advisory](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w), [stale-state advisory](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp).
