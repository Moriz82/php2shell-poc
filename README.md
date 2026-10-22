# PHP2Shell edge-case validation lab

Covers **CVE-2026-109618** ("RCE via OOM corruption",
[GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w))
and **CVE-2026-109619** ("RCE via stale global state",
[GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)).

PHP fixed both in **8.2.35, 8.3.36, 8.4.27 and 8.5.12**
([PHP release notice](https://www.php.net/archive/2026.php#2026-10-21-5)).

One entry point, `exploit.py`, enumerates the attack shapes the advisories
describe, measures them against real PHP builds, and reports what each one
actually proves. It replaces an earlier harness that only replayed normal
requests and therefore exercised none of the vulnerability.

## The model

Both advisories describe a **producer** and a **consumer**:

| | what it is | examples |
|---|---|---|
| producer | an operation that publishes request-owned state into a worker global and then dies before the matching reset | OOM during multipart parsing, a parse error, an uncaught exception, an execution timeout |
| consumer | an operation that reaches that global again, in a later request on the same worker, before normal request initialization | session upload progress, a diagnostic raised while applying a per-request INI setting |

The producer and the consumer must land on the **same worker**. The tool
runs them back to back on a single-worker prefork container, which is
what makes the sequence reproducible.

## Requirements

- Docker with the images already cached. Nothing is pulled automatically.
- Python 3.10+ (standard library only).

The default matrix runs against `php:8.4.26-apache` (vulnerable) and
`php:8.4.27-apache` (fixed), which the differential section compares.

## Usage

```sh
python3 -m unittest -q                       # unit tests
python3 exploit.py --mode matrix             # full edge-case matrix, both builds
python3 exploit.py --mode detect             # quick check of one build
python3 exploit.py --mode matrix --rce       # matrix plus the code execution stage
python3 exploit.py --mode matrix --output reports/matrix.json
```

Useful flags:

| flag | meaning |
|---|---|
| `--image php:8.4.26-apache` | target image, repeatable |
| `--profile no-upload-progress` | ini profile, repeatable, see `PROFILES` |
| `--case oom-part-header-flood` | run only these cases, repeatable |
| `--rce` | also run the code execution stage |
| `--keep` | leave the containers running for inspection |
| `--output FILE` | write the JSON report |

Exit codes make the tool usable as a gate: `0` no signal and no build
below the fix, `1` a vulnerability was demonstrated, `2` a target is below
PHP's fixed release but no read was demonstrated.

## The case matrix

`--mode matrix` runs every case against every target.

**OOM strategies (CVE-2026-109618).** The advisory names three ways a
request reaches OOM while staying inside the apparent limits; the matrix
covers all three plus the framing edge cases around them.

| case | shape |
|---|---|
| `oom-large-field` | one field larger than `memory_limit`, inside `post_max_size` |
| `oom-many-large-fields` | 1001 fields of 3000 bytes |
| `oom-content-length-absent` | multipart body with no `Content-Length` |
| `oom-content-length-understated` | `Content-Length` a quarter of the real body |
| `oom-content-length-zero` | `Content-Length: 0` with a real body |
| `oom-part-header-flood` | 150000 headers inside a single part |
| `oom-empty-file-controls` | 60000 zero-length file parts, which do not count towards `max_file_uploads` |
| `oom-nested-field-names` | 20000 fields nested 16 levels deep |
| `oom-many-vars` | 5000 variables, far past `max_input_vars` |

**Producers (CVE-2026-109619).** Each one abandons an operation before
its matching reset.

| case | shape |
|---|---|
| `prod-upload-progress-oom` | OOM inside the upload progress callback |
| `prod-parse-error` | `require` of a missing file |
| `prod-uncaught-error` | uncaught `RuntimeException` |
| `prod-max-execution-time` | infinite loop under `max_execution_time` |
| `prod-fatal-destructor` | exception thrown from `__destruct` |
| `prod-shutdown-warning` | warning raised in a shutdown function |

**Consumers (CVE-2026-109619).** Each one reads the stale state.

| case | shape |
|---|---|
| `cons-session-upload-progress` | upload progress before normal initialization |
| `cons-htaccess-php-value` | a diagnostic raised while applying a per-request INI setting |
| `cons-htaccess-php-value-after-fatal` | the same consumer after a fatal producer |

The tool also enumerates the INI settings the advisory names as possible
early consumers and reports, per build, which ones are deprecated and
which ones are actually raised per request. On `php:8.4.26-apache` and
`php:8.4.27-apache` ten of them are deprecated at startup, including
`auto_detect_line_endings`, `assert.exception`, `session.sid_length`,
`session.sid_bits_per_character` and the `mbstring` encoding settings.
None of them raised a diagnostic when applied per request from
`.htaccess`, so on these builds that consumer path is closed. The tool
reports that instead of assuming the path is open.

## Oracles and verdicts

Nothing is guessed. Every case produces a verdict from measured evidence.

| verdict | evidence |
|---|---|
| `VULNERABLE` | a `Set-Cookie` value decoding to a multi-kilobyte binary blob (an out-of-bounds read of freed request memory), a libphp code pointer in that read, or a worker that died on a signal |
| `EXPOSED` | the build is below PHP's fixed release, but no read was demonstrated |
| `NOT-TRIGGERED` | no vulnerability signal, and the build is at or above the fix |

`--mode matrix` prints a **differential**: the cases whose verdict differs
between the vulnerable and the fixed build. Those are the cases that
actually distinguish the two, and they are the ones worth trusting.

## What the matrix found on the reference builds

Measured on this machine against the official `php:8.4.26-apache` and
`php:8.4.27-apache` images.

| case | 8.4.26 | 8.4.27 |
|---|---|---|
| `oom-large-field` | VULNERABLE, 4096 byte read | OOM reached, no read |
| `oom-content-length-absent` | VULNERABLE, 4096 byte read | no signal |
| `oom-content-length-understated` | VULNERABLE, 4096 byte read | OOM reached, no read |
| `oom-content-length-zero` | VULNERABLE, 4096 byte read | no signal |
| `oom-part-header-flood` | OOM reached, no reclaimable state | OOM reached, no read |
| `oom-empty-file-controls` | no reclaimable state, limit not reached | no signal |
| `oom-nested-field-names` | no reclaimable state, limit not reached | no signal |
| `oom-many-vars` | no reclaimable state, limit not reached | no signal |
| `prod-upload-progress-oom` | VULNERABLE, 4096 byte read | OOM reached, no read |
| `prod-parse-error` and the other fatal producers | OOM reached, no read | no signal |
| `cons-session-upload-progress` | VULNERABLE, 4096 byte read | OOM reached, no read |
| `cons-htaccess-php-value` | VULNERABLE, 4096 byte read | OOM reached, no read |

Two results are worth calling out.

**Only some OOM shapes leave exploitable state.** The plain oversized
field is the one that leaves a session id a consumer can reclaim. The
header flood reaches the memory limit on its own, which confirms the
advisory's claim that the headers cost more memory than they occupy on
the wire, but it leaves nothing reclaimable. The empty file controls, the
deeply nested names and the many variable shapes neither exhaust the limit
at these counts nor leave reclaimable state. A sweep of nine consumer
field widths did not change that. The tool reports this distinction
instead of collapsing it into "memory was exhausted".

**The framing of the request decides whether the OOM strategy is even
reachable.** A body with no `Content-Length` and a body with a
`Content-Length` of zero both still reach the parser and still leave
reclaimable state, so the advisory's framing edge cases are real attack
paths, not curiosities.

## Calibration

The public reference implementation for this bug hardcodes the heap
offsets of one specific build. Change the build, the ini profile or the
field widths and it stops working, which is why it does not generalise
across edge cases.

This tool measures instead. A consumer request full of uniquely marked
fields reclaims the allocation the producer freed; the marker comes back
inside the `Set-Cookie` and names the field index. A forged string length
then turns that into an out-of-bounds read. The calibration is per
producer shape, so every case in the matrix is measured on its own terms.

Two details the calibration depends on, both found the hard way:

- consumer field names must be **integer keys**. A zero padded name like
  `0042` is a string key, and the request array is laid out differently,
  so the freed block is never reclaimed.
- the consumer request must stay **under `max_input_vars`**. Crossing it
  raises the same startup warning the producer relies on, and that warning
  blocks the very cookie the consumer is trying to read.

On the official `php:8.4.26-apache` image the calibration measures index
841, which is the value the published reference hardcodes. It gets there
on its own.

## Code execution stage

`--rce` adds the stage that turns the leaked addresses into command
execution: a fake `zend_array` whose `pDestructor` points at `zif_system`,
written over the stale session reference. The command runs as the web
worker. The stage is opt-in and is calibrated for the official
`php:8.4.26-apache` image; `--carrier-offset` and `--pads` extend it to
other builds.

## Mitigations

The advisory names several configuration mitigations. This is what they
actually do, measured on the **vulnerable** `php:8.4.26-apache` build with
four cases that are exploitable by default. Every profile closes every
case, and each one closes it for a different reason.

| profile | verdict | why |
|---|---|---|
| default | VULNERABLE | the producer publishes the session state and the consumer reads it |
| `session.upload_progress.enabled=Off` | closed | the OOM still happens, but nothing publishes the session state for the consumer to reach |
| `memory_limit=-1` | closed | there is no predictable OOM, so there is no early exit to leave state behind |
| `display_errors=Off` | closed | the startup warning is no longer emitted, so headers are not sent early and the session cookie goes out normally |
| `post_max_size=1M` | closed | the request body is rejected before parsing, so the OOM is never reached |
| `session.use_cookies=0` | closed | the OOM still happens, but the consumer has no cookie to read the stale state through |
| `max_input_nesting_level=2`, `max_input_vars=100` | closed | the parser stops early, so the memory limit is never reached |

Reproduce with:

```sh
python3 exploit.py --mode matrix --image php:8.4.26-apache \
  --profile default --profile no-upload-progress --profile unlimited-memory \
  --profile errors-off --profile small-post --profile no-session-cookies \
  --profile tight-nesting \
  --case oom-large-field --case cons-session-upload-progress \
  --case prod-upload-progress-oom --case cons-htaccess-php-value \
  --output reports/mitigations.json
```

None of this makes a deployment safe. The advisory is explicit that
updating is the only complete mitigation, that the mitigations above are
incomplete, and that a configuration mitigation never covers every
producer and consumer pair. What the table shows is which path each
setting closes, so the remaining path can be reasoned about rather than
assumed.

## Scope and limits

- The tool only ever talks to containers it creates on `127.0.0.1`. There
  is no remote target mode.
- Containers are temporary, memory limited, and removed when the run ends.
  Nothing outside the container is modified.
- A `NOT-TRIGGERED` verdict means no signal was observed, not that the
  build is safe. Absence of evidence is not evidence of absence, and the
  advisory is explicit that a configuration mitigation is never complete.
- The consumer that depends on a per-request INI diagnostic only opens if
  the deployment actually raises one. The enumeration reports which
  settings are deprecated in the build and which are raised per request,
  so a deployment with no such setting is correctly reported as not
  exposing that path.
- Only the mod_php SAPI is driven. The advisory notes that FPM exits the
  child when request startup fails, which removes the startup consumer
  path, and FrankenPHP and LSAPI are not exercised here.

## Layout

```
exploit.py      the harness: lab driver, request builders, calibration, oracles, matrix
test_exploit.py unit tests for the request shapes, pointer arithmetic and verdict rules
reports/        JSON reports: matrix.json is the current run, the other three are
                output from the earlier request-only harness
```

## Sources

- [PHP security notice, 21 October 2026](https://www.php.net/archive/2026.php#2026-10-21-5)
- [GHSA-w8hw-w9fx-j79w — RCE via OOM corruption](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [GHSA-6wmf-4rv5-p3rp — RCE via stale global state](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
