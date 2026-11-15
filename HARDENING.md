# LimitLatch deployment and resource limits

Run exactly one application process per persistent DATA_DIR. Resource-limited workers require Unix resource limits. demo.py is unchanged.

```sh
DATA_DIR=/var/lib/limitlatch APP_HOST=127.0.0.1 PUBLIC_BASE_URL=https://limitlatch.example python3 app.py
```

## Deployment checklist

Complete these deployment steps before strangers use the app with real data:

1. Bind APP_HOST=127.0.0.1 when the proxy is local. Set APP_TRUSTED_PROXIES to exact proxy addresses otherwise. Firewall the application port.
2. Disable or redact access logs for `/w/` paths at proxies, CDNs, load balancers and WAFs. Tokens grant access to data and keys.
3. Provision at least 30 MiB beyond APP_DATA_CAP_MB, plus space for atomic replacement and exports. Worker files are outside workspace accounting.
4. Run one process per DATA_DIR. Back up admission.key with the workspaces. Restrict filesystem access to the application operator.

## Admission and proxy identity

Per source: ten live workspaces, 10 MiB stored data and ten successful creations per hour. Global defaults: 3,000 workspaces and 200 MiB. Each workspace has a shared 5 MiB allowance and twenty runs. Rejected writes do not install partial results; deleting runs releases storage.

IPv4-mapped IPv6 addresses normalize to IPv4. Other IPv6 addresses are grouped by /64 before hashing. Raw addresses are not persisted or logged. Source counts and byte counters contain only owners of live workspaces and are removed when the last workspace is deleted. Denied admissions do not create bookkeeping keys.

Creation histories expire after one hour and empty deques are removed during admissions and periodic sweeps. At most 3,000 histories, each with at most ten timestamps, are retained. Admission of a new source fails closed when that table is full; live histories are never evicted to make a quota bypass possible. Histories use monotonic time and reset on process restart; live workspace counts survive restart through keyed metadata.

Previously stored IPv6 owner digests cannot be converted to /64 digests because raw addresses were deliberately not stored. Existing workspaces remain usable and count toward global capacity, but their old owner quotas cannot be attributed to the new /64 identity. New admissions use normalized identities.

Source selection:

- Without proxy configuration, use the TCP peer and ignore forwarding headers.
- An explicit APP_TRUSTED_PROXIES peer must supply exactly one valid X-Real-IP header; duplicates, missing values and lists are rejected. The proxy must overwrite this header.
- With HTTPS termination enabled, no explicit trusted proxies, a loopback bind and a loopback peer, the rightmost X-Forwarded-For entry is accepted. Missing or invalid values fall back to the loopback peer. Private-network peers are not implicitly trusted.

Set APP_TRUSTED_PROXIES explicitly in shared deployments. Source quotas do not resist an attacker controlling many networks.

## Receipt deadlines and concurrency

There are at most 24 connections. Every request, including a keep-alive request, gets a fresh absolute five-second request-line/header deadline. A Timer shuts down the socket when it expires, even if bytes arrive continuously. The header timer is cancelled when header parsing finishes.

POST receipt has a separate absolute deadline that scales with declared length, about 37 seconds for 1 MiB. It also uses a socket-shutdown Timer. Completion or failure cancels the timer and resets the socket timeout; upload time never leaks into the next request. Processing runs outside receipt deadlines.

Every POST has a hard 1 MiB encoded-body cap, checked before reading. Content-Encoding and Transfer-Encoding are rejected. Host and Origin are checked. A missing or null Origin is accepted only with Sec-Fetch-Site: same-origin. Pages use Referrer-Policy: same-origin and a nonce-based CSP.

Replay and verification share two processing slots with a three-second queue. Run views, bundle downloads and exports share two read slots with a separate three-second queue. Workers have five-second CPU, six-second wall, 512 MiB address-space and 5 MiB output limits.

## Input and saved-run limits

The parser accepts 1 MiB decoded text and 5,000 rows. Encoded form bodies can exceed their cap even when decoded logs fit. At most fifty sanitized kind/tool pairs are supported. Mixed currencies are rejected before replay.

The form explicitly distinguishes the parser limit from the practical saved-run size: about 2,000 rows, depending on evidence size and processing time. Each allowed row produces two evidence entries. Both worker output and the whole workspace are capped at 5 MiB, so 5,000-row persistence is not promised. A large run can fill the shared workspace allowance. Export and delete runs to make room; no saved runs are silently evicted.

Amounts must already be integer minor currency units. Decimal amounts are rejected without rounding. For example, USD 25.00 must be converted to amount_minor 2500 before upload. Kinds must map to refund, transfer, spend, destructive or read; surrounding whitespace and case are normalized. Numeric identifiers and epoch seconds/milliseconds are accepted. Unknown columns are dropped, and unsafe identifiers receive stable aliases.

## Activity and storage failures

Workspace reads do not rewrite or fsync meta.json. Activity uses an existing zero-byte .activity marker, updated at most once per minute under only the workspace stripe. It never holds the global accounting guard and does not recreate a deleted directory. Expiry uses the later of metadata and marker time. Marker timestamps survive ordinary process restarts; activity is approximate by up to one minute and is not synchronously durable across a machine crash.

Policy and replay writes remain atomic file replacements. Disk errors return a generic 507 page with the required notices, without filesystem paths or raw exception messages. Unexpected POST exceptions return a generic 500 page. Rotation checks accounting before moving a workspace and fails without moving it if accounting is unavailable.

## Forms and refresh

Browser policy saves redirect with 303 to a GET workspace page. Non-browser clients that do not request text/html retain the existing 200 representation response. Successful replays redirect with 303 to the run.

Policy and replay forms use same-origin fetch in browsers. Validation and busy responses replace the visible document while retaining the original GET history entry, avoiding POST resubmission on refresh without persisting rejected input. Replay errors preserve both escaped log text and outage-window text. Neither raw input is stored as a flash message or placed in a URL. With JavaScript disabled, validation failures render directly and refresh may offer to repeat the POST; successful browser policy and replay saves still redirect.

The policy form exposes daily_scope and low_fail_mode. Each risk selector contains one high and one low option with the saved value selected. Destructive actions count as one, so the form omits their per-action field.

## Evidence and replay semantics

No AI model or live connector is used. The replay connector returns the logged actual_minor, falling back to amount_minor. Daily scope defaults to per_agent; all_agents shares one cap. Events are sorted by timestamp, retaining input order for ties. Summaries and reports disclose scope and timestamp ties. Overruns retain policy_reason.

Evidence and anchor time values use the supplied replay clock. exported_at and report generated_at are wall-clock generation times; replay_clock_end and time_basis make the distinction explicit. The timestamp authority is a local HMAC stand-in, not an independent RFC 3161 authority. Evidence stores are in-memory replicas during replay.

Bundle downloads are re-verified before serving. A failed stored-run verification returns 409 and identifies the first bad sequence when available. Run pages verify the bundle signature, policy digest, chain and anchors plus derived_mac for displayed results, totals, summary and report. The bundle download currently performs verification and extraction in separate workers; operators must prevent concurrent external modification of DATA_DIR.

A signed HMAC bundle is not third-party proof. Anyone holding the signing and timestamp keys can forge bundles. derived_mac is not an integrity guarantee against the workspace holder: it uses the same downloadable signing secret. It detects corruption and modifications made without the key. Independent provenance needs asymmetric signing keys held outside the app.

The operational control report contains counts and disclosures, not an insurance rating or premium input.

## Job files

app_limits.run_job is the sole worker implementation; app_jobs.run_job delegates to it. Jobs use .job-* directories under DATA_DIR, clean up on completion and failure, and sweep debris older than ten minutes. A downloaded output file remains open until transmission completes.

`.job-*` directories are outside the APP_DATA_CAP_MB accounting. The previous minimum headroom calculation is (2 exports + 2 reads + 2 jobs) x 5 MiB = 30 MiB. Provision additional space for atomic replacement and export serialization overhead. APP_DATA_CAP_MB is a workspace-data limit, not a filesystem quota.

## Workspace tokens and sample data

A workspace URL is the only access key. Tokens are not recorded by the app; directory names are SHA-256 digests. Tokens may appear in browser history and infrastructure access logs, which operators must redact. Sharing is through downloaded bundles and keys, not read-only links. Rotating a link invalidates the old token; rotating keys also deletes runs signed with the old keys.

Try with sample data creates a labelled, made-up 40-refund log and one transfer during an outage. Workspace metadata, pages, export and signed policy identify sample data. All HTML pages include the operator notice, privacy link, deterministic-replay statement and HMAC warning.

## Known open items

- Saved-run size is about 2,000 rows rather than the 5,000-row parser ceiling.
- Decimal amounts and arbitrary action names require explicit conversion before upload; numeric agent_id values and Epoch timestamps are supported.
- HMAC secrets are downloadable; third-party provenance requires independently managed asymmetric signing.
- URL tokens require infrastructure access-log redaction.
- Workspace activity is coalesced and not fsynced on each read.
- JavaScript-disabled validation responses can be resubmitted on refresh.
- demo.py remains unchanged and still patches html.escape; app.py must never import it.

## Regression coverage

```sh
python3 -m unittest discover -s tests
```

The existing engine, application, hosting and security suites remain applicable. tests/test_review_round6.py adds coverage for admission bounds, IPv6 grouping, receipt deadlines, keep-alive timeout reset, storage errors, rotation accounting, coalesced activity, replay input retention, browser policy redirects, form choices and input-format disclosures. Documentation assertions in test_review_round3.py now describe current behavior rather than pinning superseded findings.
