# PSL Monitor

Monitors the [Public Suffix List](https://publicsuffix.org/list/public_suffix_list.dat) for entries whose
domains have **expired**, become **defunct**, or **changed hands**, and tracks **`_psl` TXT compliance**
of private-section entries. Built for PSL maintainers: engineering-facing UI, colour-coded findings,
history and diffs of every scan, weekly email reports.

Single Go binary, SQLite database file, no external services besides public DNS resolvers and RDAP.

## Quick start (Docker)

```sh
git clone --recurse-submodules https://github.com/groundcat/psl-monitor.git
cd psl-monitor
cp .env.example .env        # set ADMIN_USERNAME / ADMIN_PASSWORD and SMTP_*
docker compose up -d --build   # or: make up
open http://localhost:8080
```

Already cloned without `--recurse-submodules`? Run `git submodule update --init` (or `make whois-init`).
This fetches the WHOIS fallback.

The database lives in the `pslmon-data` volume (`/data/pslmon.db`) and survives container
rebuilds. If no admin is configured in `.env`, the first visit shows a setup page.

On a fresh install the scheduler starts the jobs at their next configured UTC time. To populate
data right away, open **Workers** and start, in this order: *DNS check (private)*, *_psl TXT scan*,
*RDAP scan (private)*, *DNS check (ICANN)*.

Admin CLI (inside the container):

```sh
docker compose exec pslmon pslmon user create alice 'long-password-here' alice@example.org
docker compose exec pslmon pslmon user reset-password alice 'new-long-password'
```

## What is monitored

| | Private section | ICANN section |
|---|---|---|
| Target | ICANN suffix + 1 label of every rule (`foo.bar.edu.pl`, `*.baz.bar.edu.pl` → `bar.edu.pl`) | every rule name (`edu.pl`, `*.kawasaki.jp` → `kawasaki.jp`) |
| DNS NS check | daily (default) | weekly (default) |
| RDAP scan | monthly + automatically on any DNS anomaly | quarterly (disabled by default) + on anomaly |
| `_psl` TXT | weekly, per rule | n/a |

Suffix extraction implements the full PSL algorithm (normal, `*.` wildcard, `!` exception rules)
using the ICANN rules only; comments are stripped and each rule ends at the first whitespace.
`// VERSION:` and `// COMMIT:` identify each downloaded list; a **snapshot** with the rule diff is
stored whenever the content changes.

### Detection logic

* **Resolver pool**: queries are spread across public resolvers (Cloudflare, Google, Quad9,
  OpenDNS by default; configurable) with per-resolver rate limits. Resolvers that keep failing are
  benched for a while. Each target has a hard deadline so timeouts never stall a scan.
* **Negative answers** (NXDOMAIN / NODATA / SERVFAIL) only count once a resolver from a
  **second provider** agrees; a single positive answer wins. Timeouts on at least 2 providers count
  as "missing". Local or resolver errors are *inconclusive*: they neither advance nor reset counters.
* **Unchanged NS** means at least one baseline NS is still present. Resolvers returning different
  subsets (`ns1,ns2` vs `ns1,ns2,ns3`) are unioned and treated as unchanged. The baseline follows
  gradual migrations.
* **Grace period** (default 5 **distinct UTC days**):
  * had NS → missing on 5 days → `defunct`
  * NS set fully disjoint from the baseline on 5 days → `changed` (possible change of hands; the baseline
    stays until an admin accepts the new NS)
  * running a check twice on the same day does not advance the counters
* **Parking detection**: NS hosts are matched against the community parking-NS list, their parent
  domains, and keywords (`park`, `expired`, `renew`, …). All three are editable in Settings.
* **RDAP** (IANA bootstrap, refreshed daily, plus the community extra-servers list; TLDs go through `rdap.iana.org`): creation and expiry
  dates are cached on every lookup, and errors never overwrite cached data. A changed creation date
  means the domain was **re-registered**. Each RDAP server gets its own worker pool with adaptive
  throttling (honours `Retry-After`, halves its rate on 429), so a slow registry never holds up the
  others. When RDAP is unavailable, the WHOIS fallback takes over; only TLDs with neither show as `unsupported`.
* **WHOIS / web-WHOIS fallback**: see [below](#whois-fallback).
* **`_psl` TXT**: `_psl.<rule>` (wildcards: the name below `*.`) must contain a PR link. Rules in the
  upstream `missingTXT` exemption list (embedded; can be refreshed from GitHub on the TXT page) are
  grandfathered.

### Severity & confidence

| Severity | Typical cause |
|---|---|
| **critical** | RDAP expired / 404 (dropped) / pending delete / creation date changed; defunct with RDAP confirmation; changed + parked |
| **high** | NS changed for full grace period; defunct without RDAP; parked NS; expiring ≤ 30 d; RDAP hold; new ICANN suffix registration / delegation |
| **medium** | defunct but registration active (lame delegation); expiring ≤ 90 d; newly registered; `_psl` TXT missing |
| **low** | inside grace period; private entry with < 1 year left (PSL expects > 1 year) |
| **info** | resolvers disagreed |

Each finding also carries a confidence (`confirmed` / `high` / `medium` / `low`). See the in-app **Help** page.

## WHOIS fallback

RDAP is always tried first. Many ccTLDs have no RDAP, and some registries' RDAP servers time out
or omit the expiry date. For those cases the app falls back to
[reg233/whois-domain-lookup](https://github.com/reg233/whois-domain-lookup), a PHP project
with maintained WHOIS server lists, **web-based WHOIS scrapers** for registries without port-43
access, and per-ccTLD parsers.

| RDAP answer | What happens |
|---|---|
| found, with expiry | RDAP only |
| found, **no expiry** (e.g. `.at`, `.eu`) | WHOIS fills in expiry/creation; source `rdap+whois` |
| **no server** for the TLD | WHOIS answer is used; source `whois` |
| **error / timeout** | WHOIS answer is used; source `whois` |
| not found (404) | authoritative: WHOIS is not consulted |

On startup the app also loads the upstream's `rdap-servers-extra.json` (RDAP servers missing from
the IANA bootstrap, e.g. `.ch`, `.de`, `.co`, and deeper suffixes such as `br.com`), so more domains
get proper RDAP before WHOIS is needed at all. Manual overrides in Settings take precedence.

The data source of every cached record is shown on the target page and in tables. You can filter on
it in advanced search (*registration source*). Errors from the fallback never overwrite good cached data.

**How it is integrated**

* The upstream repo is a **git submodule** at `third_party/whois-domain-lookup`, pinned to a commit
  and tracking `main`. The PHP code is used as-is, with no fork and no patches.
* `docker compose` builds it into an internal sidecar (`whois`, image `psl-monitor-whois`,
  Dockerfile in `docker/whois/`). It is not published on the host. The Go app calls its JSON API
  (`/src/index.php?domain=…&whois=1&json=1`) through `internal/whoisfb`, with per-TLD concurrency and
  rate limits (WHOIS servers ban aggressive clients) and retries only on transient errors.
* Configure it with `WHOIS_FALLBACK_URL` (set automatically by compose), the optional
  `WHOIS_FALLBACK_PASSWORD` (upstream `SITE_PASSWORD`, sent as a SHA-256 bearer token) and
  `WHOIS_USER_AGENT`. You can disable it or tune it on the Settings page. The Workers page shows its
  status, upstream version and counters.

**Updating the upstream**

```sh
make whois-status          # pinned vs. latest upstream commit + changelog
make whois-update          # move the pin to upstream main (review, then commit)
make whois-update-commit   # same, and commit
docker compose up -d --build whois
```

When deploying, `make deploy` runs `git pull`, syncs the submodule to the **committed** pin, and
rebuilds. Production therefore runs exactly the reviewed upstream version, never an untested `main`.
A weekly GitHub Action (`.github/workflows/whois-upstream.yml`) opens a PR whenever upstream has new
commits, and CI runs a live fallback test against the pinned PHP code.

Without Docker (development): run the submodule with any PHP ≥ 8.1 (curl, mbstring, dom, intl), for example
`php -S 127.0.0.1:18090 -t third_party/whois-domain-lookup`, and set
`WHOIS_FALLBACK_URL=http://127.0.0.1:18090`.

## UI

Dashboard · Flagged · Private · ICANN · Advanced search (TLD, parent suffix, entity, NS
substring, RDAP expiry/creation ranges, flags, DNS state, TXT status, parked, removed) · `_psl`
TXT · Rules · Events · Snapshots · Workers (live progress, resolver and RDAP server health,
manual runs) · Runs (logs, per-run events, **diff between any two runs**) · Schedule · Settings ·
Users · Account. Every list can be exported as txt/csv, and filter URLs can be bookmarked.

Targets can be **acknowledged** (hidden from "unacknowledged" until a *new* flag type appears),
annotated, re-checked on demand, or have their current NS **accepted as the new baseline**. All of
these also work in bulk.

## Configuration

* `.env`: process settings and **all credentials** (SMTP, initial admin). See `.env.example`.
* **Settings page** (stored in the DB): concurrency, QPS, timeouts, grace period, resolvers, RDAP
  overrides, parking lists, retention. Changes apply immediately to new runs.
* **Schedule page**: enable/disable each job, interval (`1d`, `7d`, `12h`, …) and preferred UTC
  time. Missed runs are caught up after a restart.

Weekly reports go to every active admin with an email address who has reports enabled. Each report
attaches `flagged-private`, `flagged-icann`, `expiring-90d`, `psl-txt-missing` and `events` text files.

## Performance (measured)

On a single host with default settings:

| Job | Targets | Duration |
|---|---|---|
| DNS check, private | 2,138 domains | ~25 s |
| DNS check, ICANN | 6,949 suffixes | ~1.5 min |
| `_psl` TXT scan | 3,450 rules | ~1 min |
| RDAP scan, private | 2,138 domains | ~4 min RDAP only; ~7 min with WHOIS fallback (≈640 domains via WHOIS) |
| RDAP scan, ICANN | 6,949 suffixes | ~15 min (`.no`/`.pl` registries throttle) |

Results are written in batches by a single writer goroutine, and readers use a separate WAL connection
pool, so the UI stays responsive during scans. Restarts mark interrupted runs as such; a crash loses at
most one batch (≤ 200 targets or 1 s).

## Development

```sh
go test ./...                 # unit + integration tests (some use /tmp/opencode/psl.dat if present)
go run ./cmd/probe -n 300 -v  # live sample of random targets against real resolvers
DB_PATH=./data/dev.db ADMIN_USERNAME=admin ADMIN_PASSWORD=admin-pass-123 go run ./cmd/pslmon
```

Layout: `internal/psl` (parser), `internal/dnscheck` (resolver pool), `internal/rdap`,
`internal/compliance` (`_psl` TXT / exemptions), `internal/whoisfb` (WHOIS fallback client), `internal/analyze` (state machine and flag
evaluation, pure logic), `internal/checker` (scan orchestration), `internal/scheduler`,
`internal/store` (SQLite), `internal/web` (UI), `internal/report` + `internal/mailer`.
