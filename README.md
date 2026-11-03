# TE 451 Labs: lab platform

The web platform for the weekly TE 451 (Fundamentals of Network Security) labs
at KNUST. Students work through auto-graded labs with **their own per-student
numbers, keys and files**. Staff get a dashboard for progress, login history,
marks export, extra time, suspensions and grading of short answers.

Served on the department network only, at `https://netsec.internal`.

## Stack

| Piece | Choice |
|---|---|
| App | Django 5.2 (Python 3.12), server-rendered templates |
| Database | PostgreSQL 16 (SQLite for local development) |
| Web server | nginx: TLS from the course's own name-constrained root CA |
| Passwords | Argon2id; django-axes lockout per username + IP |
| Deploy | Docker Compose on an Ubuntu 24.04 VM (ESXi) |
| Backups | nightly `pg_dump` to `./backups`, kept 21 days |

## Layout

```
apps/accounts/     users (index number = username), login events, suspension, forced password change
apps/labs/         lab engine: models, timing rules, grading, scoring
apps/labs/content/ THE LABS: one Python module per lab (prompts + per-student generators + graders)
apps/staffpanel/   dashboard, students, CSV import, extra time, grading queue, marks export
apps/audit/        append-only log of staff actions
deploy/            nginx, internal CA script, backups, entrypoint
tests/             run: make test
```

## Local development

Needs [uv](https://docs.astral.sh/uv/) and `make`. Everything runs on SQLite with `DEBUG` on.

```bash
make setup   # install deps, migrate, create demo accounts, publish all labs
make run     # http://127.0.0.1:8000
```

Demo logins (password `demo-pass-2026` for all): `lecturer`, `ta`, and students
`2045001`–`2045003`. Log in as a student in one browser and as `ta` in a
private window to see both sides.

| Command | What it does |
|---|---|
| `make run` | Dev server on http://127.0.0.1:8000 |
| `make test` | Full test suite (`make test-fast` stops at the first failure) |
| `make sync` | Reload lab definitions after editing `apps/labs/content/` |
| `make migrations` / `make migrate` | Create / apply migrations after model changes |
| `make check` | System checks + fail if a migration is missing |
| `make reset` | Wipe the local database and reseed demo data |
| `make staff NAME=jagyemang ROLE=lecturer` | Create a real staff account (prompts for password) |
| `make shell` | Django shell |
| `make up` / `make down` / `make logs` | Docker Compose stack (see deployment below) |

Run `make` on its own to list every command. `seed_demo` refuses to run unless
`DJANGO_DEBUG=1`, so demo passwords can't end up on the server.

To try a real class list instead of the demo students, go to **Students →
Import CSV** and upload `deploy/sample_students.csv`.

## Deploying on the server

1. **Create the VM** (Ubuntu Server 24.04): 12–16 vCPU, 40–48 GB RAM, 300–500 GB disk,
   one static IP on the lab VLAN. Install Docker Engine and the Compose plugin.
2. **DNS:** on the lab router, map `netsec.internal` to the VM's IP.
3. **Get the code** onto the VM (`git clone …`), then `cd netsec-labs`.
4. **Create the CA and server certificate** (replace the IP with the VM's):
   ```bash
   deploy/ca/make-ca.sh netsec.internal 10.10.20.5
   ```
   Copy the printed fingerprint. Then **move `deploy/ca/out/ca.key` off the
   server** (to an encrypted USB drive); it's only needed to renew the server
   certificate each year (`make-ca.sh … --server-only`).
5. **Configure:** `cp .env.example .env` and fill in the secret key, database
   password and `ROOT_CA_FINGERPRINT`.
6. **Start:** `docker compose up -d --build`. Migrations and `sync_labs` run automatically.
7. **Create staff accounts:**
   ```bash
   docker compose exec web python manage.py create_staff jagyemang --role lecturer --name "Justice Agyemang" --superuser
   docker compose exec web python manage.py create_staff ta.obed --role ta --name "Obed Somuah"
   ```
8. **Check:** from a laptop on the lab Wi-Fi, open http://netsec.internal/ca.crt,
   then https://netsec.internal.

### Updating

```bash
git pull && docker compose up -d --build
```

### Backups and restore

Dumps land in `./backups/` nightly (and once at every start). Copy them off the
VM regularly; an ESXi snapshot before each update is also cheap insurance.

```bash
docker compose exec -T db pg_restore -U netsec -d netsec --clean < backups/netsec-YYYYMMDD-HHMM.dump
```

## Writing a lab

See the docstring in `apps/labs/content/base.py`. In short: subclass `TaskDef`,
generate parameters **only** from the `rng` you're given, return the prompt via
`format_html`, and implement `check`. Add the lab to `content/__init__.py`, then
`make sync`.

| Need | Use | Example |
|---|---|---|
| Per-student downloadable file | `files(p) -> {name: bytes}` (generated on demand, never stored); override `file_names(p)` too if building is slow | Lab 1 capture, Lab 3 ciphertexts |
| Several tasks about one artefact | same `seed_key` on each task | Lab 1 tasks 1–3 share one pcap |
| Partial credit | `check` returns a float in [0, 1] | Lab 1 classification drills |
| Guessable answer | `max_attempts = 2` on the task | multiple choice, "which one is ECB?" |
| Written answer | subclass `ManualTask` with a `rubric` | every lab's last task |
| Network capture | `content/pcap.py` (`Capture`, `TcpConversation`, DNS) | `l01_concepts.py` |
| Big primes, safe primes | `content/numtheory.py` (`random_prime_bits`, `next_prime`, `safe_prime`) | `l04_public_key.py` |
| Deterministic X.509 cert / chain | `content/x509gen.py` (`make_cert`, `deterministic_rsa_key`) | `l06_pki.py` |
| TLS handshake capture | `content/tls.py` (`build_handshake`, `CIPHER_SUITES`) over `pcap.py` | `l08_transport.py` |

Generated parameters are cached per worker process, so a slow `generate()` (Lab 4's
1024-bit key takes ~0.3 s) runs once per student, not on every page view. Treat
`p` as read-only.

**Every lab needs a solver test** that breaks the puzzle the way a student would,
across many seeds (see `tests/test_labs_1_3.py`). This catches the seed that
generates an unsolvable variant before a student finds it. Tests for captures
check the answers against **tshark** when it's installed (they're skipped
otherwise), so graders agree with what Wireshark shows.

| Lab | Lecture | Tasks |
|---|---|---|
| `l00-orientation` | L0 | ethics pledge, trust the lab CA, Python hashing |
| `l01-security-concepts` | L1 | plaintext FTP password, traffic analysis, replay attack (own pcap); CIA / passive-active / X.800 drills; design principles (TA) |
| `l02-number-theory` | L2 | GCD, inverse, modexp, CRT, Miller–Rabin, φ(n); Carmichael (TA) |
| `l03-symmetric` | L3 | Caesar, substitution, Vigenère, rail fence, two-time pad, spot ECB, CBC bit-flip; why AEAD (TA) |
| `l04-public-key` | L4 | RSA by hand; break RSA with close primes (Fermat), e = 3 (cube root), a shared prime (gcd); DH small group (baby-step giant-step), DH man in the middle; hybrid/ECC (TA) |
| `l05-integrity` | L5 | identify hashes; crack an unsalted hash and salted hashes with external tools (CrackStation/john/hashcat); verify + forge an HMAC; salts & slow hashes (TA) |
| `l06-pki` | L6 | read an X.509 certificate; verify a root→intermediate→leaf chain; spot the cert a browser rejects (expiry/SAN); KDC & revocation (TA) |
| `l07-auth` | L7 | compute a TOTP code; evaluate an RBAC policy under least privilege; spot the world-readable secret file; factors/MFA, Kerberos, access models (TA) |
| `l08-transport` | L8 | cipher suites & forward secrecy; read a TLS handshake in Wireshark (SNI + chosen suite); fingerprint an SSH host key; the handshake & metadata leaks (TA) |
| `l09-wireless` | L9 | derive the WPA2 PMK (PBKDF2 over passphrase + SSID); crack a weak passphrase offline from a wordlist; spot the evil-twin AP in a scan; WEP→WPA3 & wireless threats (TA) |
| `l10-email-ip` | L10 | evaluate SPF to catch a spoofed sender; verify S/MIME signatures to find a tampered and a forged email; classify IPsec transport vs tunnel mode; email trust & IP-layer security (TA) |
| `l11-malware-firewall` | L11 | trace packets through an ordered firewall ruleset (first-match, default-deny); detect a TCP SYN port scan in a capture; triage malware by type; firewalls/IDS & defence in depth (TA) |
| `l12-ethics-law` | L12 | tell authorised security work from an offence; order the steps of responsible disclosure; map incidents to offence categories; ethics/law capstone reflection (TA) |

Lab content is code, so it's versioned and reviewed. Staff control *when* labs
run (mode, window, duration, attempts, weight, feedback) from the dashboard.

## Resetting attempts

Resetting deletes the attempt (answers, marks, TA grades) and the student gets new
numbers when they start again. Each reset goes in the audit log with its reason.

* **One student:** the Reset button on the lab's progress page or the student's page.
* **All students:** the lab's Settings page. You must type the lab's slug and give a reason.

## Time rules

* **Deadline mode:** open until the close time.
* **Timed mode:** the clock starts at **Start**; the session ends at start + duration,
  capped at the lab's close time.
* **Extra time** (per student, per lab or all labs) pushes back both the duration
  and the close time, and applies immediately, even mid-session.
* The server enforces every deadline; the countdown in the browser is display only.
