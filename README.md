# KMAX — Kali Multi-tool eXplorer

> **A modular, dependency-light security toolkit for Kali Linux (and any Python 3.8+ host).**
> صرف Python standard library + اختیاری `nmap` / `dig` / `openssl`. کوئی بھاری dependency نہیں.

[![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)](#)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Kali%20Linux-557C94.svg)](#)

---

## فہرست / Table of contents

- [تعارف (اردو)](#تعارف--introduction-اردو)
- [Quick start](#quick-start)
- [Installation](#installation--انسٹالیشن)
- [Commands — English](#commands--english)
- [Commands — اردو](#commands--اردو)
- [Reports](#reports--رپورٹس)
- [Exit codes](#exit-codes)
- [Project layout](#project-layout)
- [Testing](#testing)
- [Legal notice](#legal-notice--قانونی-نوٹس)

---

## تعارف / Introduction (اردو)

**KMAX** ایک کمانڈ لائن سیکیورٹی ٹول ہے جو Kali Linux کے لیے بنایا گیا ہے۔ یہ چھ ماڈیول فراہم کرتا ہے:

| ماڈیول | کام |
|---|---|
| `scan` | IP / CIDR پر زندہ ہوسٹس کی تلاش (ICMP + TCP + ARP cache) |
| `ports` | TCP/UDP پورٹ اسکیننگ، banner grabbing اور service fingerprinting |
| `dns` | DNS ریکارڈز، AXFR (zone transfer) چیک، subdomain enumeration، rDNS |
| `web` | HTTP ہیڈرز، redirects، security headers اور TLS سرٹیفکیٹ کا تجزیہ |
| `sysinfo` | مقامی سسٹم، ہارڈ ویئر، نیٹ ورک، posture اور security-tool inventory |
| `report` | محفوظ شدہ JSON رپورٹس کو یکجا کر کے Markdown / HTML / CSV بنانا |
| `shell` | انٹرایکٹو REPL — سب subcommands ایک ہی پرامپٹ میں |

ہر ماڈیول **findings** پیدا کرتا ہے جن میں severity (`critical` → `good`)، تفصیل، remediation اور ایک risk score ہوتا ہے۔

## Introduction (English)

KMAX is a modular reconnaissance and posture-analysis toolkit. It is deliberately
**dependency-free**: the complete network stack (a DNS resolver, an async port
scanner, an HTTP/TLS client) is implemented on the Python standard library.
External binaries — `nmap`, `dig`, `openssl`, `ping` — are used only when present,
and every capability degrades gracefully without them.

---

## Quick start

```bash
# 1. install (editable, recommended for development)
git clone https://example.invalid/kmax.git && cd kmax
./install.sh

# 2. or install straight from the project root
pip install .

# 3. run
kmax --help
kmax scan 10.0.0.0/24
kmax ports 10.0.0.5 -p top100 --no-banner
kmax dns example.com --axfr
kmax web https://example.com
kmax sysinfo --tools
kmax shell
```

---

## Installation / انسٹالیشن

### Kali / Debian (recommended)

```bash
chmod +x install.sh
sudo ./install.sh              # installs kmax + optional helper packages
./install.sh --user             # no sudo: installs into ~/.local
./install.sh --venv             # isolated virtualenv at ./.venv
./install.sh --uninstall        # remove the package
```

`install.sh` چیک کرتا ہے:
- Python 3.8+ موجود ہے
- اختیاری helpers (`nmap`, `dnsutils`, `openssl`, `netcat`) — اگر نہ ہوں تو بتا دیتا ہے (لازمی نہیں)

### Manual

```bash
python3 -m pip install --user .
kmax --version
```

### Requirements

- Python **3.8+** (tested on 3.11)
- کوئی تھرڈ پارٹی پیکج **لازمی نہیں** (`requirements.txt` صرف اختیاری extras بتاتا ہے)
- اختیاری: `nmap`, `dig` (dnsutils), `openssl`, `ping`

### Run without installing

```bash
python3 -m kmax scan 192.168.1.1
```

---

## Commands — English

### Global flags (always before the subcommand)

| Flag | Meaning |
|---|---|
| `-h, --help` | show help |
| `--version` | version + environment |
| `-v, --verbose` | show debug detail while scanning |
| `-q, --quiet` | suppress headers and progress — ideal for pipelines |
| `--json` | machine-readable JSON on stdout |
| `--no-color` | disable ANSI colours |
| `--debug` | full traceback on error |
| `-o, --report PATH` | save a report; the **extension** picks the format |
| `--format {html,markdown,md,json,csv}` | force a report format |
| `--timeout SECONDS` | per-probe timeout (default 1.0) |
| `--workers N` | concurrency (default 200) |
| `--no-resolve` | skip reverse DNS lookups |

### `kmax scan` — host discovery

```bash
kmax scan 10.0.0.0/24
kmax scan 10.0.0.10 10.0.0.11 --no-ping
kmax scan 10.0.0.0/24 --tcp 22,80,443 --nmap
kmax -q scan 192.168.1.0/24 --json -o discovery.json
```

| Flag | Meaning |
|---|---|
| `--tcp PORTS` | TCP ports used as liveness probes (default `80,443,22,445`) |
| `--no-ping` | skip ICMP, use TCP probes only |
| `--nmap` | additionally use `nmap -sn` when available |

### `kmax ports` — port scanning

```bash
kmax ports 10.0.0.5
kmax ports 10.0.0.5 -p 22,80,443
kmax ports 10.0.0.5 -p 1-1024 --workers 400
kmax ports 10.0.0.5 -p top100
kmax ports 10.0.0.5 -p 53 --udp
kmax ports 10.0.0.5 --no-banner
kmax ports 10.0.0.5 -p top1000 -o ports.html
```

| Flag | Meaning |
|---|---|
| `-p, --ports SPEC` | `80` · `80,443` · `1-1024` · `top100` · `top1000` · `all` |
| `--top N` | nmap-style top-N most common ports |
| `--udp` | probe UDP instead of TCP |
| `--no-banner` | skip banner grabbing (much faster) |

Banner grabbing اسکینر service کا نام، version اور (اگر ممکن ہو) ٹیکنالوجی بھی نکالتا ہے۔

### `kmax dns` — DNS intelligence

```bash
kmax dns example.com
kmax dns example.com --types A,AAAA,MX,TXT,SOA,NS,CAA
kmax dns example.com --axfr
kmax dns example.com -s --wordlist /usr/share/wordlists/subdomains.txt
kmax dns example.com --dns-server 1.1.1.1 --no-axfr --no-bruteforce
```

| Flag | Meaning |
|---|---|
| `--types LIST` | record types to query |
| `--axfr` | attempt a zone transfer against each nameserver |
| `-s, --subdomains` | brute-force subdomains |
| `--wordlist PATH` | wordlist for brute force (has a built-in default) |
| `--dns-server IP` | resolver to use (default 8.8.8.8) |
| `--no-axfr` / `--no-bruteforce` | skip those phases |

AXFR **کھلا** ہونا ایک critical misconfiguration ہے — KMAX اسے critical severity سے رپورٹ کرتا ہے۔

### `kmax web` — HTTP & TLS

```bash
kmax web https://example.com
kmax web http://10.0.0.5:8080 --no-tls
kmax web https://self-signed.local --insecure
kmax web example.com 10.0.0.7 --no-redirect
kmax web https://example.com --json -o web.json
```

| Flag | Meaning |
|---|---|
| `--insecure` | do not verify the certificate chain |
| `--no-tls` | skip the TLS/certificate phase |
| `--no-redirect` | do not follow redirects |

فراہم کردہ تجزیہ: status، final URL، redirect chain، ~6 security headers، disclosure headers، cookies اور مکمل X.509 تفصیلات (subject، issuer، validity، days remaining، SANs، protocol، cipher، signature algorithm)۔

### `kmax sysinfo` — local posture

```bash
kmax sysinfo
kmax sysinfo --tools
kmax sysinfo --packages
kmax sysinfo --public-ip
kmax sysinfo -o sysinfo.html
```

| Flag | Meaning |
|---|---|
| `--tools` | security-tool inventory (nmap، hydra، sqlmap، …) |
| `--packages` | package-manager facts (dpkg / apt / pip counts) |
| `--public-ip` | resolve the public egress IP |

### `kmax report` — merge saved reports

```bash
kmax report scan.json ports.csv dns.md
kmax report *.json --out combined.html --top 20
kmax report web.json --format csv -o web.csv
```

| Flag | Meaning |
|---|---|
| `--out PATH` | write the merged report |
| `--top N` | how many findings to show (default 10) |

### `kmax shell` — interactive REPL

```bash
kmax shell
```

```
kmax> scan 10.0.0.0/24
kmax> ports 10.0.0.5 -p top100 --no-banner
kmax> set json on
kmax> set report out.json
kmax> version
kmax> exit
```

`set` کلید: `json`, `quiet`, `report`, `format`, `timeout`, `workers`, `verbose`.
`run <cmd>` سے کوئی بھی shell کمانڈ چلائی جا سکتی ہے، `env` runtime دکھاتا ہے۔

---

## Commands — اردو

### بنیادی مثالیں

```bash
# پورے نیٹ ورک میں زندہ مشینیں ڈھونڈیں
kmax scan 192.168.1.0/24

# ایک ہوسٹ کے اہم پورٹس + banner
kmax ports 192.168.1.10 -p top100

# مکمل DNS ریکارڈز + zone transfer + subdomains
kmax dns mycompany.com --axfr -s

# ویب سائٹ کے ہیڈرز اور TLS سرٹیفکیٹ
kmax web https://mycompany.com

# اپنی مشین کی سیکیورٹی پوزیشن
kmax sysinfo --tools

# انٹرایکٹو موڈ
kmax shell
```

### رپورٹ بنانا

```bash
kmax -q scan 10.0.0.0/24 --json       -o scan.json      # مشین کے لیے
kmax -q dns example.com                -o dns.md        # GitHub/README کے لیے
kmax -q web https://example.com        -o web.html      # براؤزر میں دیکھیں
kmax -q ports 10.0.0.5 -p top1000      -o ports.csv     # اسپریڈ شیٹ کے لیے
```

> فارمیٹ **فائل کی extension** سے طے ہوتا ہے: `.json` `.md` `.html` `.csv`
> یا `--format` سے زبردستی مقرر کریں۔

### ٹِپس

- `-q` کے ساتھ `--json` استعمال کریں تاکہ stdout صرف JSON ہو (pipelines کے لیے)۔
- سکینز کو تیز کرنے کے لیے `--workers` بڑھائیں، مگر `--timeout` کم نہ کریں۔
- `--axfr` صرف ان domains پر چلائیں جن کی اجازت ہو۔

---

## Reports / رپورٹس

چار فارمیٹس، ایک ہی in-memory ماڈل سے:

| Format | Best for |
|---|---|
| **JSON** | automation، دوسرے ٹولز، `kmax report` سے merge |
| **Markdown** | GitHub، README، chat میں شیئر کرنا |
| **HTML** | براؤزر میں دکھانے کے لیے، self-contained (کوئی CDN نہیں) |
| **CSV** | Excel / Google Sheets، pivoting |

Sample Markdown output:

```markdown
# KMAX DNS intelligence - example.com

| Field | Value |
| --- | --- |
| Tool | `kmax 2.0.0` |
| Risk score | **14/100** |

**Findings:** medium: 1 · low: 2 · info: 1 · good: 2
```

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | success |
| `1` | unexpected runtime error |
| `2` | bad user input (invalid target / port spec / URL) |
| `3` | report file missing or unreadable |
| `4` | nothing found (empty result set) |

CI میں استعمال: `kmax -q ports 10.0.0.5 -p 22 --json || echo "check failed"`

---

## Project layout

```
kmax/
├── kmax/
│   ├── __init__.py
│   ├── __main__.py          # python -m kmax
│   ├── cli.py               # argparse CLI, dispatch, REPL
│   ├── core/
│   │   ├── context.py       # Runtime object
│   │   ├── models.py        # Finding / PortResult / CertInfo / ScanMeta
│   │   ├── report.py        # JSON / Markdown / HTML / CSV engine
│   │   ├── ui.py            # colours, tables, boxes, quiet/json-safe prints
│   │   └── utils.py         # target & port parsing, networking helpers
│   └── modules/
│       ├── netscan.py       # host discovery
│       ├── portscan.py      # async TCP/UDP scanner + banners
│       ├── dnsenum.py       # built-in DNS client, AXFR, subdomains
│       ├── webscan.py       # HTTP + TLS analysis
│       └── sysinfo.py       # local system posture
├── tests/test_kmax.py       # 77 tests, offline, stdlib + pytest
├── install.sh
├── requirements.txt
├── pyproject.toml
├── LICENSE
└── README.md
```

---

## Testing

```bash
python3 -m pytest -q                 # 77 tests, fully offline
python3 -m pytest -q -k dns          # one area only
```

ٹیسٹ سوٹ کو انٹرنیٹ کی ضرورت نہیں: socket ٹیسٹ loopback پر bind ہوتے ہیں اور DNS ٹیسٹ ہاتھ سے بنے packets پارس کرتے ہیں۔

---

## Legal notice / قانونی نوٹس

> **صرف اُن سسٹمز پر استعمال کریں جن پر آپ کو واضح تحریری اجازت ہو۔**
> غیر مجاز سکیننگ بہت سے ممالک میں جرم ہے۔ KMAX پیدا کنندہ کسی بھی غلط استعمال کا ذمہ دار نہیں۔
>
> Authorised testing only. Scanning systems you do not own or have written
> permission to test is illegal in many jurisdictions. The authors accept no
> liability for misuse.

`--axfr`، subdomain brute-forcing اور aggressive port scans target پر لاگز چھوڑتے ہیں — engagement کے scope کی پابندی کریں۔

---

## License

MIT — see [LICENSE](LICENSE).
