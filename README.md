# OSINPY — OSINT & Google Dorking Suite

A tool for **defensive OSINT and exposure assessment** — built to help security teams and researchers identify what sensitive information their organization has inadvertently exposed to public search engines.

Built with a fully async architecture (`asyncio`) and a multi-engine fallback system for resilience.

---

## Use case

Organizations frequently expose sensitive assets without realizing it — open S3 buckets, indexed admin panels, publicly accessible backup folders, employee documents. OSINPY automates the process of checking whether your own infrastructure has this kind of exposure, which is a standard step in any security audit or bug bounty engagement.

**Intended for:**
- Security auditors assessing their own organization's exposure
- Bug bounty hunters working on authorized programs
- Penetration testers with explicit written authorization
- Students learning OSINT methodology in lab environments (HackTheBox, TryHackMe, personal VMs)

---

## Features

- **100% async architecture** — concurrent searches and downloads via `asyncio`, no blocking I/O
- **4-level engine fallback** — automatically switches between search backends if one is rate-limited:
  1. `nodriver` — headless Chromium (most resilient)
  2. `duckduckgo` — lightweight text search
  3. `google` — direct HTTP requests
  4. `yahoo` — organic result extraction
- **Parallel downloader** — saves discovered files directly to a custom directory (`-d`)
- **Structured export** — results saved as JSON in `/output/` with URL, title, and snippet

---

## Search categories

| # | Category | Description |
|---|----------|-------------|
| 1 | `findFiles` | Locate publicly indexed files (PDFs, spreadsheets, source code) |
| 2 | `findPanels` | Identify exposed admin panels (for authorized scope only) |
| 3 | `findOpen_directories` | Find open directory listings on web servers |
| 4 | `intelligenceOsint` | Organizational OSINT — public documents, org charts |
| 5 | `advancedTechniques` | Combined dork patterns for broad recon |
| 6 | `infrastructure` | Cloud asset exposure — S3 buckets, Jenkins, Kubernetes dashboards |

---

## Installation

**Requirements:** Python 3.12+, Google Chrome/Chromium (for `nodriver` engine)

```bash
git clone https://github.com/lucachak/Crawler.git
cd Crawler
python -m venv .venv
source .venv/bin/activate      # Linux/macOS
# .venv\Scripts\activate       # Windows
pip install -r requirements.txt
```

---

## Usage

```bash
python main.py <engine> <category> <subcategory> [options]
```

### Examples

**Check if your organization's PDFs are publicly indexed:**
```bash
python main.py auto findFiles pdfs --filter yourdomain.com --max-results 10
```

**Find open directory listings on your own domain:**
```bash
python main.py auto findOpen_directories general --filter yourdomain.com --max-results 10
```

**Check for exposed admin panels in an authorized bug bounty scope:**
```bash
python main.py auto findPanels generic_admin --filter target-in-scope.com --max-results 5
```

**Headless scan for exposed cloud assets:**
```bash
python main.py nodriver infrastructure s3_buckets_aws --filter yourdomain.com --headless --max-results 5
```

### Options

| Flag | Description |
|------|-------------|
| `--filter` | Restrict results to a specific domain |
| `--query` | Additional search terms |
| `--max-results` | Maximum number of results to return |
| `--download-dir` | Directory to save downloaded files |
| `--headless` | Run browser engine without opening a window |

---

## Project structure

```
OSINPY/
├── helpers/
│   ├── Crawler.py      # Async crawlers and parallel downloader
│   ├── Executor.py     # Category interpreter and dork template builder
│   └── manual.py       # Dork database organized by category
├── output/             # JSON output from each run (git-ignored)
├── downloads/          # Default download folder (git-ignored)
├── main.py             # CLI entrypoint
└── README.md
```

---

## Legal disclaimer

This tool is intended strictly for **authorized security assessments** — use it only against systems you own or have explicit written permission to test.

Scanning or collecting information from systems without authorization violates computer crime laws in most jurisdictions (including Brazil's LGPD/Marco Civil da Internet, the EU's CFAA equivalent, and others). The author accepts no liability for unauthorized use.

If you're unsure whether your use is authorized, it isn't.

---

## Author

**Lucas Lucachak** — [github.com/lucachak](https://github.com/lucachak) · [portfolio](https://portifolio-vercel-inky.vercel.app)