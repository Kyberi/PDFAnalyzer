# 🔬 PDFAnalyzer — Advanced PDF Security Scanner

A containerized, multi-tool forensic pipeline for automated PDF security analysis. Integrates 15+ tools into a single Docker-based workflow with structured reporting, threat scoring, and SIEM integration.

---

## 🛠️ Tools Included

| Tool | Purpose |
|---|---|
| **pdfid** | Detect suspicious keywords (`/JS`, `/OpenAction`, `/Launch`, `/EmbeddedFile`, etc.) |
| **pdf-parser** | Deep structural analysis of all PDF objects and streams |
| **peepdf** | JavaScript detection and deobfuscation |
| **ExifTool** | Extract full document metadata (author, software, dates, encryption) |
| **pdfinfo** | Document structure (pages, encryption type, PDF version) |
| **pdftotext** | Primary text extractor (poppler-based, handles most PDFs) |
| **pdfminer** | Fallback text extractor (Python-based) |
| **tesseract-ocr** | Second fallback — OCR for image-based PDFs |
| **strings** | Pattern search for URLs, shell commands, JS keywords, dangerous PDF keywords |
| **YARA** | Malware pattern matching with embedded + custom rulesets |
| **qpdf** | PDF decryption with known password (supports all encryption types) |
| **pdfcrack** | Brute-force / wordlist for RC4 / AES-128 encrypted PDFs |
| **john** | Brute-force / wordlist for AES-256 encrypted PDFs via `pdf2john` |
| **ClamAV** | Local antivirus scan against ~300MB malware signature database |
| **curl** | Cloud hash reputation lookup via VirusTotal API v3 |
| **zbar-tools** | Extract and decode QR codes from embedded images (Quishing detection) |

---

## 🧱 Tech Stack

| Component | Details |
|---|---|
| Base image | `python:3.11-slim-bookworm` (multi-stage build) |
| Build stage | `gcc`, `libjpeg-dev`, `zlib1g-dev` (compiler not in final image) |
| peepdf | 0.4.x + Pillow 3.2.0 (pre-compiled wheel) |
| yara-python | Latest (pre-compiled wheel) |
| pdfminer.six | Latest |
| ExifTool | 12.x (apt) |
| poppler-utils | System (`pdftotext`, `pdfinfo`, `pdfimages`) |
| qpdf | System |
| pdfcrack | System |
| john | System + `pdf2john.py` (JohnTheRipper bleeding-jumbo) |
| zbar-tools | System (`zbarimg`) |

---

## 🏗️ Build the Image

```bash
cd PDFAnalyzer
sudo docker build -t kyberi/pdfanalyzer .
```

> Uses a **multi-stage Dockerfile**: `gcc` exists only in the builder stage — the final runtime image is smaller and has no compiler.

---

## 🚀 Usage

### Basic analysis

```bash
sudo docker run --rm -v $(pwd):/data kyberi/pdfanalyzer filename.pdf
```

> ⚠️ **ClamAV:** Without a volume the signature database (~300MB) is **re-downloaded on every run**.
> To cache it permanently:
> ```bash
> sudo docker run --rm -v $(pwd):/data -v clamav_db:/var/lib/clamav kyberi/pdfanalyzer filename.pdf
> ```

### Full options

```
pdfanalyzer <file.pdf> [options]

Options:
  <password>         Decrypt with known password
  -w <wordlist.txt>  Wordlist attack on encrypted PDF
  -t <seconds>       Brute-force timeout (default: 120)
  --json             Write JSON report to /data/<name>.report.json
  --misp             Write MISP Core Format event to /data/<name>.misp.json
  --batch            Scan all *.pdf files in /data sequentially

Environment variables:
  VT_API_KEY=<key>   VirusTotal API key for cloud hash lookup
```

### ⚙️ Environment Variables

All settings are passed via **CLI flags** or **environment variables** (`-e` flag).

```bash
# Pass VT_API_KEY inline
VT_API_KEY=your_key docker run --rm -v $(pwd):/data kyberi/pdfanalyzer document.pdf

# Or with -e flag
docker run --rm -e VT_API_KEY=your_key -v $(pwd):/data kyberi/pdfanalyzer document.pdf
```

### Examples

```bash
# Basic scan (no ClamAV)
sudo docker run --rm -v $(pwd):/data kyberi/pdfanalyzer document.pdf

# Full scan with ClamAV persistent database
sudo docker run --rm -v $(pwd):/data -v clamav_db:/var/lib/clamav kyberi/pdfanalyzer document.pdf

# Batch scan all PDFs in current directory
sudo docker run --rm -v $(pwd):/data -v clamav_db:/var/lib/clamav kyberi/pdfanalyzer --batch

# Generate JSON report
sudo docker run --rm -v $(pwd):/data kyberi/pdfanalyzer document.pdf --json

# Generate MISP event (for SOC integration)
sudo docker run --rm -v $(pwd):/data kyberi/pdfanalyzer document.pdf --misp

# Scan with known password
sudo docker run --rm -v $(pwd):/data kyberi/pdfanalyzer protected.pdf mypassword

# Wordlist attack on encrypted PDF with custom timeout
sudo docker run --rm -v $(pwd):/data kyberi/pdfanalyzer protected.pdf -w wordlist.txt -t 300

# VirusTotal cloud lookup (inline key)
VT_API_KEY=your_key docker run --rm -v $(pwd):/data -v clamav_db:/var/lib/clamav kyberi/pdfanalyzer document.pdf

# Custom YARA rules (place .yar files in ./yara_rules/)
sudo docker run --rm -v $(pwd):/data -v $(pwd)/yara_rules:/data/yara_rules kyberi/pdfanalyzer document.pdf
```

---

## 🦠 ClamAV Antivirus Database

> ⚠️ **Important:** Without a named volume, the ClamAV signature database (~300MB) is downloaded **every time you start the container**. Always mount `-v clamav_db:/var/lib/clamav` to avoid this.

ClamAV requires a virus signature database (~300MB). This is automatically managed by `entrypoint.sh`.

### Persistent volume (recommended)

```bash
# Create a named volume once (survives container restarts/removals)
sudo docker volume create clamav_db

# Always mount it with -v clamav_db:/var/lib/clamav
sudo docker run --rm -v $(pwd):/data -v clamav_db:/var/lib/clamav kyberi/pdfanalyzer document.pdf
```

*The entrypoint script will:*
1. **Auto-download** the DB (~300MB) on the first run if not present.
2. **Auto-update** in the background if the DB is older than 7 days.
3. **Skip** silently if the volume is not mounted (no AV scan will be performed).

### Manual update

```bash
sudo docker run --rm -v clamav_db:/var/lib/clamav --entrypoint freshclam pdfanalyzer
```

---

## 🔐 Password-Protected PDFs

### Encryption support matrix

| Encryption | Auto brute-force | Known password |
|---|---|---|
| No password (empty) | ✅ Auto-detected via qpdf | — |
| RC4 / AES-128 | ✅ pdfcrack (up to 6 chars, 30s) | ✅ qpdf |
| AES-256 | ✅ john + pdf2john (configurable timeout, default 120s) | ✅ qpdf |
| Wordlist attack | ✅ pdfcrack / john with `-w` flag | — |
| Microsoft AIP / IRM | ❌ Not possible (Azure DRM) | ❌ Not possible |
| Adobe LiveCycle DRM | ❌ Not possible | ❌ Not possible |

### Brute-force behaviour

- **RC4 / AES-128:** Uses `pdfcrack` with a 30-second hard limit.
- **AES-256:** Uses `john` + `pdf2john` with a configurable timeout (`-t <seconds>`, default 120s). Charset: `a-z`, `A-Z`, `0-9`, max 6 characters. After the run, prints the `john --status` summary (passwords tried, speed, progress).
- After cracking, `qpdf` decrypts the file and **all subsequent analysis stages run on the unlocked file**.

### Create a password-protected PDF for testing

```bash
# AES-128
sudo docker run --rm -v $(pwd):/data --entrypoint qpdf kyberi/pdfanalyzer \
    --encrypt abc abc 128 -- input.pdf protected_128.pdf

# AES-256
sudo docker run --rm -v $(pwd):/data --entrypoint qpdf kyberi/pdfanalyzer \
    --encrypt abc abc 256 -- input.pdf protected_256.pdf
```

---

## 📊 Analysis Pipeline (Step by Step)

Each analysis runs the following stages in order:

```
╔══════════════════════════════════════════════════════════════╗
║  📄 PDFAnalyzer Report: filename.pdf                         ║
╚══════════════════════════════════════════════════════════════╝
  File / Size / MD5 / SHA256 / Type / Date

  🔧 1. Encryption      — Detect, identify algorithm, crack or decrypt
  🔧 2. pdfid           — Suspicious keyword counts (/JS, /OpenAction, /Launch…)
  🔧 3. pdf-parser      — Object/stream structure summary
  🔧 4. peepdf          — JavaScript analysis and deobfuscation
  🔧 5. YARA            — Malware rule matches (built-in + custom rules)
  🔧 6. ExifTool        — Full metadata extraction
  🔧 7. pdfinfo         — Document information
  🔧 8. Text Extraction — pdftotext → pdfminer → tesseract OCR (cascade)
  🔧 9. QR Code         — Extract images and decode QR codes (Quishing)
  🔧10. Entropy         — File / Text / Strings entropy analysis
  🔧11. VirusTotal      — Cloud hash reputation (if API key provided)
  🔧12. ClamAV          — Antivirus scan (if DB is mounted/downloaded)
  🔧13. strings         — JS keywords / URLs / shell cmds / Advanced IoCs

╔══════════════════════════════════════════════════════════════╗
║  🛡️  Risk Assessment                                         ║
╚══════════════════════════════════════════════════════════════╝
  Risk Level : 🟢 LOW / 🟡 MEDIUM / 🔴 HIGH  (score: N)
  Findings   : list of detected indicators
```

---

## 🔍 Entropy Analysis (Obfuscation Detection)

The scanner computes **Shannon entropy** across three independent layers of the file to precisely locate hidden or obfuscated payloads, even inside otherwise "normal" PDFs:

| Layer | What it measures | Threshold | Risk added |
|---|---|---|---|
| **File Entropy** | Entire raw binary file | ≥ 7.9 / 8.0 | +20 |
| **Text Entropy** | Visible text extracted by pdftotext/pdfminer | ≥ 6.0 / 8.0 | +15 |
| **Strings Entropy** | All printable ASCII strings inside the binary | ≥ 6.5 / 8.0 | +15 |

**Why three layers?**

- **File entropy** alone is unreliable because normal PDFs always use `FlateDecode` (Zlib) compression internally, pushing the whole-file entropy to 7.5–7.8 even for clean documents. Only extremely packed/encrypted content will exceed 7.9.
- **Text entropy** targets Base64-encoded payloads embedded as visible text on a page. Normal text has entropy ~4.5. If it's above 6.0, the "text" is actually encoded data.
- **Strings entropy** scans only the printable ASCII layer (excluding binary blobs and image data). Obfuscated JavaScript inside PDF objects will dramatically raise this value above 6.5.

Example output:
```
  → File Entropy   : 7.7412 / 8.0  (Threshold: 7.9)
  → Text Entropy   : 4.8101 / 8.0  (Threshold: 6.0)
  → Strings Entropy: 5.4210 / 8.0  (Threshold: 6.5)

  ✅  All entropy levels are within normal ranges
```

---

## 🦟 Advanced IoC Extraction

The `strings` section performs automatic **Indicator of Compromise (IoC)** extraction using Python regex:

| IoC Type | Method | False-positive filtering |
|---|---|---|
| **Email addresses** | Word-boundary regex `\b...\b` | Filters `*@2x.*` (image scale suffixes) |
| **IP addresses** | IPv4 pattern `\b(N.N.N.N)\b` | Skips RFC-1918 private ranges (`10.`, `192.168.`, `172.`, `127.`) |
| **Bitcoin wallets** | Legacy (`1...`/`3...`) + SegWit (`bc1...`) | Length-validated (25-39 chars) |

Data is sourced from **both** the extracted visible text (`$TEXT`) **and** raw `strings` output, then deduplicated. If any IoC is found, **+10** is added to the risk score.

---

## 🔲 QR Code Analysis (Quishing)

The scanner automatically:
1. Extracts all embedded images from the PDF using `pdfimages -j`.
2. Passes each image through `zbarimg` to detect and decode QR codes.
3. Outputs the decoded URL/data and flags the file with **+10** risk points.

This detects **Quishing** attacks — phishing PDFs that embed malicious QR codes instead of clickable links to bypass URL scanners.

---

## 🧩 YARA Rules

### Built-in rules (embedded in image)

| Rule | Severity | Detects |
|---|---|---|
| `PDF_JavaScript` | MEDIUM | `/JavaScript`, `/JS` keywords |
| `PDF_OpenAction` | MEDIUM | `/OpenAction`, `/AA` — auto-run on open |
| `PDF_Launch` | HIGH | `/Launch` — external process execution |
| `PDF_EmbeddedFile` | LOW | `/EmbeddedFile` — attachments |
| `PDF_Obfuscation` | MEDIUM | `fromCharCode`, `unescape(`, `eval(` |
| `PDF_ExternalURI` | INFO | `/URI` — external links |

### Custom YARA rules

Mount a directory of your own `.yar` files:

```bash
sudo docker run --rm -v $(pwd):/data -v $(pwd)/yara_rules:/data/yara_rules kyberi/pdfanalyzer document.pdf
```

All `.yar` files inside `/data/yara_rules/` are loaded and compiled alongside the built-in ruleset. Rule `severity` field in the `meta:` block drives risk scoring (HIGH +50, MEDIUM +20, LOW +5).

---

## 📤 Output Formats

### JSON Report (`--json`)

Writes a machine-readable report to `/data/<name>.report.json`:

```json
{
  "file": "document.pdf",
  "sha256": "a3f...",
  "risk_score": 35,
  "risk_level": "MEDIUM",
  "findings": ["pdfid: /JavaScript = 2", "strings: external URLs found"],
  "encrypted": false,
  "cracked_password": null
}
```

### MISP Event (`--misp`)

Writes a MISP Core Format event to `/data/<name>.misp.json`, ready for import into any MISP instance or SIEM:

```json
{
  "Event": {
    "uuid": "...",
    "info": "PDFAnalyzer detection: document.pdf",
    "date": "2026-05-15",
    "Attribute": [
      {"type": "sha256", "value": "a3f...", "to_ids": true},
      {"type": "filename", "value": "document.pdf", "to_ids": false}
    ]
  }
}
```

---

## 🛡️ Risk Scoring

| Indicator | Points |
|---|---|
| ClamAV: malware detected | +100 |
| VirusTotal: malicious engines | +100 |
| strings: shell/exec commands found | +50 |
| YARA HIGH severity match | +50 |
| File type mismatch (not a valid PDF) | +40 |
| pdfid: `/JS`, `/JavaScript`, `/OpenAction`, `/Launch`, etc. | +25 each |
| peepdf: JavaScript detected | +25 |
| strings: JavaScript keywords found | +25 |
| Phishing keywords in visible text | +20 |
| High file entropy (≥ 7.9) | +20 |
| YARA MEDIUM severity match | +20 |
| High text entropy (≥ 6.0) | +15 |
| High strings entropy (≥ 6.5) | +15 |
| Weak password cracked (brute-force / wordlist) | +15 |
| QR Code detected (possible Quishing) | +10 |
| Extracted Emails/IPs/Bitcoin wallets | +10 |
| strings: external URLs found | +5 |
| pdfid: `/EmbeddedFile` | +5 |
| Encrypted PDF with empty password | +5 |
| YARA LOW severity match | +5 |
| PDF is password-protected | +5 |

**Thresholds:**
- 🟢 **LOW** — score < 30 *(harmless or weak signals only)*
- 🟡 **MEDIUM** — score 30–79 *(multiple suspicious indicators present)*
- 🔴 **HIGH** — score ≥ 80 *(confirmed threat or multiple strong indicators)*

**Threshold rationale:**
- A typical clean PDF with external URLs gets ≤ 10 → stays 🟢 LOW
- A PDF with JavaScript + phishing text gets 25 + 20 = 45 → 🟡 MEDIUM
- A single ClamAV or VirusTotal hit gives 100 → instant 🔴 HIGH
- Shell commands alone (50) + JS keywords (25) = 75 → 🟡 MEDIUM, needs one more signal for HIGH

---

## 📁 Project Structure

```
PDFAnalyzer/
├── Dockerfile      # Multi-stage build (builder + runtime stages)
├── analyze.sh      # Main analysis script (all 13 stages)
├── entrypoint.sh   # ClamAV DB lifecycle + exec to analyze.sh
├── pdf.yar         # Built-in YARA rules for PDF malware detection
├── DOCKERHUB.md    # Docker Hub description
├── .gitignore
└── README.md       # This file
```

---

## 🔓 Running Without `sudo`

```bash
sudo usermod -aG docker $USER
newgrp docker
docker run --rm -v $(pwd):/data kyberi/pdfanalyzer document.pdf
```

---

## ⚙️ Volume Mount Reference

```
docker run --rm  -v /path/to/pdfs:/data  -v clamav_db:/var/lib/clamav  kyberi/pdfanalyzer file.pdf
                 ^^^^^^^^^^^^^^^^^^^^^^^^ ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
                 your PDF folder          ClamAV signature DB (persistent)
```

> ⚠️ The `-v` flags must come **before** the image name (`pdfanalyzer`).

---

## 🔐 Password-Protected PDF — Test Workflow

```bash
# Step 1: create a protected PDF
sudo docker run --rm -v $(pwd):/data --entrypoint qpdf kyberi/pdfanalyzer \
    --encrypt test test 256 -- original.pdf protected.pdf

# Step 2: analyze with auto brute-force (120s default)
sudo docker run --rm -v $(pwd):/data kyberi/pdfanalyzer protected.pdf

# Step 3: analyze with wordlist
sudo docker run --rm -v $(pwd):/data kyberi/pdfanalyzer protected.pdf -w wordlist.txt

# Step 4: analyze with known password
sudo docker run --rm -v $(pwd):/data kyberi/pdfanalyzer protected.pdf test
```

---

## 💡 Tips

- **Speed up repeat scans:** Mount `clamav_db` volume — avoids re-downloading 300MB every run.
- **SIEM integration:** Use `--json` output and pipe to `jq` or ingest into Splunk/Elastic.
- **SOC workflow:** Use `--misp` to create MISP events automatically for each suspicious file.
- **Custom threat rules:** Drop `.yar` files in a local `yara_rules/` folder and mount it to `/data/yara_rules`.
- **Batch scanning:** Use `--batch` to process all PDFs in a directory sequentially.
- **Long passwords:** Increase timeout with `-t 600` for brute-force cracking.
