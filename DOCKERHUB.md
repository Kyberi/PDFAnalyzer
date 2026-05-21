# 🔬 PDFAnalyzer — Advanced PDF Security Scanner

A containerized, multi-tool forensic pipeline for automated PDF security analysis. Integrates 15+ forensic tools into a single Docker-based workflow with structured reporting, threat scoring, and SIEM integration.

## ✨ Key Features
- **Comprehensive Scanning**: Uses `pdfid`, `pdf-parser`, `peepdf`, `YARA`, `ClamAV`, `exiftool`, `strings`, `pdfminer`, and `tesseract-ocr`.
- **Advanced Entropy Analysis**: Detects obfuscated payloads, packed JavaScript, and Base64 encoded streams across three independent layers (File, Text, Strings).
- **Automated Password Cracking**: Built-in `pdfcrack` (RC4/AES-128) and `john the ripper` (AES-256) for brute-forcing and dictionary attacks on protected PDFs.
- **Quishing Detection**: Automatically extracts images and scans for malicious QR codes using `zbar-tools`.
- **IoC Extraction**: Extracts hidden Emails, IP addresses, and Bitcoin wallets via advanced Regex filtering.
- **Threat Scoring**: Intelligent weighted risk scoring (Low, Medium, High) based on detected indicators.
- **SOC Integration**: Exports analysis reports to JSON or MISP Core Format.
- **Cloud Intelligence**: Optional VirusTotal hash reputation checks via API.

## 🚀 Quick Start

Run a basic scan on a file in your current directory:
```bash
docker run --rm -v $(pwd):/data kyberi/pdfanalyzer document.pdf
```

### Enable ClamAV (Antivirus)
To avoid downloading the ~300MB ClamAV signature database on every run, mount a persistent volume:
```bash
docker volume create clamav_db
docker run --rm -v $(pwd):/data -v clamav_db:/var/lib/clamav kyberi/pdfanalyzer document.pdf
```

### Batch Scanning
Scan all PDFs in a directory sequentially:
```bash
docker run --rm -v $(pwd):/data -v clamav_db:/var/lib/clamav kyberi/pdfanalyzer --batch
```

## ⚙️ Configuration & Options

```text
Options:
  <password>         Decrypt with known password
  -w <wordlist.txt>  Wordlist attack on encrypted PDF
  -t <seconds>       Brute-force timeout (default: 120)
  --json             Write JSON report  → /data/<name>.report.json
  --misp             Write MISP event   → /data/<name>.misp.json
  --batch            Scan all *.pdf files in /data sequentially
  --help, -h         Show help

Environment variables (inline):
  VT_API_KEY=<key>   VirusTotal API key for cloud hash lookup
```

Example with VirusTotal, JSON output, and custom YARA rules:
```bash
docker run --rm \
  -e VT_API_KEY="your_api_key" \
  -v $(pwd):/data \
  -v clamav_db:/var/lib/clamav \
  -v $(pwd)/yara_rules:/data/yara_rules \
  kyberi/pdfanalyzer document.pdf --json
```

## 🔐 Password Protected PDFs
The scanner automatically attempts to crack passwords. Use `-t` to change the brute-force timeout or `-w` to provide a custom wordlist:
```bash
docker run --rm -v $(pwd):/data kyberi/pdfanalyzer encrypted.pdf -w wordlist.txt -t 300
```

## 📖 Full Documentation
For complete documentation including entropy analysis, IoC extraction, YARA rules, MISP export, and risk scoring details, see the [GitHub README](https://github.com/Kyberi/PDFAnalyzer).
