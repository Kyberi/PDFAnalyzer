#!/bin/bash

# PDFAnalyzer — Multi-tool PDF Security Scanner

# ── Batch mode ──────────────────────────────────────────────────────
if [[ "$1" == "--batch" ]]; then
    shift
    FOUND=0
    for pdf in /data/*.pdf /data/*.PDF; do
        [[ -f "$pdf" ]] || continue
        FOUND=1
        bash "$0" "$(basename "$pdf")" "$@"
        echo ""
        echo "════════════════════════════════════════════════════════════════"
    done
    [[ $FOUND -eq 0 ]] && echo "  No PDF files found in /data/"
    exit 0
fi

# ── Help ──────────────────────────────────────────────────────────────────
if [[ "$1" == "--help" || "$1" == "-h" || -z "$1" ]]; then
    echo ""
    echo "  ╔════════════════════════════════════════════════════════════════╗"
    echo "  ║       PDFAnalyzer — Advanced PDF Security Scanner             ║"
    echo "  ╚════════════════════════════════════════════════════════════════╝"
    echo ""
    echo "  Usage:"
    echo "    docker run --rm -v \$(pwd):/data kyberi/pdfanalyzer <file.pdf> [options]"
    echo ""
    echo "  Options:"
    echo "    <password>         Decrypt with known password"
    echo "    -w <wordlist.txt>  Wordlist attack on encrypted PDF"
    echo "    -t <seconds>       Brute-force timeout (default: 120)"
    echo "    --json             Write JSON report  → /data/<name>.report.json"
    echo "    --misp             Write MISP event   → /data/<name>.misp.json"
    echo "    --batch            Scan all *.pdf files in /data sequentially"
    echo "    --help, -h         Show this help"
    echo ""
    echo "  Environment variables (inline):"
    echo "    VT_API_KEY=<key>   VirusTotal API key for cloud hash lookup"
    echo ""
    echo "  ⚠️  ClamAV Note:"
    echo "    Without a volume, the AV database (~300MB) is downloaded on EVERY run."
    echo "    To cache it permanently, add: -v clamav_db:/var/lib/clamav"
    echo ""
    echo "  Examples:"
    echo "    docker run --rm -v \$(pwd):/data kyberi/pdfanalyzer doc.pdf"
    echo "    docker run --rm -v \$(pwd):/data kyberi/pdfanalyzer doc.pdf secret123"
    echo "    docker run --rm -v \$(pwd):/data kyberi/pdfanalyzer doc.pdf -w words.txt -t 300"
    echo "    docker run --rm -v \$(pwd):/data kyberi/pdfanalyzer doc.pdf --json --misp"
    echo "    docker run --rm -v \$(pwd):/data kyberi/pdfanalyzer --batch"
    echo "    docker run --rm -v \$(pwd):/data -v clamav_db:/var/lib/clamav kyberi/pdfanalyzer doc.pdf"
    echo "    docker run --rm -e VT_API_KEY=xxx -v \$(pwd):/data kyberi/pdfanalyzer doc.pdf"
    echo "    docker run --rm -v \$(pwd):/data -v ./rules:/data/yara_rules kyberi/pdfanalyzer doc.pdf"
    echo ""
    echo "  Analysis stages:"
    echo "     1. Encryption      — detect algorithm, crack or decrypt"
    echo "     2. pdfid           — suspicious keywords (/JS /Launch /OpenAction ...)"
    echo "     3. pdf-parser      — deep structural object analysis"
    echo "     4. peepdf          — JavaScript detection and deobfuscation"
    echo "     5. YARA            — malware rules (built-in + custom from /data/yara_rules)"
    echo "     6. ExifTool        — full metadata extraction"
    echo "     7. pdfinfo         — document structure"
    echo "     8. Text Extraction — pdftotext → pdfminer → tesseract OCR"
    echo "     9. QR Codes        — Quishing detection (zbarimg)"
    echo "    10. Entropy         — file / text / strings Shannon entropy"
    echo "    11. VirusTotal      — cloud hash reputation (requires VT_API_KEY)"
    echo "    12. ClamAV          — antivirus scan  (requires clamav_db volume)"
    echo "    13. strings         — JS keywords / URLs / shell cmds / IoCs"
    echo ""
    exit 0
fi

FILE="$1"; shift
PASSWORD=""
WORDLIST=""
TIMEOUT=120
JSON_OUTPUT=false
RISK_SCORE=0
RISK_FINDINGS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        -t|--timeout)  TIMEOUT="$2"; shift 2 ;;
        -w|--wordlist) WORDLIST="$2"; shift 2 ;;
        --json)        JSON_OUTPUT=true; shift ;;
        --misp)        MISP_OUTPUT=true; shift ;;
        *)             PASSWORD="$1"; shift ;;
    esac
done

# ── File validation ────────────────────────────────────────────────────────
if [[ ! -f "$FILE" ]]; then
    echo ""
    echo "  ❌ Error: file '$FILE' not found in /data"
    echo "     Make sure to mount your directory: -v \$(pwd):/data"
    echo ""
    exit 1
fi

# ── Helpers ───────────────────────────────────────────────────────────────
print_banner() {
    python3 -c "
import sys, unicodedata
title = sys.argv[1]
text = '  ' + title + '  '
def dw(c):
    # variation selectors (U+FE00-FE0F) are zero-width
    if '\uFE00' <= c <= '\uFE0F': return 0
    if unicodedata.category(c) == 'Mn': return 0
    return 2 if unicodedata.east_asian_width(c) in ('W','F') else 1
w = sum(dw(c) for c in text)
print()
print('╔' + '═' * w + '╗')
print('║' + text + '║')
print('╚' + '═' * w + '╝')
" "$1"
}

print_section() {
    python3 -c "
import sys, unicodedata
title = sys.argv[1]
text = '  \U0001F527 ' + title + '  '
def dw(c):
    if '\uFE00' <= c <= '\uFE0F': return 0
    if unicodedata.category(c) == 'Mn': return 0
    return 2 if unicodedata.east_asian_width(c) in ('W','F') else 1
w = sum(dw(c) for c in text)
print()
print('  \u250C' + '\u2500' * w + '\u2510')
print('  \u2502' + text + '\u2502')
print('  \u2514' + '\u2500' * w + '\u2518')
print()
" "$1"
}


add_risk() {
    # $1 = points, $2 = description
    RISK_SCORE=$((RISK_SCORE + $1))
    RISK_FINDINGS+=("$2")
}

# ── Report header ─────────────────────────────────────────────────────────
print_banner "📄 PDFAnalyzer Report: $(basename "$FILE")"
echo ""
FILESHA=$(sha256sum "$FILE" | cut -d' ' -f1)
echo "  File    : $FILE"
echo "  Size    : $(du -h "$FILE" | cut -f1)"
echo "  MD5     : $(md5sum "$FILE" | cut -d' ' -f1)"
echo "  SHA256  : $FILESHA"
echo "  Type    : $(file -b "$FILE")"
echo "  Date    : $(date -u '+%Y-%m-%d %H:%M:%S UTC')"

# Warn if not a PDF
if ! file -b "$FILE" | grep -qi "pdf"; then
    echo ""
    echo "  ⚠️  WARNING: File does not appear to be a valid PDF!"
    add_risk 40 "File type mismatch (not a standard PDF)"
fi

# ── 1. Encryption Check ───────────────────────────────────────────────────
print_section "Encryption — Password Protection Check"
DECRYPTED="/tmp/decrypted_$(basename "$FILE")"
CRACKED_PASSWORD=""
ENCRYPT_ALGO=""

# Primary: pdfinfo (works for owner-only protected files)
ENCRYPTED=$(pdfinfo "$FILE" 2>/dev/null | grep "^Encrypted:" | awk '{print $2}')

# Fallback: pdfid /Encrypt count (works even when pdfinfo can't open the file)
if [[ "$ENCRYPTED" != "yes" ]]; then
    ENCRYPT_COUNT=$(python3 /opt/pdftools/pdfid.py "$FILE" 2>/dev/null | grep -w "/Encrypt" | grep -oP '\d+' | tail -1)
    [[ "${ENCRYPT_COUNT:-0}" -gt 0 ]] && ENCRYPTED="yes"
fi

# Detect algorithm from exiftool
ENCRYPT_ALGO=$(exiftool -Encryption "$FILE" 2>/dev/null | grep -oP "(?<=: ).*")

if [[ "$ENCRYPTED" == "yes" ]]; then
    echo "  🔒 PDF is encrypted (password protected)"
    [[ -n "$ENCRYPT_ALGO" ]] && echo "  📋 Algorithm: $ENCRYPT_ALGO"
    add_risk 5 "PDF is password-protected"


    if [[ -n "$PASSWORD" ]]; then
        # Try known password
        echo "  → Attempting decrypt with provided password: '$PASSWORD'"
        if qpdf --decrypt --password="$PASSWORD" "$FILE" "$DECRYPTED" 2>/dev/null; then
            echo "  ✅ Password correct: '$PASSWORD'"
            CRACKED_PASSWORD="$PASSWORD"
            FILE="$DECRYPTED"
        else
            echo "  ❌ Password '$PASSWORD' is incorrect"
        fi

    elif [[ -n "$WORDLIST" ]]; then
        # Wordlist attack
        echo "  → Running pdfcrack with wordlist: $WORDLIST"
        CRACK_OUT=$(pdfcrack -f "$FILE" -w "$WORDLIST" 2>/dev/null)
        CRACK_RESULT=$(echo "$CRACK_OUT" | grep -i "found")
        if [[ -n "$CRACK_RESULT" ]]; then
            CRACKED_PASSWORD=$(echo "$CRACK_RESULT" | grep -oP "(?<=password: ).*" | tr -d "'\"")
            echo "  ✅ PASSWORD CRACKED: '$CRACKED_PASSWORD'"
            add_risk 15 "Weak PDF password cracked via wordlist"
            qpdf --decrypt --password="$CRACKED_PASSWORD" "$FILE" "$DECRYPTED" 2>/dev/null && FILE="$DECRYPTED"
        else
            echo "  ❌ Password not found in wordlist"
        fi

    else
        # Try empty password first (qpdf supports all encryption types)
        if qpdf --decrypt --password="" "$FILE" "$DECRYPTED" 2>/dev/null; then
            echo "  ⚠️  PDF opened with EMPTY password!"
            CRACKED_PASSWORD="(empty)"
            add_risk 5 "Encrypted PDF with empty password"
            FILE="$DECRYPTED"
        elif echo "$ENCRYPT_ALGO" | grep -q "256"; then
            # AES-256: use john + pdf2john
            PDF2JOHN="/opt/pdf2john.py"
            if [[ -z "$PDF2JOHN" ]]; then
                echo "  ❌ pdf2john not found — cannot crack AES-256"
                echo "  💡 Pass password directly: pdfanalyzer $(basename "$FILE") <password>"
            else
                echo "  → Extracting PDF hash with pdf2john..."
                "$PDF2JOHN" "$FILE" > /tmp/pdf_hash.txt 2>/dev/null
                if [[ -n "$WORDLIST" ]]; then
                    echo "  → Running john with wordlist: $WORDLIST"
                    CRACK_OUT=$(timeout 60 john /tmp/pdf_hash.txt --wordlist="$WORDLIST" 2>/dev/null)
                else
                echo "  → Running john brute-force (${TIMEOUT}s limit, charset: a-z A-Z 0-9, max 6 chars)..."
                JOHN_SESSION="/tmp/john_pdf_session"
                timeout "$TIMEOUT" john /tmp/pdf_hash.txt \
                    --incremental=Alnum --max-length=6 \
                    --session="$JOHN_SESSION" 2>/dev/null
                fi
                CRACKED_PASSWORD=$(john --show /tmp/pdf_hash.txt 2>/dev/null | grep -oP "^[^:]+:[^:]+" | cut -d: -f2 | head -1)
                # Show john status (passwords tried, speed)
                JOHN_STATUS=$(john --status="$JOHN_SESSION" 2>/dev/null | head -3)
                [[ -n "$JOHN_STATUS" ]] && echo "  📊 John status:" && echo "$JOHN_STATUS" | sed 's/^/     /'
                if [[ -n "$CRACKED_PASSWORD" ]]; then
                    echo "  ✅ PASSWORD CRACKED: '$CRACKED_PASSWORD'"
                    add_risk 15 "AES-256 PDF password cracked via john"
                    qpdf --decrypt --password="$CRACKED_PASSWORD" "$FILE" "$DECRYPTED" 2>/dev/null && FILE="$DECRYPTED"
                else
                    echo "  ⏱️  john: password not found"
                    echo "  💡 Try with wordlist: pdfanalyzer $(basename "$FILE") -w wordlist.txt"
                fi
                rm -f /tmp/pdf_hash.txt
            fi
        else
            # RC4 / AES-128: try pdfcrack brute-force
            echo "  → Trying pdfcrack brute-force (30 sec limit, max 6 chars)..."
            CRACK_OUT=$(timeout 30 pdfcrack -f "$FILE" -m 6 2>/dev/null)
            CRACK_RESULT=$(echo "$CRACK_OUT" | grep -i "found")
            if [[ -n "$CRACK_RESULT" ]]; then
                CRACKED_PASSWORD=$(echo "$CRACK_RESULT" | grep -oP "(?<=password: ).*" | tr -d "'\"")
                echo "  ✅ PASSWORD CRACKED: '$CRACKED_PASSWORD'"
                add_risk 15 "Weak PDF password cracked via brute-force"
                qpdf --decrypt --password="$CRACKED_PASSWORD" "$FILE" "$DECRYPTED" 2>/dev/null && FILE="$DECRYPTED"
            else
                echo "  ⏱️  Brute-force timeout — password not found within 30s"
                echo "  💡 Try with wordlist: pdfanalyzer file.pdf -w wordlist.txt"
            fi
        fi
    fi

    if [[ -n "$CRACKED_PASSWORD" ]]; then
        echo ""
        echo "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "  🔑 DECRYPTED — continuing analysis on unlocked file"
        echo "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    fi
else
    echo "  🔓 PDF is not encrypted"
fi

# ── 2. pdfid ──────────────────────────────────────────────────────────────
print_section "pdfid — Suspicious Object Detection"
PDFID_OUT=$(python3 /opt/pdftools/pdfid.py "$FILE" 2>/dev/null)
echo "$PDFID_OUT"

# Risk scoring based on pdfid output
for kw in "/JS" "/JavaScript" "/AA" "/OpenAction" "/Launch" "/JBIG2Decode" "/RichMedia" "/XFA"; do
    COUNT=$(echo "$PDFID_OUT" | grep -w "$kw" | grep -oP '\d+' | tail -1)
    if [[ "$COUNT" -gt 0 ]] 2>/dev/null; then
        add_risk 25 "pdfid: $kw = $COUNT"
    fi
done
COUNT=$(echo "$PDFID_OUT" | grep -w "/EmbeddedFile" | grep -oP '\d+' | tail -1)
[[ "$COUNT" -gt 0 ]] 2>/dev/null && add_risk 5 "pdfid: /EmbeddedFile = $COUNT"

# ── 2. pdf-parser ─────────────────────────────────────────────────────────
print_section "pdf-parser — Structure Summary"
python3 /opt/pdftools/pdf-parser.py -a "$FILE" 2>/dev/null || echo "  ⚠️  pdf-parser: failed"

# ── 3. peepdf ─────────────────────────────────────────────────────────────
print_section "peepdf — JavaScript & Risk Analysis"
PEEPDF_OUT=$(peepdf -f "$FILE" 2>/dev/null)
echo "$PEEPDF_OUT"

if echo "$PEEPDF_OUT" | grep -qiE "javascript|suspicious"; then
    add_risk 25 "peepdf: detected JavaScript or suspicious elements"
fi

# ── 4. YARA ───────────────────────────────────────────────────────────────
print_section "YARA — Malware Pattern Matching"
YARA_OUT=$(python3 -c "
import yara, sys, glob
rules_files = {'default': '/opt/yara-rules/pdf.yar'}
for i, f in enumerate(glob.glob('/data/yara_rules/*.yar')):
    rules_files[f'custom_{i}'] = f
try:
    rules = yara.compile(filepaths=rules_files)
    matches = rules.match('$FILE')
    for m in matches:
        sev = m.meta.get('severity', 'LOW')
        print(f'[{sev}] {m.rule}: {m.meta.get(\"description\", \"\")}')
except Exception as e:
    print(f'Error: {e}')
" 2>/dev/null)

if [[ -n "$YARA_OUT" && ! "$YARA_OUT" == "Error"* ]]; then
    echo "$YARA_OUT" | sed 's/^/  /'
    while IFS= read -r line; do
        [[ "$line" == *"HIGH"* ]] && add_risk 50 "YARA: $line"
        [[ "$line" == *"MEDIUM"* ]] && add_risk 20 "YARA: $line"
        [[ "$line" == *"LOW"* ]] && add_risk 5 "YARA: $line"
    done <<< "$YARA_OUT"
else
    echo "  ✅ No YARA rules matched"
fi

# ── 5. ExifTool ───────────────────────────────────────────────────────────
print_section "ExifTool — Metadata Extraction"
exiftool "$FILE" 2>/dev/null || echo "  ⚠️  exiftool: failed"

# ── 6. pdfinfo ────────────────────────────────────────────────────────────
print_section "pdfinfo — Document Information"
pdfinfo "$FILE" 2>/dev/null || echo "  ⚠️  pdfinfo: failed"

# ── 7. pdfminer — Text Content ────────────────────────────────────────────
print_section "Text Extraction — pdftotext + pdfminer"

# Primary: pdftotext (poppler) — handles most PDFs including Microsoft Print to PDF
TEXT=$(pdftotext "$FILE" - 2>/dev/null)
TEXT_CHECK=$(echo "$TEXT" | tr -d '[:space:]')   # strip whitespace to detect truly empty output

if [[ -n "$TEXT_CHECK" ]]; then
    echo "  [source: pdftotext]"
    echo "$TEXT" | sed 's/^/  /'
else
    # Fallback: pdfminer
    TEXT=$(python3 -c "
import sys
from pdfminer.high_level import extract_text
try:
    t = extract_text(sys.argv[1])
    print(t.strip() if t else '')
except Exception as e:
    print(f'error: {e}')
" "$FILE" 2>/dev/null)
    TEXT_CHECK=$(echo "$TEXT" | tr -d '[:space:]')

    if [[ -n "$TEXT_CHECK" ]]; then
        echo "  [source: pdfminer]"
        echo "$TEXT" | sed 's/^/  /'
    elif command -v tesseract &>/dev/null; then
        echo "  [source: tesseract OCR — image-based PDF detected]"
        OCR_DIR="/tmp/ocr_$$"
        mkdir -p "$OCR_DIR"
        pdftoppm -r 200 "$FILE" "$OCR_DIR/page" 2>/dev/null
        TEXT=""
        for img in "$OCR_DIR"/page*.ppm; do
            [[ -f "$img" ]] || continue
            TEXT+=$(tesseract "$img" stdout -l eng 2>/dev/null)
            TEXT+=$'\n'
        done
        rm -rf "$OCR_DIR"
        TEXT_CHECK=$(echo "$TEXT" | tr -d '[:space:]')
        if [[ -n "$TEXT_CHECK" ]]; then
            echo "$TEXT" | sed 's/^/  /'
        else
            echo "  ⚠️  No text found even after OCR (pure vector/DRM-protected)"
        fi
    else
        echo "  ⚠️  No extractable text (image-based PDF, custom fonts, or DRM-protected)"
    fi
fi

# Check for phishing keywords in text
if echo "$TEXT" | grep -qiE "verify your account|click here|urgent|password|bank|confirm|login"; then
    add_risk 20 "Phishing keywords detected in visible text"
fi

# ── 8.5. QR Code Analysis (Quishing) ──────────────────────────────────────
print_section "QR Code Analysis (Quishing)"
mkdir -p "/tmp/qr_$$"
pdfimages -j "$FILE" "/tmp/qr_$$/img" 2>/dev/null
QR_DATA=""
for img in "/tmp/qr_$$"/*; do
    [[ -f "$img" ]] || continue
    QR_DATA+=$(zbarimg --quiet --raw "$img" 2>/dev/null)
    QR_DATA+=$'\n'
done
rm -rf "/tmp/qr_$$"
QR_CHECK=$(echo "$QR_DATA" | tr -d '[:space:]')
if [[ -n "$QR_CHECK" ]]; then
    echo "$QR_DATA" | sed 's/^/  /'
    add_risk 10 "QR Code detected (possible Quishing)"
else
    echo "  ✅  No QR codes found"
fi


# ── 9. Entropy Analysis ────────────────────────────────────────────────────────────
print_section "Entropy Analysis — Obfuscation Detection"
ENTROPY_OUT=$(python3 -c "
import sys, math, collections, subprocess

def calc_ent(data):
    if not data: return 0.0
    freq = collections.Counter(data)
    n = len(data)
    return -sum((c/n)*math.log2(c/n) for c in freq.values())

file_path = sys.argv[1]
text_data = sys.argv[2].encode('utf-8', 'ignore')

try:
    with open(file_path, 'rb') as f:
        file_ent = calc_ent(f.read())
except:
    file_ent = 0.0

text_ent = calc_ent(text_data)

try:
    strings_out = subprocess.check_output(['strings', file_path], stderr=subprocess.DEVNULL)
    strings_ent = calc_ent(strings_out)
except:
    strings_ent = 0.0

print(f'{file_ent:.4f},{text_ent:.4f},{strings_ent:.4f}')
" "$FILE" "$TEXT")

FILE_ENT=$(echo "$ENTROPY_OUT" | cut -d',' -f1)
TEXT_ENT=$(echo "$ENTROPY_OUT" | cut -d',' -f2)
STR_ENT=$(echo "$ENTROPY_OUT" | cut -d',' -f3)

echo "  → File Entropy   : $FILE_ENT / 8.0  (Threshold: 7.9)"
echo "  → Text Entropy   : $TEXT_ENT / 8.0  (Threshold: 6.0)"
echo "  → Strings Entropy: $STR_ENT / 8.0  (Threshold: 6.5)"
echo ""

HAS_HIGH_ENT=0

if python3 -c "import sys; sys.exit(0 if float('${FILE_ENT:-0}') >= 7.9 else 1)" 2>/dev/null; then
    echo "  ⚠️  Extreme file entropy — possible encryption or heavy packing"
    add_risk 20 "High file entropy ($FILE_ENT)"
    HAS_HIGH_ENT=1
fi

if python3 -c "import sys; sys.exit(0 if float('${TEXT_ENT:-0}') >= 6.0 and float('${TEXT_ENT:-0}') > 0.0 else 1)" 2>/dev/null; then
    echo "  ⚠️  High text entropy — visible text may contain Base64 payloads"
    add_risk 15 "High text entropy ($TEXT_ENT)"
    HAS_HIGH_ENT=1
fi

if python3 -c "import sys; sys.exit(0 if float('${STR_ENT:-0}') >= 6.5 and float('${STR_ENT:-0}') > 0.0 else 1)" 2>/dev/null; then
    echo "  ⚠️  High strings entropy — hidden strings contain obfuscated data"
    add_risk 15 "High strings entropy ($STR_ENT)"
    HAS_HIGH_ENT=1
fi

if [[ $HAS_HIGH_ENT -eq 0 ]]; then
    echo "  ✅  All entropy levels are within normal ranges"
fi

# ── 10. VirusTotal ───────────────────────────────────────────────────────────────
VT_API_KEY="${VT_API_KEY:-}"
if [[ -n "$VT_API_KEY" ]]; then
    print_section "VirusTotal — Cloud Hash Reputation"
    echo "  → Querying SHA256: $FILESHA"
    VT_RESP=$(curl -s --max-time 15 -H "x-apikey: $VT_API_KEY" \
        "https://www.virustotal.com/api/v3/files/$FILESHA" 2>/dev/null)

    if [[ -z "$VT_RESP" ]]; then
        echo "  ⚠️  VirusTotal request failed (no response — check network)"
    else
        cat > /tmp/vt_parse.py << 'VTPY'
import sys, json

raw = sys.stdin.read()
try:
    d = json.loads(raw)
except Exception:
    print("STATUS:ERROR")
    print("  ⚠️  VirusTotal: invalid response (not JSON)")
    sys.exit(0)

# ── Handle API errors ──
err = d.get("error")
if err:
    code = err.get("code", "")
    msg  = err.get("message", "Unknown error")
    if code == "NotFoundError":
        print("STATUS:NOTFOUND")
        print("  ℹ️  Hash not found in VirusTotal (file never submitted)")
    elif code == "WrongCredentialsError":
        print("STATUS:ERROR")
        print("  ❌ VirusTotal: invalid API key")
    elif code == "QuotaExceededError":
        print("STATUS:ERROR")
        print("  ⚠️  VirusTotal: API quota exceeded (try again later)")
    elif code == "ForbiddenError":
        print("STATUS:ERROR")
        print("  ❌ VirusTotal: access forbidden (check API key permissions)")
    else:
        print("STATUS:ERROR")
        print(f"  ⚠️  VirusTotal API error: {code} — {msg}")
    sys.exit(0)

# ── Parse successful response ──
attrs = d.get("data", {}).get("attributes", {})
if not attrs:
    print("STATUS:ERROR")
    print("  ⚠️  VirusTotal: unexpected response format (no attributes)")
    sys.exit(0)

stats   = attrs.get("last_analysis_stats", {})
results = attrs.get("last_analysis_results", {})
sha256  = attrs.get("sha256", "")

mal     = stats.get("malicious", 0)
susp    = stats.get("suspicious", 0)
clean   = stats.get("harmless", 0) + stats.get("undetected", 0)
total   = sum(stats.values())

print(f"STATUS:OK:{mal}")

# ── Detection ratio ──
if mal > 0:
    print(f"  🔴 Detections  : {mal} / {total} engines flagged as MALICIOUS")
elif susp > 0:
    print(f"  🟡 Detections  : {susp} / {total} engines flagged as SUSPICIOUS")
else:
    print(f"  🟢 Detections  : 0 / {total} engines — clean")

# ── Threat classification ──
pop = attrs.get("popular_threat_classification", {})
label = pop.get("suggested_threat_label")
if label:
    print(f"  🏷️  Threat Label : {label}")

categories = pop.get("popular_threat_category", [])
if categories:
    cat_str = ", ".join(f'{c["value"]} ({c["count"]})' for c in categories[:5])
    print(f"  📂 Categories  : {cat_str}")

names = pop.get("popular_threat_name", [])
if names:
    name_str = ", ".join(f'{n["value"]} ({n["count"]})' for n in names[:5])
    print(f"  🔖 Threat Names: {name_str}")

# ── Community reputation ──
reputation = attrs.get("reputation")
if reputation is not None:
    if reputation < -10:
        rep_icon = "🔴"
    elif reputation < 0:
        rep_icon = "🟡"
    else:
        rep_icon = "🟢"
    print(f"  {rep_icon} Reputation  : {reputation}")

# ── Tags ──
tags = attrs.get("tags", [])
if tags:
    print(f"  🔗 Tags        : {', '.join(tags[:10])}")

# ── Detection engines detail ──
if mal > 0 or susp > 0:
    print()
    print("  ┌─────────────────────────────────────────────────────────┐")
    print("  │  Engine Detections                                     │")
    print("  └─────────────────────────────────────────────────────────┘")
    hits = [(k, v.get("result", "—")) for k, v in results.items()
            if v.get("category") in ("malicious", "suspicious")]
    for eng, result in sorted(hits, key=lambda x: x[0])[:15]:
        print(f"    ▸ {eng:<24} → {result}")
    if len(hits) > 15:
        print(f"    … and {len(hits) - 15} more engines")

# ── File type info ──
type_desc = attrs.get("type_description")
if type_desc:
    print(f"  📄 File Type   : {type_desc}")

# ── Link ──
if sha256:
    print(f"  🌐 VT Link     : https://www.virustotal.com/gui/file/{sha256}")
VTPY
        VT_PARSED=$(echo "$VT_RESP" | python3 /tmp/vt_parse.py 2>/dev/null)
        rm -f /tmp/vt_parse.py

        echo "$VT_PARSED" | tail -n +2

        # Extract malicious count from STATUS line
        VT_STATUS=$(echo "$VT_PARSED" | head -1)
        if [[ "$VT_STATUS" == STATUS:OK:* ]]; then
            MAL="${VT_STATUS##STATUS:OK:}"
            [[ "${MAL:-0}" -gt 0 ]] && add_risk 100 "VirusTotal: $MAL engines flagged as malicious"
        fi
    fi
fi

# ── 11. ClamAV ───────────────────────────────────────────────────────────────────
if command -v clamscan &>/dev/null; then
    CLAM_DB=$(find /var/lib/clamav -name "*.cvd" -o -name "*.cld" 2>/dev/null | head -1)
    if [[ -n "$CLAM_DB" ]]; then
        print_section "ClamAV — Antivirus Scan"
        CLAM_OUT=$(clamscan --no-summary "$FILE" 2>/dev/null)
        echo "$CLAM_OUT" | sed 's/^/  /'
        echo "$CLAM_OUT" | grep -qi "FOUND" && add_risk 100 "ClamAV: malware detected"
    fi
fi

# ── 12. strings ────────────────────────────────────────────────────────────
print_section "strings — Suspicious Pattern Search"

echo "  → JavaScript keywords:"
JS=$(strings "$FILE" | grep -iE "javascript|eval\(|unescape|fromcharcode|activex" 2>/dev/null | head -10)
[[ -n "$JS" ]] && { echo "$JS" | sed 's/^/    /'; add_risk 25 "strings: JavaScript keywords found"; } || echo "    (none found)"

echo ""
echo "  → External URLs:"
URLS=$(strings "$FILE" | grep -iE "https?://|ftp://" 2>/dev/null | grep -v "go.microsoft.com\|w3.org\|adobe.com" | head -10)
[[ -n "$URLS" ]] && { echo "$URLS" | sed 's/^/    /'; add_risk 5 "strings: external URLs found"; } || echo "    (none found)"

echo ""
echo "  → Shell / execution commands:"
CMDS=$(strings "$FILE" | grep -iE "/bin/sh|cmd\.exe|powershell|wget |curl " 2>/dev/null | head -10)
[[ -n "$CMDS" ]] && { echo "$CMDS" | sed 's/^/    /'; add_risk 50 "strings: shell/exec commands found"; } || echo "    (none found)"

echo ""
echo "  → Advanced IoC Extraction:"
IOCS=$(python3 -c "
import sys, re
data = sys.stdin.read()
emails = set(re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b', data))
emails = {e for e in emails if not re.search(r'@[0-9]+x\.', e)}
ips = set(re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', data))
btc = set(re.findall(r'\b(?:bc1|[13])[a-zA-HJ-NP-zA-HJ-NP-Z0-9]{25,39}\b', data))
for e in emails: print(f'    Email: {e}')
for i in ips:
    if not i.startswith(('127.', '10.', '192.168.', '172.', '0.')): print(f'    IP: {i}')
for b in btc: print(f'    BTC Wallet: {b}')
" <<< "$TEXT"$'\n'"$(strings \"$FILE\" 2>/dev/null)")
if [[ -n "$IOCS" ]]; then
    echo "$IOCS"
    add_risk 10 "Extracted Emails/IPs/Wallets"
else
    echo "    (none found)"
fi

echo ""
echo "  → Dangerous PDF keywords:"
DKWS=$(strings "$FILE" | grep -iE "launch|openaction|acroform|richmedia|embeddedfile|objstm" 2>/dev/null | head -10)
[[ -n "$DKWS" ]] && echo "$DKWS" | sed 's/^/    /' || echo "    (none found)"

# ── 9. Risk Summary ───────────────────────────────────────────────────────
print_banner "🛡️  Risk Assessment — $(basename "$FILE")"
echo ""

if [[ $RISK_SCORE -ge 80 ]]; then
    RISK_LEVEL="🔴 HIGH"
elif [[ $RISK_SCORE -ge 30 ]]; then
    RISK_LEVEL="🟡 MEDIUM"
else
    RISK_LEVEL="🟢 LOW"
fi

echo "  Risk Level : $RISK_LEVEL  (score: $RISK_SCORE)"
echo ""

if [[ ${#RISK_FINDINGS[@]} -gt 0 ]]; then
    echo "  Findings:"
    for f in "${RISK_FINDINGS[@]}"; do
        echo "    • $f"
    done
else
    echo "  No suspicious indicators detected."
fi

echo ""

# ── JSON Output ───────────────────────────────────────────────────────────────
if [[ "$JSON_OUTPUT" == true ]]; then
    JSON_FILE="/data/$(basename "${FILE%.pdf}").report.json"
    FINDINGS_JSON=$(printf '%s\n' "${RISK_FINDINGS[@]}" | python3 -c "
import sys, json
lines = [l.strip() for l in sys.stdin if l.strip()]
print(json.dumps(lines))
")
    python3 -c "
import sys, json
data = {
  'file': sys.argv[1],
  'sha256': sys.argv[2],
  'risk_score': int(sys.argv[3]),
  'risk_level': sys.argv[4].replace('🔴 ','').replace('🟡 ','').replace('🟢 ',''),
  'findings': json.loads(sys.argv[5]),
  'encrypted': sys.argv[6] == 'yes',
  'cracked_password': sys.argv[7] if sys.argv[7] else None,
}
print(json.dumps(data, indent=2))
" "$(basename "$FILE")" "$FILESHA" "$RISK_SCORE" "$RISK_LEVEL" "$FINDINGS_JSON" "${ENCRYPTED:-no}" "${CRACKED_PASSWORD:-}" > "$JSON_FILE"
    echo "  📄 JSON report saved: $(basename "$JSON_FILE")"
fi

# ── MISP Output ───────────────────────────────────────────────────────────────
if [[ "$MISP_OUTPUT" == true ]]; then
    MISP_FILE="/data/$(basename "${FILE%.pdf}").misp.json"
    python3 -c "
import sys, json, uuid, datetime
event = {
    'Event': {
        'uuid': str(uuid.uuid4()),
        'info': f'PDFAnalyzer detection: {sys.argv[1]}',
        'date': str(datetime.date.today()),
        'timestamp': str(int(datetime.datetime.now().timestamp())),
        'Attribute': [
            {'type': 'sha256', 'value': sys.argv[2], 'to_ids': True},
            {'type': 'filename', 'value': sys.argv[1], 'to_ids': False}
        ]
    }
}
print(json.dumps(event, indent=2))
" "$(basename "$FILE")" "$FILESHA" > "$MISP_FILE"
    echo "  📄 MISP report saved: $(basename "$MISP_FILE")"
fi
