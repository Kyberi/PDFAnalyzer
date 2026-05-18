#!/bin/bash

# ── Short-circuit for help / no args ─────────────────────────────────────
if [[ -z "$1" || "$1" == "--help" || "$1" == "-h" ]]; then
    exec /opt/analyze.sh "$@"
fi

# ── ClamAV Database Check ─────────────────────────────────────────────────
CLAM_DIR="/var/lib/clamav"
CLAM_STAMP="$CLAM_DIR/.last_update"

# Check if DB files exist at all
if [[ ! -f "$CLAM_DIR/main.cvd" && ! -f "$CLAM_DIR/main.cld" &&
      ! -f "$CLAM_DIR/daily.cvd" && ! -f "$CLAM_DIR/daily.cld" ]]; then
    echo ""
    echo "  [ClamAV] ⬇️  Virus database not found. Downloading (~300MB)..."
    echo "  [ClamAV]    Tip: mount a volume to cache this permanently:"
    echo "  [ClamAV]    -v clamav_db:/var/lib/clamav"
    echo ""
    mkdir -p "$CLAM_DIR"
    freshclam --quiet 2>/dev/null && touch "$CLAM_STAMP" || echo "  [ClamAV] ⚠️  Download failed — skipping AV scan"

# Check if DB is older than 7 days
elif [[ -f "$CLAM_STAMP" ]] && find "$CLAM_STAMP" -mtime +7 | grep -q .; then
    echo ""
    echo "  [ClamAV] 🔄 Database older than 7 days — updating in background..."
    freshclam --quiet 2>/dev/null && touch "$CLAM_STAMP" &
    disown

# DB exists but no stamp (first run with mounted volume)
elif [[ ! -f "$CLAM_STAMP" ]]; then
    touch "$CLAM_STAMP"
fi

# ── Run the analyzer ──────────────────────────────────────────────────────
exec /opt/analyze.sh "$@"
