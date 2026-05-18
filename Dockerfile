# ─── Stage 1: Builder ─────────────────────────────────────────────────────
# Compiles C extensions: Pillow 3.2.0 (required by peepdf) and yara-python
FROM python:3.11-slim-bookworm AS builder

RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libjpeg-dev zlib1g-dev && \
    rm -rf /var/lib/apt/lists/*

# Build binary wheels so the runtime stage needs no compiler
RUN pip wheel --no-cache-dir --wheel-dir /wheels Pillow==3.2.0 yara-python

# ─── Stage 2: Runtime ─────────────────────────────────────────────────────
FROM python:3.11-slim-bookworm

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    wget \
    curl \
    ca-certificates \
    libimage-exiftool-perl \
    poppler-utils \
    qpdf \
    binutils \
    file \
    pdfcrack \
    john \
    tesseract-ocr \
    tesseract-ocr-eng \
    clamav \
    zbar-tools \
    jq \
    libjpeg62-turbo && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /wheels /wheels

RUN pip install --no-cache-dir --no-index --find-links /wheels Pillow==3.2.0 yara-python && \
    pip install --no-cache-dir jsbeautifier colorama future pythonaes six && \
    pip install --no-cache-dir peepdf --no-deps && \
    pip install --no-cache-dir pdfminer.six && \
    rm -rf /wheels

RUN mkdir -p /opt/pdftools && \
    wget -q "https://raw.githubusercontent.com/DidierStevens/DidierStevensSuite/master/pdfid.py" \
    -O /opt/pdftools/pdfid.py && \
    wget -q "https://raw.githubusercontent.com/DidierStevens/DidierStevensSuite/master/pdf-parser.py" \
    -O /opt/pdftools/pdf-parser.py && \
    wget -q "https://raw.githubusercontent.com/openwall/john/bleeding-jumbo/run/pdf2john.py" \
    -O /opt/pdf2john.py && \
    chmod +x /opt/pdf2john.py

RUN mkdir -p /opt/yara-rules
COPY pdf.yar /opt/yara-rules/pdf.yar

COPY analyze.sh /opt/analyze.sh
COPY entrypoint.sh /opt/entrypoint.sh

RUN chmod +x /opt/analyze.sh /opt/entrypoint.sh && \
    mkdir -p /var/lib/clamav

VOLUME ["/var/lib/clamav"]
WORKDIR /data

ENTRYPOINT ["/opt/entrypoint.sh"]
CMD ["--help"]