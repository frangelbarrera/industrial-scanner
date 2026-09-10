# Docker image for IndustrialScanner
# Multi-stage build: builder stage installs deps, runtime stage is minimal.
FROM python:3.12-slim AS builder

# scapy requires libpcap-dev for live capture support
RUN apt-get update \
    && apt-get install -y --no-install-recommends libpcap-dev gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY pyproject.toml README.md ./
COPY modbus_scanner/ ./modbus_scanner/
COPY s7_comm_analyzer/ ./s7_comm_analyzer/
COPY dnp3_monitor/ ./dnp3_monitor/
COPY ics_scanner/ ./ics_scanner/
COPY reports/templates/ ./reports/templates/

RUN python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir build \
    && python -m build \
    && python -m pip install --no-cache-dir dist/*.whl

# Runtime stage: slim image with only runtime deps
FROM python:3.12-slim AS runtime

# libpcap0.8 is the runtime lib for scapy (no -dev needed)
RUN apt-get update \
    && apt-get install -y --no-install-recommends libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

# The analyzer must not run as root when processing untrusted PCAPs.
RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin scanner

# Copy installed packages from builder
COPY --from=builder /usr/local/lib/python3.12/site-packages/ /usr/local/lib/python3.12/site-packages/
COPY --from=builder /usr/local/bin/industrial-scanner /usr/local/bin/industrial-scanner

# Copy HTML templates (not bundled in the wheel, needed at runtime for report rendering)
COPY reports/templates/ /app/reports/templates/

# Set working directory and ownership so the unprivileged process can write reports.
RUN mkdir -p /work /app/reports \
    && chown -R scanner:scanner /work /app
WORKDIR /app
ENV PYTHONPATH=/app
VOLUME ["/work"]
USER scanner

# Default entry: show help
ENTRYPOINT ["industrial-scanner"]
CMD ["--help"]
