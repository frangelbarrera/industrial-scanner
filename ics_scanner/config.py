"""Configuration management for IndustrialScanner.

Uses pydantic-settings to load configuration from environment variables
with type validation and defaults.
"""

from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class ScannerConfig(BaseSettings):
    """Configuration for IndustrialScanner, loaded from environment.

    All settings have sensible defaults. Override by setting environment
    variables (e.g., INDUSTRIALSCANNER_LOG_LEVEL=DEBUG) or by copying
    .env.example to .env.
    """

    model_config = SettingsConfigDict(
        env_prefix="INDUSTRIALSCANNER_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Logging
    log_level: str = Field(default="INFO", description="Log level (DEBUG, INFO, WARNING, ERROR)")

    # Modbus scanner defaults
    modbus_default_port: int = Field(default=502, description="Default Modbus/TCP port")
    modbus_default_unit: int = Field(default=1, description="Default Modbus Unit ID")
    modbus_timeout: float = Field(default=2.0, description="Socket timeout in seconds")
    modbus_max_concurrency: int = Field(default=8, description="Max hosts scanned in parallel")

    # S7Comm analyzer defaults
    s7_default_port: int = Field(default=102, description="Default S7Comm TCP port")

    # DNP3 analyzer defaults
    dnp3_default_port: int = Field(default=20000, description="Default DNP3 TCP/UDP port")

    # Reports
    reports_dir: str = Field(default="reports", description="Output root for reports")
    report_html: bool = Field(default=True, description="Render HTML reports")
    report_json: bool = Field(default=True, description="Render JSON reports")

    # Security
    sanitize_html: bool = Field(
        default=True, description="Escape all user-controlled bytes in HTML"
    )
    allowed_targets: str = Field(
        default="",
        description="CSV of allowed IPs/CIDRs for active scans (empty = unrestricted within policy)",
    )

    # SIEM forwarding (optional)
    syslog_host: str | None = Field(default=None, description="Syslog host for SIEM forwarding")
    syslog_port: int = Field(default=514, description="Syslog port")
    syslog_protocol: str = Field(default="udp", description="Syslog protocol (udp or tcp)")


def load_config() -> ScannerConfig:
    """Load and return the scanner configuration.

    Reads from environment variables and .env file if present.
    """
    return ScannerConfig()
