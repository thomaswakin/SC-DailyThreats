"""Send the daily briefing as an HTML email via standard SMTP."""

from __future__ import annotations
import getpass
import io
import logging
import os
import smtplib
import ssl
import zipfile
from datetime import datetime, timezone
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

import keyring
import markdown as md

from threats.models import DailyBriefing
from threats.models.briefing import SigmaRule

log = logging.getLogger(__name__)

_KEYCHAIN_SERVICE = "threats-daily-briefing"


def _get_credential(env_var: str, keychain_key: str) -> str:
    """Check env var first (CI/override), then macOS Keychain."""
    return os.getenv(env_var) or keyring.get_password(_KEYCHAIN_SERVICE, keychain_key) or ""


def setup_email_credentials() -> None:
    """Interactive prompt to store SMTP credentials in macOS Keychain."""
    print("Store SMTP credentials in macOS Keychain (encrypted, no files written)\n")
    print("Brevo:   smtp-relay.brevo.com  port 587  (user = your email, password = SMTP key from Brevo dashboard)")
    print("Mailjet: in-v3.mailjet.com     port 587  (user = API key, password = secret key)")
    print()
    host     = input("SMTP host: ").strip()
    port     = input("SMTP port [587]: ").strip() or "587"
    user     = input("SMTP username: ").strip()
    password = getpass.getpass("SMTP password / key: ")
    from_addr = input(f"From address [{user}]: ").strip() or user

    keyring.set_password(_KEYCHAIN_SERVICE, "host", host)
    keyring.set_password(_KEYCHAIN_SERVICE, "port", port)
    keyring.set_password(_KEYCHAIN_SERVICE, "user", user)
    keyring.set_password(_KEYCHAIN_SERVICE, "password", password)
    keyring.set_password(_KEYCHAIN_SERVICE, "from", from_addr)
    print("\nCredentials saved to macOS Keychain. No secrets written to disk.")


def _smtp_credentials(email_cfg: dict) -> tuple[str, str, str, int, str]:
    """Return (host, user, password, port, from_addr) from Keychain/env."""
    host     = _get_credential("SMTP_HOST",     "host")
    user     = _get_credential("SMTP_USER",     "user")
    password = _get_credential("SMTP_PASSWORD", "password")
    port     = int(_get_credential("SMTP_PORT", "port") or email_cfg.get("smtp_port", 587))
    from_addr = _get_credential("SMTP_FROM", "from") or user
    return host, user, password, port, from_addr


def _recipients(email_cfg: dict) -> list[str]:
    r = email_cfg.get("to", [])
    return [r] if isinstance(r, str) else r


def _cc_recipients(email_cfg: dict) -> list[str]:
    r = email_cfg.get("cc", [])
    return [r] if isinstance(r, str) else r


def _zip_sigma_rules(sigma_dir: Path) -> bytes | None:
    """Create an in-memory ZIP of all YAML files in sigma_dir. Returns None if empty."""
    yaml_files = list(sigma_dir.glob("*.yaml")) if sigma_dir.exists() else []
    if not yaml_files:
        return None
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for f in sorted(yaml_files):
            zf.write(f, f.name)
    return buf.getvalue()


_FP_RISK_COLORS = {"low": "#2e7d32", "medium": "#e65100", "high": "#c62828"}


def _sigma_html_section(rules: list[SigmaRule]) -> str:
    """Build HTML for the Sigma rules summary section (no raw IOC values)."""
    if not rules:
        return ""

    rows = []
    for rule in rules:
        logsource = f"{rule.logsource.get('category', '')} / {rule.logsource.get('product', '—')}"
        fp_risk = rule.fp_risk or "—"
        fp_color = _FP_RISK_COLORS.get(rule.fp_risk, "#555")
        expiry = f"{rule.expiry_days}d" if rule.expiry_days else "none"
        fp_notes_td = (
            f"<br><small style='color:#666'><em>{rule.fp_notes[:160]}</em></small>"
            if rule.fp_notes else ""
        )
        rows.append(
            f"<tr>"
            f"<td><strong>{rule.title}</strong>{fp_notes_td}</td>"
            f"<td><code>{rule.level}</code></td>"
            f"<td><span style='color:{fp_color};font-weight:bold'>{fp_risk}</span></td>"
            f"<td>{expiry}</td>"
            f"<td>{rule.description[:120]}{'…' if len(rule.description) > 120 else ''}</td>"
            f"</tr>"
        )

    return f"""
<h2>Generated Sigma Detection Rules ({len(rules)})</h2>
<p><em>Full YAML rule files are attached as a ZIP. Rules have been reviewed for false positive
risk. FP Risk: <span style='color:#2e7d32'>low</span> /
<span style='color:#e65100'>medium</span> /
<span style='color:#c62828'>high</span> — review high-risk rules carefully before deploying.</em></p>
<table>
<thead><tr><th>Rule</th><th>Level</th><th>FP Risk</th><th>Expiry</th><th>Description</th></tr></thead>
<tbody>{"".join(rows)}</tbody>
</table>
"""


def _sigma_plain_section(rules: list[SigmaRule]) -> str:
    if not rules:
        return ""
    lines = [f"\n\nGenerated Sigma Detection Rules ({len(rules)})", "-" * 60]
    for rule in rules:
        logsource = f"{rule.logsource.get('category', '')} / {rule.logsource.get('product', '—')}"
        expiry = f"expires in {rule.expiry_days}d" if rule.expiry_days else "no expiry"
        fp_risk = f"FP:{rule.fp_risk}" if rule.fp_risk else ""
        lines.append(f"  [{rule.level.upper()}] {rule.title}  {fp_risk}  {expiry}")
        lines.append(f"    Logsource: {logsource}")
        lines.append(f"    {rule.description[:120]}")
        if rule.fp_notes:
            lines.append(f"    FP notes: {rule.fp_notes[:120]}")
        lines.append("")
    lines.append("Full YAML rule files are attached as sigma_rules.zip")
    return "\n".join(lines)


def _send_via_smtp(msg: MIMEMultipart, from_addr: str, recipients: list[str],
                   host: str, port: int, user: str, password: str) -> bool:
    try:
        context = ssl.create_default_context()
        with smtplib.SMTP(host, port, timeout=30) as server:
            server.ehlo()
            server.starttls(context=context)
            server.login(user, password)
            server.sendmail(from_addr, recipients, msg.as_string())
        log.info("Email sent to %s via %s", recipients, host)
        return True
    except Exception as exc:
        log.error("Failed to send email: %s", exc)
        return False


def send_briefing_email(
    briefing: DailyBriefing,
    md_path: Path,
    cfg: dict,
    sigma_dir: Path | None = None,
) -> bool:
    """
    Send the daily briefing as an HTML email with optional Sigma ZIP attachment.
    Credentials are read from macOS Keychain (set via --setup-email).
    Env vars SMTP_HOST/USER/PASSWORD/PORT/FROM override Keychain for CI use.
    Returns True on success, False on failure (non-blocking).
    """
    email_cfg = cfg.get("email", {})
    recipients = _recipients(email_cfg)
    if not recipients:
        log.warning("Email: no recipients configured — skipping")
        return False

    host, user, password, port, from_addr = _smtp_credentials(email_cfg)
    if not (host and user and password):
        log.warning("Email: SMTP credentials not found. Run: threats-cli --setup-email")
        return False

    cc = _cc_recipients(email_cfg)

    critical_count = len(briefing.critical_items) + len(briefing.multi_source_clusters)
    urgency = "🔴 CRITICAL — " if critical_count else ""
    subject = (
        f"{email_cfg.get('subject_prefix', '[ThreatIntel]')} {urgency}"
        f"Briefing {briefing.briefing_date} | "
        f"{len(briefing.items)} items · "
        f"{len(briefing.new_ttps)} new TTPs · "
        f"{len(briefing.sigma_rules)} Sigma rules"
    )

    raw_md = md_path.read_text(encoding="utf-8")
    html_body = md.markdown(raw_md, extensions=["tables", "fenced_code", "nl2br"])
    sigma_html = _sigma_html_section(briefing.sigma_rules)
    sigma_plain = _sigma_plain_section(briefing.sigma_rules)

    # Insert Sigma section before the footer line
    if sigma_html and "</body>" in html_body:
        html_body = html_body.replace("</body>", sigma_html + "</body>")
    elif sigma_html:
        html_body += sigma_html

    html_full = _HTML_WRAPPER.format(content=html_body)

    msg = MIMEMultipart("mixed")
    msg["Subject"] = subject
    msg["From"]    = from_addr
    msg["To"]      = ", ".join(recipients)
    if cc:
        msg["Cc"]  = ", ".join(cc)

    alt = MIMEMultipart("alternative")
    alt.attach(MIMEText(raw_md + sigma_plain, "plain", "utf-8"))
    alt.attach(MIMEText(html_full,            "html",  "utf-8"))
    msg.attach(alt)

    # Attach Sigma ZIP if rules exist
    if sigma_dir and briefing.sigma_rules:
        zip_bytes = _zip_sigma_rules(sigma_dir)
        if zip_bytes:
            zip_name = f"sigma_rules_{briefing.briefing_date}.zip"
            attachment = MIMEApplication(zip_bytes, _subtype="zip")
            attachment.add_header("Content-Disposition", "attachment", filename=zip_name)
            msg.attach(attachment)
            log.info("Attached %d Sigma rules as %s", len(briefing.sigma_rules), zip_name)

    # Attach IOC export ZIP if present
    if briefing.ioc_export_path:
        from pathlib import Path as _Path
        ioc_zip_path = _Path(briefing.ioc_export_path)
        if ioc_zip_path.exists():
            ioc_zip_bytes = ioc_zip_path.read_bytes()
            ioc_zip_name = ioc_zip_path.name
            ioc_attachment = MIMEApplication(ioc_zip_bytes, _subtype="zip")
            ioc_attachment.add_header("Content-Disposition", "attachment", filename=ioc_zip_name)
            msg.attach(ioc_attachment)
            log.info("Attached IOC export as %s", ioc_zip_name)

    return _send_via_smtp(msg, from_addr, recipients + cc, host, port, user, password)


def send_no_data_email(briefing: DailyBriefing, cfg: dict, last_run_at: datetime | None) -> bool:
    """Send a brief 'no new threat data' notification email."""
    email_cfg = cfg.get("email", {})
    recipients = _recipients(email_cfg)
    if not recipients:
        return False

    host, user, password, port, from_addr = _smtp_credentials(email_cfg)
    if not (host and user and password):
        log.warning("Email: SMTP credentials not found. Run: threats-cli --setup-email")
        return False

    cc = _cc_recipients(email_cfg)

    since_str = last_run_at.strftime("%Y-%m-%d %H:%M UTC") if last_run_at else "last run"
    subject = (
        f"{email_cfg.get('subject_prefix', '[ThreatIntel]')} "
        f"No New Threat Data | {briefing.briefing_date}"
    )
    plain = (
        f"Daily Threat Intel — {briefing.briefing_date}\n\n"
        f"No new threat intelligence has been collected since {since_str}.\n"
        f"The pipeline ran successfully. Nothing to report at this time.\n\n"
        f"-- Daily Threat Intel"
    )
    html_full = _HTML_WRAPPER.format(content=f"""
<h1>Daily Threat Intelligence Briefing</h1>
<h2>{briefing.briefing_date} — No New Threat Data</h2>
<p>No new threat intelligence has been collected since <strong>{since_str}</strong>.</p>
<p>The pipeline ran successfully. Nothing to report at this time.</p>
""")

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = from_addr
    msg["To"]      = ", ".join(recipients)
    if cc:
        msg["Cc"]  = ", ".join(cc)
    msg.attach(MIMEText(plain,    "plain", "utf-8"))
    msg.attach(MIMEText(html_full, "html", "utf-8"))

    return _send_via_smtp(msg, from_addr, recipients + cc, host, port, user, password)


_HTML_WRAPPER = """\
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
         font-size: 14px; line-height: 1.6; color: #1a1a2e; max-width: 860px;
         margin: 0 auto; padding: 24px; background: #f5f5f5; }}
  .card {{ background: #fff; border-radius: 8px; padding: 24px 32px;
           margin-bottom: 24px; box-shadow: 0 1px 4px rgba(0,0,0,.08); }}
  h1 {{ color: #0f3460; border-bottom: 3px solid #e94560; padding-bottom: 8px; }}
  h2 {{ color: #16213e; border-left: 4px solid #e94560; padding-left: 10px;
        margin-top: 32px; }}
  h3 {{ color: #0f3460; }}
  h4 {{ color: #333; margin-bottom: 4px; }}
  table {{ border-collapse: collapse; width: 100%; margin: 12px 0; }}
  th {{ background: #16213e; color: #fff; padding: 8px 12px; text-align: left; }}
  td {{ padding: 7px 12px; border-bottom: 1px solid #eee; }}
  tr:nth-child(even) {{ background: #f9f9f9; }}
  code {{ background: #f0f0f0; padding: 2px 6px; border-radius: 3px;
          font-family: 'SF Mono', Consolas, monospace; font-size: 12px; }}
  pre code {{ display: block; padding: 12px; overflow-x: auto; }}
  blockquote {{ border-left: 4px solid #e94560; margin: 12px 0;
                padding: 8px 16px; background: #fff8f8; color: #444; }}
  a {{ color: #0f3460; }}
  hr {{ border: none; border-top: 1px solid #eee; margin: 24px 0; }}
  .footer {{ color: #888; font-size: 12px; text-align: center; margin-top: 32px; }}
</style>
</head>
<body>
<div class="card">
{content}
</div>
<p class="footer">Daily Threat Intel · MITRE ATT&amp;CK® is a trademark of The MITRE Corporation</p>
</body>
</html>
"""
