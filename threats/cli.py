"""CLI entry point: threats-cli"""

import argparse
import sys
from datetime import date


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Daily Threat Intelligence — briefing and Sigma rule generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  threats-cli --run-now                     # Run pipeline for today
  threats-cli --run-date 2026-03-09         # Re-run for a specific date
  threats-cli --daemon                      # Start scheduled daemon (runs daily at configured time)
  threats-cli --status                      # Show last 5 run statuses
""",
    )
    parser.add_argument("--run-now", action="store_true", help="Run the full pipeline immediately")
    parser.add_argument("--run-date", metavar="YYYY-MM-DD", help="Run pipeline for a specific date")
    parser.add_argument("--daemon", action="store_true", help="Start the daily scheduler daemon")
    parser.add_argument("--status", action="store_true", help="Print recent run log")
    parser.add_argument("--settings", default="config/settings.yaml", help="Path to settings.yaml")
    parser.add_argument("--feeds", default="config/feeds.yaml", help="Path to feeds.yaml")
    parser.add_argument("--no-llm", action="store_true", help="Disable LLM enrichment for this run")
    parser.add_argument("--setup-email", action="store_true", help="Store SMTP credentials in macOS Keychain")
    parser.add_argument("--test-email", action="store_true", help="Send a test email using stored credentials")
    args = parser.parse_args()

    if args.setup_email:
        from threats.generators.emailer import setup_email_credentials
        setup_email_credentials()
        return

    if args.test_email:
        _send_test_email(args.settings)
        return

    if args.no_llm:
        import os
        os.environ["ANTHROPIC_API_KEY"] = ""

    if args.run_now or args.run_date:
        from threats.pipeline import run_pipeline_full
        run_date = None
        if args.run_date:
            run_date = date.fromisoformat(args.run_date)
        stats = run_pipeline_full(
            briefing_date=run_date,
            settings_path=args.settings,
            feeds_path=args.feeds,
        )
        print(f"\nPipeline complete:")
        print(f"  Collected : {stats.get('collected', 0)}")
        print(f"  Stored    : {stats.get('stored', 0)}")
        print(f"  IOCs      : {stats.get('iocs', 0)}")
        print(f"  Sigma     : {stats.get('sigma', 0)}")
        if stats.get("briefing_path"):
            print(f"  Briefing  : {stats['briefing_path']}")

    elif args.daemon:
        import yaml
        with open(args.settings) as f:
            cfg = yaml.safe_load(f)
        run_at = cfg.get("pipeline", {}).get("run_at", "06:00")
        from threats.scheduler import start_scheduler
        start_scheduler(run_at)

    elif args.status:
        _print_status(args.settings)

    else:
        parser.print_help()
        sys.exit(1)


def _print_status(settings_path: str) -> None:
    import yaml
    with open(settings_path) as f:
        cfg = yaml.safe_load(f)
    db_path = cfg["storage"]["db_path"]

    from threats.storage import Database
    db = Database(db_path)
    try:
        db.connect()
        rows = db.conn.execute(
            "SELECT * FROM run_log ORDER BY id DESC LIMIT 10"
        ).fetchall()
        if not rows:
            print("No runs recorded yet.")
            return
        print(f"{'Date':<12} {'Status':<10} {'Collected':>10} {'Stored':>8} {'IOCs':>6} {'Sigma':>6} {'Duration'}")
        print("-" * 75)
        for r in rows:
            dur = ""
            if r["finished_at"] and r["started_at"]:
                from datetime import datetime
                start = datetime.fromisoformat(r["started_at"])
                end = datetime.fromisoformat(r["finished_at"])
                secs = int((end - start).total_seconds())
                dur = f"{secs}s"
            print(
                f"{r['run_date']:<12} {r['status']:<10} {r['items_collected']:>10} "
                f"{r['items_stored']:>8} {r['iocs_found']:>6} {r['sigma_generated']:>6} {dur}"
            )
    finally:
        db.close()


def _send_test_email(settings_path: str) -> None:
    import smtplib, ssl, yaml
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText
    from threats.generators.emailer import _get_credential

    with open(settings_path) as f:
        cfg = yaml.safe_load(f)

    email_cfg = cfg.get("email", {})
    recipients = email_cfg.get("to", [])
    if isinstance(recipients, str):
        recipients = [recipients]

    host     = _get_credential("SMTP_HOST",     "host")
    user     = _get_credential("SMTP_USER",     "user")
    password = _get_credential("SMTP_PASSWORD", "password")

    if not (host and user and password):
        print("No credentials found. Run: threats-cli --setup-email")
        return

    port      = int(_get_credential("SMTP_PORT", "port") or email_cfg.get("smtp_port", 587))
    from_addr = _get_credential("SMTP_FROM", "from") or user

    print(f"Sending test email...")
    print(f"  From : {from_addr}")
    print(f"  To   : {', '.join(recipients)}")
    print(f"  Via  : {host}:{port}")

    msg = MIMEMultipart("alternative")
    msg["Subject"] = "[ThreatIntel] Test Email — delivery check"
    msg["From"]    = from_addr
    msg["To"]      = ", ".join(recipients)
    msg.attach(MIMEText(
        "Daily Threat Intel — Test Email\n\nSMTP is configured correctly. "
        "You will receive the daily briefing at 06:00 each morning.",
        "plain", "utf-8",
    ))
    msg.attach(MIMEText(
        "<h2>Daily Threat Intel — Test Email</h2>"
        "<p>SMTP is configured correctly. "
        "You will receive the daily briefing at 06:00 each morning.</p>",
        "html", "utf-8",
    ))

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP(host, port, timeout=15) as server:
            server.ehlo()
            server.starttls(context=context)
            server.login(user, password)
            server.sendmail(from_addr, recipients, msg.as_string())
        print("✓ Test email sent successfully.")
    except Exception as exc:
        print(f"✗ Failed: {exc}")


if __name__ == "__main__":
    main()
