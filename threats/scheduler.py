"""Daily job scheduler."""

import logging
import schedule
import time

from threats.pipeline import run_pipeline_full

log = logging.getLogger(__name__)


def start_scheduler(run_at: str = "06:00") -> None:
    """Register and run the daily pipeline job indefinitely."""
    log.info("Scheduler starting — daily run at %s", run_at)
    schedule.every().day.at(run_at).do(_run_job)

    while True:
        schedule.run_pending()
        time.sleep(30)


def _run_job() -> None:
    log.info("Scheduled daily run triggered")
    try:
        run_pipeline_full()
    except Exception as exc:
        log.error("Pipeline run failed: %s", exc, exc_info=True)
