import logging
import sys

logger = logging.getLogger("hantong")


def setup_logging(level: str) -> None:
    # The container filesystem is read-only; Docker collects stdout.
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s - %(levelname)s - %(name)s - %(message)s",
        stream=sys.stdout,
    )
