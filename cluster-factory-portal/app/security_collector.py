"""Periodic security telemetry ingestion entry point."""

import json
import logging

from . import security_store


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    result = security_store.collect()
    logging.info("security collection complete: %s", json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
