"""Periodic security telemetry ingestion entry point."""

import json
import logging
import sys

from . import device_egress_store, security_store, vulnerabilities


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    failed = False
    # The sources are independent, so one failing does not hold back the others.
    for name, collect in (("security", security_store.collect), ("vulnerability", vulnerabilities.collect),
                          ("device egress", device_egress_store.collect)):
        try:
            result = collect()
        except Exception:
            logging.exception("%s collection failed", name)
            failed = True
        else:
            logging.info("%s collection complete: %s", name, json.dumps(result, sort_keys=True))
    if failed:
        sys.exit(1)


if __name__ == "__main__":
    main()
