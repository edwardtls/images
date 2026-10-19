"""Trusted in-cluster dispatcher kept separate from the public web identity."""

import logging
import time

from . import kube


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    while True:
        try:
            kube.dispatch_pending()
            kube.reconcile()
        except Exception:
            logging.exception("factory dispatch loop failed")
        time.sleep(3)


if __name__ == "__main__":
    main()
