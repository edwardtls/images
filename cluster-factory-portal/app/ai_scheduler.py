"""Schedule entry points for daily startup, deadline enforcement, and hard stop."""

from __future__ import annotations

import datetime as dt
from email.message import EmailMessage
import os
import smtplib
import sys

from . import ai_control


def _email(subject: str, body: str) -> None:
    username = os.getenv("SMTP_USERNAME")
    password = os.getenv("SMTP_PASSWORD")
    recipient = os.getenv("CONTACT_RECIPIENT") or username
    if not all((username, password, recipient)):
        return
    message = EmailMessage()
    message["Subject"], message["From"], message["To"] = subject, username, recipient
    message.set_content(body)
    with smtplib.SMTP(os.getenv("SMTP_HOST", "smtp.gmail.com"), int(os.getenv("SMTP_PORT", "587")), timeout=30) as smtp:
        smtp.starttls(); smtp.login(username, password); smtp.send_message(message)


def _deadline(value: str | None) -> dt.datetime | None:
    return dt.datetime.fromisoformat(value) if value else None


def daily_start() -> None:
    current = ai_control.status()
    if current["mode"] != "off":
        _email("D00S AI daily scan skipped", f"The 06:00 scan was skipped because mode {current['mode']} is already active.")
        return
    ai_control.start("daily", 3, True)


def enforce() -> None:
    state = ai_control._state()
    deadline = _deadline(state.get("deadline"))
    if state.get("mode") == "off" or not deadline or dt.datetime.now(dt.timezone.utc) < deadline:
        return
    active = ai_control._active_jobs()
    if state.get("mode") == "daily" and active and int(state.get("extensions", 0)) < 1:
        extended = dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=1)
        ai_control._write_state({"deadline": extended.isoformat(), "extensions": 1})
        _email("D00S AI run extended by one hour",
               f"The 06:00 remediation job is still active. Shutdown was extended once, until {extended.isoformat()}.")
        return
    previous = state.get("last_run") or {}
    ai_control.stop()
    _email("D00S AI deadline shutdown",
           f"Mode {state.get('mode')} reached its deadline and was stopped. Last run state: {previous.get('state', 'unknown')}.")


def hard_stop() -> None:
    state = ai_control._state()
    ai_control.stop()
    if state.get("mode") != "off":
        _email("D00S AI nightly shutdown", f"The mandatory 23:00 shutdown stopped mode {state.get('mode')}.")


def main() -> None:
    action = sys.argv[1] if len(sys.argv) > 1 else "enforce"
    {"daily-start": daily_start, "enforce": enforce, "hard-stop": hard_stop}[action]()


if __name__ == "__main__":
    main()
