#!/usr/bin/env python3
"""Small fixed-inventory Prometheus exporter for Tasmota power outlets."""

from __future__ import annotations

import concurrent.futures
import html
import ipaddress
import json
import logging
import os
import re
import time
import urllib.error
import urllib.request
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


LOG = logging.getLogger("refoss-exporter")
ROW_RE = re.compile(r"\{s\}(.*?)\{m\}(.*?)\{e\}", re.DOTALL)
TAG_RE = re.compile(r"<[^>]+>")
NUMBER_RE = re.compile(r"[-+]?(?:\d+(?:\.\d*)?|\.\d+)")

KNOWN_METRICS = {
    "voltage": ("tasmota_voltage_V", "gauge", "Outlet voltage"),
    "current": ("tasmota_current_A", "gauge", "Outlet current"),
    "active power": ("tasmota_active_power_W", "gauge", "Active power"),
    "apparent power": ("tasmota_apparent_power_VA", "gauge", "Apparent power"),
    "reactive power": ("tasmota_reactive_power_VAr", "gauge", "Reactive power"),
    "power factor": ("tasmota_power_factor", "gauge", "Power factor"),
    "energy today": ("tasmota_energy_today_kWh_total", "gauge", "Energy used today"),
    "energy yesterday": ("tasmota_energy_yesterday_kWh_total", "gauge", "Energy used yesterday"),
    "energy total": ("tasmota_energy_kWh_total", "counter", "Lifetime energy counter"),
    "temperature": ("tasmota_temperature_C", "gauge", "Outlet temperature"),
}


def load_devices() -> list[dict[str, str]]:
    raw = os.environ.get("DEVICES_JSON", "")
    try:
        devices = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"DEVICES_JSON is not valid JSON: {exc}") from exc
    if not isinstance(devices, list) or not devices:
        raise SystemExit("DEVICES_JSON must be a non-empty list")

    names: set[str] = set()
    validated: list[dict[str, str]] = []
    for item in devices:
        if not isinstance(item, dict):
            raise SystemExit("each device must be an object")
        name = str(item.get("name", "")).strip()
        address = str(item.get("ip", "")).strip()
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", name):
            raise SystemExit(f"invalid device name: {name!r}")
        try:
            parsed_address = ipaddress.ip_address(address)
        except ValueError as exc:
            raise SystemExit(f"invalid address for {name}: {address!r}") from exc
        if not parsed_address.is_private:
            raise SystemExit(f"device {name} must use a private address")
        if name in names:
            raise SystemExit(f"duplicate device name: {name}")
        names.add(name)
        validated.append({"name": name, "ip": address})
    return validated


def clean_text(value: str) -> str:
    value = value.replace("</td><td style='text-align:left'>", " ")
    value = value.replace("</td><td>&nbsp;</td><td>", " ")
    return " ".join(html.unescape(TAG_RE.sub(" ", value)).split())


def parse_page(page: str) -> dict[str, float]:
    values: dict[str, float] = {}
    for raw_label, raw_value in ROW_RE.findall(page):
        label = clean_text(raw_label).lower()
        value_text = clean_text(raw_value)
        match = NUMBER_RE.search(value_text)
        if not match:
            continue
        metric = KNOWN_METRICS.get(label)
        if metric:
            values[metric[0]] = float(match.group(0))
    return values


def fetch_device(device: dict[str, str], timeout: float) -> tuple[dict[str, str], dict[str, float], float, bool]:
    started = time.monotonic()
    request = urllib.request.Request(
        f"http://{device['ip']}/?m=1",
        headers={"User-Agent": "d00s-refoss-exporter/2"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            if response.status != 200:
                raise urllib.error.HTTPError(request.full_url, response.status, "unexpected status", response.headers, None)
            page = response.read(262144).decode("utf-8", errors="replace")
        values = parse_page(page)
        if "tasmota_active_power_W" not in values:
            raise ValueError("power metrics not found")
        return device, values, time.monotonic() - started, True
    except (OSError, ValueError, urllib.error.URLError) as exc:
        LOG.warning("collection failed for %s (%s): %s", device["name"], device["ip"], exc)
        return device, {}, time.monotonic() - started, False


def escape_label(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def render_metrics(devices: list[dict[str, str]], timeout: float) -> bytes:
    workers = min(4, len(devices))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        results = list(executor.map(lambda device: fetch_device(device, timeout), devices))

    samples: dict[str, list[tuple[dict[str, str], float]]] = defaultdict(list)
    output = [
        "# HELP tasmota_exporter_up Whether the outlet was collected successfully",
        "# TYPE tasmota_exporter_up gauge",
    ]
    for device, values, duration, success in results:
        labels = f'device="{escape_label(device["name"])}",device_ip="{escape_label(device["ip"])}"'
        output.append(f"tasmota_exporter_up{{{labels}}} {1 if success else 0}")
        samples["tasmota_exporter_scrape_duration_seconds"].append((device, duration))
        for metric_name, value in values.items():
            samples[metric_name].append((device, value))

    output.extend(
        [
            "# HELP tasmota_exporter_scrape_duration_seconds Time spent collecting an outlet",
            "# TYPE tasmota_exporter_scrape_duration_seconds gauge",
        ]
    )
    for device, value in samples.pop("tasmota_exporter_scrape_duration_seconds", []):
        labels = f'device="{escape_label(device["name"])}",device_ip="{escape_label(device["ip"])}"'
        output.append(f"tasmota_exporter_scrape_duration_seconds{{{labels}}} {value:.6f}")

    metadata = {value[0]: (value[1], value[2]) for value in KNOWN_METRICS.values()}
    for metric_name in sorted(samples):
        metric_type, help_text = metadata[metric_name]
        output.append(f"# HELP {metric_name} {help_text}")
        output.append(f"# TYPE {metric_name} {metric_type}")
        for device, value in samples[metric_name]:
            labels = f'device="{escape_label(device["name"])}",device_ip="{escape_label(device["ip"])}"'
            output.append(f"{metric_name}{{{labels}}} {value}")

    output.append("")
    return "\n".join(output).encode("utf-8")


DEVICES = load_devices()
FETCH_TIMEOUT = min(max(float(os.environ.get("FETCH_TIMEOUT_SECONDS", "2.5")), 0.5), 10.0)


class Handler(BaseHTTPRequestHandler):
    server_version = "d00s-refoss-exporter/2"

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/healthz":
            body = b"ok\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
        elif self.path == "/metrics":
            body = render_metrics(DEVICES, FETCH_TIMEOUT)
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
        else:
            body = b"not found\n"
            self.send_response(404)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, message: str, *args: object) -> None:
        LOG.info("%s %s", self.client_address[0], message % args)


def main() -> None:
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(message)s")
    port = int(os.environ.get("EXPORTER_PORT", "8000"))
    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    LOG.info("serving %d fixed devices on port %d", len(DEVICES), port)
    server.serve_forever()


if __name__ == "__main__":
    main()
