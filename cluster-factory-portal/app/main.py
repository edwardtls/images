from __future__ import annotations

import json
import ipaddress
import os
import datetime as dt
import smtplib
import subprocess
import base64
import hashlib
import hmac
import secrets
import ssl
import threading
import time
import urllib.parse
import urllib.request
from email.message import EmailMessage
from zoneinfo import ZoneInfo

import psycopg
from authlib.jose import jwt
from authlib.jose.errors import JoseError
from flask import (Flask, Response, abort, redirect, render_template, request,
                   session, stream_with_context)
from werkzeug.middleware.proxy_fix import ProxyFix

from . import (ai_control, documentation, edge_security, kube, ps5_reports,
               security_store, vulnerabilities)
from .lifecycle import lifecycle_history
from .security import (can_manage_clusters, can_view_security, client_ip,
                       csrf_token, current_user, groups, is_admin, owner_id,
                       require_admin, require_clusters, require_security,
                       verify_csrf)

app = Flask(__name__, static_folder="static", template_folder="templates")
app.secret_key = os.environ["SESSION_SECRET"]
app.config.update(MAX_CONTENT_LENGTH=65536, SESSION_COOKIE_HTTPONLY=True,
                  SESSION_COOKIE_SECURE=True, SESSION_COOKIE_SAMESITE="Lax",
                  SESSION_COOKIE_NAME="__Host-factory_session",
                  SESSION_REFRESH_EACH_REQUEST=False, PERMANENT_SESSION_LIFETIME=86400)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

_oidc_cache: dict[str, tuple[float, dict]] = {}
LIVE_LOG_LINE_LIMIT = 3000
LIVE_LOG_BATCH_SIZE = 200


def oidc_json(url: str, *, form_data: dict | None = None) -> dict:
    issuer = os.environ["OIDC_ISSUER"]
    expected = urllib.parse.urlsplit(issuer)
    target = urllib.parse.urlsplit(url)
    if target.scheme != "https" or target.netloc != expected.netloc:
        raise RuntimeError("OIDC endpoint is outside the configured HTTPS issuer")
    data = urllib.parse.urlencode(form_data).encode() if form_data is not None else None
    headers = {"Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    req = urllib.request.Request(url, data=data, headers=headers, method="POST" if data is not None else "GET")
    with urllib.request.urlopen(req, timeout=15, context=ssl.create_default_context()) as response:
        return json.load(response)


def oidc_document(kind: str) -> dict:
    cached = _oidc_cache.get(kind)
    if cached and time.monotonic() - cached[0] < 300:
        return cached[1]
    if kind == "discovery":
        document = oidc_json(os.environ["OIDC_DISCOVERY_URL"])
        if document.get("issuer") != os.environ["OIDC_ISSUER"]:
            raise RuntimeError("OIDC discovery issuer mismatch")
    else:
        document = oidc_json(oidc_document("discovery")["jwks_uri"])
    _oidc_cache[kind] = (time.monotonic(), document)
    return document


@app.before_request
def enforce_host_and_form_type():
    if request.path == "/healthz":
        return None
    allowed = {item.strip() for item in os.getenv("ALLOWED_HOSTS", "factory.apps.d00s.org").split(",")}
    if request.host.split(":", 1)[0] not in allowed:
        abort(400, "Invalid host")
    if request.path == "/static/infrastructure.svg":
        require_admin()
    if request.method in {"POST", "PUT", "PATCH"} and request.mimetype != "application/x-www-form-urlencoded":
        abort(415, "Only URL-encoded forms are accepted")


@app.after_request
def security_headers(response):
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; "
        "connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'self'")
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cache-Control"] = "no-store"
    return response


def page(template: str, **extra):
    user = session.get("user")
    return render_template(template, user=user, admin=bool(user and is_admin(user)),
                           can_clusters=bool(user and can_manage_clusters(user)),
                           can_security=bool(user and can_view_security(user)),
                           csrf=csrf_token(), **extra)


def form() -> dict[str, str]:
    if len(request.form) > 80:
        abort(413, "Too many form fields")
    return {key: request.form.get(key, "") for key in request.form}


def visible_records(user: dict) -> list[dict]:
    records = kube.cluster_records()
    if is_admin(user):
        known = {record["profile"] for record in records}
        for profile, live in kube.inventory().get("clusters", {}).items():
            if profile not in known:
                records.append({"profile": profile, "owner": "factory-system", "owner_sub": "",
                                "created_at": "", "expires_at": live.get("expires_at") or "",
                                "url": live.get("url", "#"), "request": {}, "managed_by_portal": False})
        return records
    return [record for record in records if record.get("owner_sub") == user["sub"]]


def normalized_live_cluster(live: dict | None) -> dict:
    """Return a complete view model even while observer data is unavailable.

    Cluster records and observer inventory are updated independently.  During
    creation and deletion it is therefore valid for a record to exist without
    a corresponding inventory entry.  Templates must render that state rather
    than treating it as an application error.
    """
    result = {
        "status": "unobserved",
        "url": "#",
        "test_url": "#",
        "nodes": {"ready": "—", "total": "—"},
        "pods": {"running": "—", "total": "—", "pending": 0,
                 "failed": 0, "failures": []},
        "argo": {"healthy": "—", "total": "—"},
        "resources": {"cpu": "—", "memory": "—", "disk": "—"},
        "components": {},
        "urls": [],
        "validation_passed": False,
        "cleanup_residuals": None,
        "forgejo_url": "https://git.apps.d00s.org",
    }
    supplied = live or {}
    result.update(supplied)
    for key in ("nodes", "pods", "argo", "resources"):
        merged = dict(result[key]) if isinstance(result.get(key), dict) else {}
        defaults = {
            "nodes": {"ready": "—", "total": "—"},
            "pods": {"running": "—", "total": "—", "pending": 0,
                     "failed": 0, "failures": []},
            "argo": {"healthy": "—", "total": "—"},
            "resources": {"cpu": "—", "memory": "—", "disk": "—"},
        }[key]
        result[key] = {**defaults, **merged}
    if not isinstance(result.get("components"), dict):
        result["components"] = {}
    if not isinstance(result.get("urls"), list):
        result["urls"] = []
    return result


def normalized_inventory(records: list[dict], inventory: dict | None = None) -> dict:
    result = dict(inventory or kube.inventory())
    observed = dict(result.get("clusters") or {})
    for record in records:
        profile = record["profile"]
        observed[profile] = normalized_live_cluster(observed.get(profile))
    result["clusters"] = observed
    return result


def reconciler():
    while True:
        try:
            kube.reconcile()
        except Exception:
            app.logger.exception("job reconciliation failed")
        time.sleep(15)


threading.Thread(target=reconciler, name="factory-reconciler", daemon=True).start()


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


@app.get("/")
def landing():
    if session.get("user"):
        return redirect("/dashboard", code=303)
    return page("landing.html")


def oidc_redirect(*, registration: bool = False):
    discovery = oidc_document("discovery")
    state = secrets.token_urlsafe(32); nonce = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    session["oidc"] = {"state": state, "nonce": nonce, "verifier": verifier,
                       "created": int(time.time()), "flow": "registration" if registration else "login"}
    params = {"client_id": os.environ["OIDC_CLIENT_ID"], "response_type": "code",
              "redirect_uri": os.environ["OIDC_REDIRECT_URI"], "scope": "openid profile email groups",
              "state": state, "nonce": nonce, "code_challenge": challenge, "code_challenge_method": "S256"}
    endpoint = discovery["authorization_endpoint"]
    if registration:
        endpoint = os.environ["OIDC_ISSUER"].rstrip("/") + "/protocol/openid-connect/registrations"
    return redirect(endpoint + "?" + urllib.parse.urlencode(params), code=302)


@app.get("/login")
def login():
    return oidc_redirect()


@app.get("/signup")
def signup():
    return oidc_redirect(registration=True)


@app.get("/pending")
def pending_access():
    return page("pending.html")


@app.get("/auth/callback")
def callback():
    if request.args.get("error"):
        abort(401, "Identity provider rejected authentication")
    pending = session.pop("oidc", None)
    if (not pending or int(time.time()) - int(pending.get("created", 0)) > 600
            or not hmac.compare_digest(str(pending.get("state", "")), request.args.get("state", ""))):
        abort(400, "Invalid or expired OIDC state")
    code = request.args.get("code", "")
    if not code:
        abort(400, "OIDC authorization code is missing")
    discovery = oidc_document("discovery")
    try:
        token = oidc_json(discovery["token_endpoint"], form_data={
            "grant_type": "authorization_code", "code": code,
            "redirect_uri": os.environ["OIDC_REDIRECT_URI"],
            "client_id": os.environ["OIDC_CLIENT_ID"],
            "client_secret": os.environ["OIDC_CLIENT_SECRET"],
            "code_verifier": pending["verifier"],
        })
    except (OSError, RuntimeError, ValueError):
        app.logger.warning("OIDC token exchange failed", exc_info=True)
        abort(401, "Authentication could not be completed")
    encoded = token.get("id_token")
    if not encoded:
        abort(401, "Identity provider did not return an ID token")
    try:
        claims = jwt.decode(encoded, oidc_document("jwks"), claims_options={
            "iss": {"essential": True, "value": os.environ["OIDC_ISSUER"]},
            "aud": {"essential": True, "value": os.environ["OIDC_CLIENT_ID"]},
            "exp": {"essential": True},
            "sub": {"essential": True},
            "nonce": {"essential": True, "value": pending["nonce"]},
        })
        claims.validate(leeway=60)
    except (JoseError, OSError, RuntimeError, ValueError):
        app.logger.warning("OIDC ID token validation failed", exc_info=True)
        abort(401, "Identity token validation failed")
    user = dict(claims)
    if os.getenv("OIDC_ADMIN_GROUP", "factory-admins") not in groups(user):
        access = kube.ensure_access_request(
            user,
            client_ip(),
            legacy_user=os.getenv("OIDC_USER_GROUP", "factory-users") in groups(user),
        )
        if not access.get("approved"):
            session.clear()
            return redirect("/pending", code=303)
        user["access"] = {key: bool(access.get(key)) for key in ("approved", "clusters", "security")}
    session.clear()
    session["user"] = {key: user.get(key) for key in ("sub", "preferred_username", "groups", "access")}
    session.permanent = True; csrf_token()
    return redirect("/dashboard", code=303)


@app.post("/logout")
def logout():
    verify_csrf(form().get("csrf", "")); session.clear()
    return redirect("/", code=303)


@app.get("/dashboard")
def dashboard():
    current_user()
    return page("dashboard.html")


@app.get("/clusters")
def clusters():
    user = require_clusters(); kube.reconcile()
    records = visible_records(user)
    return page("clusters.html", clusters=records, inventory=normalized_inventory(records),
                jobs=kube.active_jobs(), quota=kube.quota_for(user))


@app.get("/build")
def build_form():
    user = require_clusters()
    return page("build.html", profiles=kube.visible_profiles(is_admin(user)), versions=kube.versions(), quota=kube.quota_for(user))


@app.get("/clusters/<profile>")
def cluster_detail(profile: str):
    user = require_clusters()
    record = next((item for item in visible_records(user) if item["profile"] == profile), None)
    if not record:
        abort(404, "Cluster not found")
    live = normalized_live_cluster(kube.inventory().get("clusters", {}).get(profile))
    return page("cluster.html", cluster=record, live=live)


@app.post("/build")
def build():
    user = require_clusters(); values = form(); verify_csrf(values.get("csrf", ""))
    profile = values.get("profile", "")
    profile_config = kube.profiles().get(profile)
    if profile_config is None:
        abort(400, "Unknown profile")
    if profile_config.get("admin_only") and not is_admin(user):
        abort(403, "This profile is limited to administrators")
    openshift = profile_config.get("platform") == "openshift"
    owned = [record for record in kube.cluster_records() if record.get("owner_sub") == user["sub"]]
    pending = [job for job in kube.active_jobs()
               if job["metadata"]["labels"].get("factory.d00s.org/owner") == owner_id(user)]
    if not is_admin(user) and len(owned) + len(pending) >= kube.quota_for(user):
        abort(409, "Your active cluster quota has been reached")
    if (any(record["profile"] == profile for record in kube.cluster_records())
            or profile in kube.inventory().get("clusters", {})):
        abort(409, "This profile already has an active cluster")
    selected_versions = {}
    for component, allowed in kube.versions().items():
        value = values.get(f"version_{component}", "")
        if value not in {item["value"] for item in allowed}:
            abort(400, f"Invalid {component} version")
        selected_versions[component] = value
    ttl = values.get("ttl", "24h")
    if not kube.TTL_RE.fullmatch(ttl):
        abort(400, "TTL must look like 24h, 7d, or 2w")
    ttl_hours = int(ttl[:-1]) * {"h": 1, "d": 24, "w": 168}[ttl[-1]]
    regular_max = str(kube.policy().get("max_ttl_regular", "7d"))
    regular_max_hours = int(regular_max[:-1]) * {"h": 1, "d": 24, "w": 168}[regular_max[-1]]
    if not is_admin(user) and ttl_hours > regular_max_hours:
        abort(400, f"Regular-user TTL is limited to {regular_max}")
    try:
        control_planes = int(values.get("control_planes", "1")); workers = int(values.get("workers", "3"))
    except ValueError:
        abort(400, "Topology values must be integers")
    if control_planes not in {1, 3, 5} or workers not in {1, 2, 3, 4, 5, 6}:
        abort(400, "Requested topology is outside the supported range")
    if openshift:
        error = kube.openshift_request_error(control_planes, workers, values.get("storage", "nfs"), ttl_hours)
        if error:
            abort(400, error)
    else:
        selected_versions.pop("openshift", None)
    request_data = {
        "name": profile, "profile": profile,
        "portal_owner": user.get("preferred_username", "factory-user"),
        "kubernetes_version": selected_versions.pop("kubernetes"),
        "calico_version": selected_versions.pop("calico"),
        "containerd_version": selected_versions.pop("containerd"),
        "argo_chart_version": selected_versions.pop("argocd_chart"),
        "topology": {"control_planes": control_planes, "workers": workers},
        "storage": {"mode": values.get("storage", "nfs")},
        "addons": {"monitoring": values.get("monitoring") == "on",
                   "metrics_server": values.get("metrics_server") == "on", "test_nginx": True},
        "lifecycle": {"ttl": ttl, "retain_data_on_expiry": False},
        "versions": selected_versions, "failure_policy": "rollback"}
    if request_data["storage"]["mode"] not in {"nfs", "ceph", "both"}:
        abort(400, "Invalid storage selection")
    try:
        job_id = kube.submit("create", request_data, user, client_ip())
    except ValueError as exc:
        abort(409, str(exc))
    return redirect(f"/jobs/{job_id}", code=303)


@app.post("/clusters/<profile>/delete")
def delete_cluster(profile: str):
    user = require_clusters(); values = form(); verify_csrf(values.get("csrf", ""))
    retain_data = values.get("retain_data") == "on"
    record = next((item for item in kube.cluster_records() if item["profile"] == profile), None)
    if not record:
        abort(404, "Cluster record not found")
    if not is_admin(user) and record.get("owner_sub") != user["sub"]:
        abort(403, "You do not own this cluster")
    if retain_data and not is_admin(user):
        abort(403, "Only administrators can retain cluster data")
    payload = dict(record["request"]); payload["retain_data"] = retain_data
    try:
        job_id = kube.submit("delete", payload, user, client_ip())
    except ValueError as exc:
        abort(409, str(exc))
    return redirect(f"/jobs/{job_id}", code=303)


@app.post("/clusters/delete-all")
def delete_all_clusters():
    user = require_clusters(); values = form(); verify_csrf(values.get("csrf", ""))
    if values.get("confirm", "").strip() != "DELETE ALL":
        abort(400, "Type DELETE ALL to confirm bulk decommissioning")
    retain_data = values.get("retain_data") == "on"
    if retain_data and not is_admin(user):
        abort(403, "Only administrators can retain cluster data")

    records = {record["profile"]: record for record in kube.cluster_records()}
    if is_admin(user):
        profiles = set(records) | set(kube.inventory().get("clusters", {}))
    else:
        profiles = {profile for profile, record in records.items()
                    if record.get("owner_sub") == user["sub"]}
    queued = 0; skipped = 0
    for profile in sorted(profiles):
        record = records.get(profile)
        request_data = dict(record["request"]) if record else kube.deletion_request(profile)
        request_data["retain_data"] = retain_data
        try:
            kube.submit("delete", request_data, user, client_ip())
            queued += 1
        except ValueError:
            skipped += 1
    return redirect(f"/clusters?bulk_queued={queued}&bulk_skipped={skipped}", code=303)


@app.get("/jobs/<job_id>")
def job_page(job_id: str):
    job = authorized_operation(job_id)
    return page("job.html", job=job, job_id=job_id)


def authorized_operation(job_id: str) -> dict:
    if not kube.JOB_ID_RE.fullmatch(job_id):
        abort(404, "Job not found")
    user = require_clusters()
    try:
        job = kube.operation_for(job_id)
    except KeyError:
        abort(404, "Job not found")
    if not is_admin(user) and job["metadata"]["labels"].get("factory.d00s.org/owner") != owner_id(user):
        abort(403, "This job belongs to another user")
    return job


@app.get("/jobs/<job_id>/logs/download")
def job_log_download(job_id: str):
    job = authorized_operation(job_id)
    if job.get("kind") == "PendingFactoryRequest":
        abort(409, "The runner has not started, so no full log exists yet")
    pods = sorted(kube.pods_for_job(job["metadata"]["name"]),
                  key=lambda pod: pod["metadata"].get("creationTimestamp", ""))
    if not pods:
        abort(404, "The retained full log is no longer available")

    @stream_with_context
    def complete_log():
        multiple = len(pods) > 1
        for index, pod in enumerate(pods):
            if multiple:
                if index:
                    yield b"\n"
                name = pod["metadata"]["name"]
                yield f"===== pod: {name} =====\n".encode()
            yield from kube.pod_log_chunks(pod["metadata"]["name"])

    return Response(complete_log(), mimetype="text/plain", headers={
        "Content-Disposition": f'attachment; filename="factory-job-{job_id}.log"',
        "X-Content-Type-Options": "nosniff",
    })


@app.get("/api/jobs/<job_id>/stream")
def job_stream(job_id: str):
    authorized_operation(job_id)
    @stream_with_context
    def events():
        seen = 0; pod = None; last_stage = None; reset_view = True
        while True:
            try:
                current = kube.operation_for(job_id)
                if current.get("kind") == "PendingFactoryRequest":
                    if last_stage != "queued":
                        yield 'event: stage\ndata: "queued"\n\n'; last_stage = "queued"
                    yield ": keepalive\n\n"; time.sleep(2); continue
                pods = kube.pods_for_job(current["metadata"]["name"])
                if not pods:
                    if kube.terminal(current):
                        outcome = "Succeeded" if current.get("status", {}).get("succeeded") else "Failed"
                        yield f"event: done\ndata: {json.dumps(outcome)}\n\n"; return
                    if last_stage != "queued":
                        yield 'event: stage\ndata: "queued"\n\n'; last_stage = "queued"
                    yield ": keepalive\n\n"; time.sleep(2); continue
                current_pod = pods[0]["metadata"]["name"]
                if current_pod != pod:
                    pod = current_pod; seen = 0; reset_view = True
                lines = kube.pod_log(pod).splitlines()
                if len(lines) < seen:
                    seen = 0; reset_view = True
                start = seen
                if len(lines) - start > LIVE_LOG_LINE_LIMIT:
                    start = len(lines) - LIVE_LOG_LINE_LIMIT
                    reset_view = True
                new_lines = lines[start:]
                stages = [line for line in new_lines if "FACTORY_STAGE" in line]
                if stages and stages[-1] != last_stage:
                    last_stage = stages[-1]
                    yield f"event: stage\ndata: {json.dumps(last_stage)}\n\n"
                for offset in range(0, len(new_lines), LIVE_LOG_BATCH_SIZE):
                    payload = {"lines": new_lines[offset:offset + LIVE_LOG_BATCH_SIZE],
                               "reset": reset_view and offset == 0}
                    yield f"event: logs\ndata: {json.dumps(payload)}\n\n"
                if new_lines:
                    reset_view = False
                seen = len(lines)
                current = kube.job_for(job_id)
                if kube.terminal(current):
                    outcome = "Succeeded" if current.get("status", {}).get("succeeded") else "Failed"
                    yield f"event: done\ndata: {json.dumps(outcome)}\n\n"; return
            except Exception as exc:
                # Surface transient API errors and keep retrying instead of
                # falsely declaring a live operation finished.
                yield f"event: stream-error\ndata: {json.dumps(str(exc))}\n\n"
            yield ": keepalive\n\n"; time.sleep(2)

    return Response(events(), mimetype="text/event-stream", headers={"X-Accel-Buffering": "no"})


@app.get("/howto")
def howto():
    current_user(); return page("howto.html")


@app.get("/ai")
def ai_dashboard():
    require_admin()
    try:
        status = ai_control.command("status")
        return page("ai.html", status=status, error=None)
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError,
            subprocess.SubprocessError, kube.KubeError) as exc:
        app.logger.warning("Kubernetes AI status failed", exc_info=True)
        return page("ai.html", status={}, error=str(exc)[:300]), 503


@app.post("/ai/action")
def ai_action():
    administrator = require_admin(); values = form(); verify_csrf(values.get("csrf", ""))
    action = values.get("action", "")
    if action not in {"enable", "development", "stay", "scan", "stop"}:
        abort(400, "Invalid AI control action")
    try:
        ai_control.command(action)
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError,
            subprocess.SubprocessError, kube.KubeError):
        app.logger.warning("Kubernetes AI action failed", exc_info=True)
        abort(502, "Kubernetes did not accept the AI control action")
    app.logger.info("administrator %s requested AI action %s",
                    administrator.get("preferred_username"), action)
    return redirect(f"/ai?action={urllib.parse.quote(action)}", code=303)


@app.get("/docs")
def documentation_index():
    require_admin()
    try:
        documents = documentation.catalog()
        error = None
    except (documentation.DocumentationError, kube.KubeError):
        app.logger.warning("documentation catalog unavailable", exc_info=True)
        documents = []
        error = "The GitOps documentation bundle is temporarily unavailable"
    categories: dict[str, list[dict]] = {}
    children: dict[str, list[dict]] = {}
    for item in documents:
        if item.get("parent"):
            children.setdefault(item["parent"], []).append(item)
    for item in documents:
        if not item.get("parent"):
            item = {**item, "children": children.get(item["id"], [])}
            categories.setdefault(item["category"], []).append(item)
    return page("docs.html", categories=categories, error=error)


@app.get("/docs/<document_id>")
def documentation_detail(document_id: str):
    require_admin()
    try:
        document = documentation.document(document_id)
    except (documentation.DocumentationError, kube.KubeError):
        app.logger.warning("documentation entry unavailable", exc_info=True)
        abort(503, "The GitOps documentation entry is temporarily unavailable")
    if not document:
        abort(404, "Documentation entry not found")
    return page("doc.html", document=document)


@app.get("/ps5")
def ps5_network_report():
    require_admin()
    today_date = dt.datetime.now(dt.timezone.utc).astimezone(ZoneInfo("Europe/Amsterdam")).date()
    window = [today_date - dt.timedelta(days=offset) for offset in range(8)]
    allowed = {day.isoformat() for day in window}
    requested = request.args.get("date", "latest")
    if requested != "latest" and requested not in allowed:
        abort(400, "Invalid PS5 report date")
    try:
        available = set(ps5_reports.available()) & allowed
        selected = (next((day.isoformat() for day in window if day.isoformat() in available),
                         today_date.isoformat()) if requested == "latest" else requested)
        reports = [{"date": day.isoformat(),
                    "label": "Today" if day == today_date else
                             "Yesterday" if day == today_date - dt.timedelta(days=1) else
                             day.strftime("%A"),
                    "available": day.isoformat() in available,
                    "selected": day.isoformat() == selected}
                   for day in window]
        report = ps5_reports.report(selected)
    except ValueError:
        abort(400, "Invalid PS5 report date")
    except ps5_reports.NotFound:
        return page("ps5.html", report=None, selected=selected,
                    reports=reports, generated=request.args.get("generated") == "1",
                    error="No report exists for that date. Run it now to create one."), 404
    except (OSError, RuntimeError, json.JSONDecodeError, subprocess.SubprocessError):
        app.logger.warning("PS5 network report unavailable", exc_info=True)
        return page("ps5.html", report=None, selected=requested,
                    reports=[], generated=False,
                    error="The PS5 report is temporarily unavailable"), 503
    return page("ps5.html", report=report, selected=report["date"],
                reports=reports, generated=request.args.get("generated") == "1", error=None)


@app.post("/ps5/generate")
def ps5_generate_report():
    require_admin(); values = form(); verify_csrf(values.get("csrf", ""))
    today = dt.datetime.now(dt.timezone.utc).astimezone(ZoneInfo("Europe/Amsterdam")).date()
    allowed = {(today - dt.timedelta(days=offset)).isoformat() for offset in range(8)}
    report_date = values.get("date", "")
    if report_date not in allowed:
        abort(400, "Invalid PS5 report date")
    try:
        ps5_reports.generate(report_date)
    except ValueError:
        abort(400, "Invalid PS5 report date")
    except (OSError, RuntimeError, json.JSONDecodeError, subprocess.SubprocessError):
        app.logger.warning("PS5 network report generation failed", exc_info=True)
        abort(502, "The PS5 report could not be generated")
    app.logger.info("administrator generated PS5 network report for %s", report_date)
    return redirect("/ps5?date=" + urllib.parse.quote(report_date) + "&generated=1", code=303)


SECURITY_WINDOWS = (("3h", "Last 3 hours"), ("today", "Today"), ("24h", "Last 24 hours"),
                    ("3d", "Last 3 days"), ("7d", "Last week"), ("all", "All"))


@app.get("/security")
def security_dashboard():
    require_security()
    windows = SECURITY_WINDOWS
    window = request.args.get("window", "today")
    view = request.args.get("view", "edge")
    if window not in dict(windows):
        abort(400, "Invalid security time window")
    if view not in {"edge", "mcp"}:
        abort(400, "Invalid security view")
    if view == "mcp":
        require_admin()
    try:
        status = security_store.mcp_status(window) if view == "mcp" else security_store.edge_status(window)
        partial = render_template(f"_security_{view}.html", status=status, error=None,
                                  window=window, admin=is_admin(current_user()), csrf=csrf_token())
        return page("security.html", partial=partial, view=view, window=window, windows=windows)
    except (RuntimeError, ValueError, psycopg.Error) as exc:
        app.logger.warning("database security status failed", exc_info=True)
        partial = render_template(f"_security_{view}.html", status={}, error=str(exc)[:200],
                                  window=window, admin=is_admin(current_user()), csrf=csrf_token())
        return page("security.html", partial=partial, view=view, window=window, windows=windows), 503


@app.get("/security/mcp")
def mcp_security_dashboard():
    require_admin()
    query = urllib.parse.urlencode({"view": "mcp", "window": request.args.get("window", "today")})
    return redirect(f"/security?{query}", code=302)


@app.get("/api/security/view")
def security_view():
    require_security()
    view = request.args.get("view", "edge")
    window = request.args.get("window", "today")
    if view not in {"edge", "mcp"} or window not in {"3h", "today", "24h", "3d", "7d", "all"}:
        abort(400, "Invalid security view")
    if view == "mcp":
        require_admin()
    try:
        status = security_store.mcp_status(window) if view == "mcp" else security_store.edge_status(window)
    except (RuntimeError, ValueError, psycopg.Error):
        app.logger.warning("database security partial failed", exc_info=True)
        abort(503, "Security telemetry is temporarily unavailable")
    return render_template(f"_security_{view}.html", status=status, error=None,
                           window=window, admin=is_admin(current_user()), csrf=csrf_token())


@app.get("/api/security/mcp/latest")
def mcp_security_latest():
    require_admin()
    try:
        payload = {"cursor": security_store.latest_mcp_cursor()}
    except (RuntimeError, ValueError, psycopg.Error):
        app.logger.warning("MCP latest-event check failed", exc_info=True)
        abort(503, "MCP telemetry is temporarily unavailable")
    return Response(json.dumps(payload), mimetype="application/json")


VULNERABILITY_VIEWS = {"systems": "system", "vulnerabilities": "vulnerability"}


@app.get("/security/vulnerabilities")
@app.get("/security/vulnerabilities/<view>/<identifier>")
def vulnerabilities_dashboard(view: str = "", identifier: str = ""):
    require_admin()
    if view and (view not in VULNERABILITY_VIEWS or not vulnerabilities.IDENTIFIER.fullmatch(identifier)):
        abort(404)
    # One page with the edge and MCP views, so switching tabs needs no reload;
    # the edge view is fetched when its tab is opened.
    return page("security.html", partial="", view="vulns", window="today", windows=SECURITY_WINDOWS,
                vuln_view=VULNERABILITY_VIEWS.get(view, "overview"), identifier=identifier)


@app.get("/api/security/vulnerabilities/status")
def vulnerabilities_status():
    require_admin()
    try:
        payload = vulnerabilities.status()
    except vulnerabilities.NotFound:
        abort(503, "No vulnerability report has been imported yet")
    except (RuntimeError, psycopg.Error):
        app.logger.warning("vulnerability report status unavailable", exc_info=True)
        abort(503, "The vulnerability report is temporarily unavailable")
    return Response(json.dumps(payload), mimetype="application/json")


@app.get("/api/security/vulnerabilities")
@app.get("/api/security/vulnerabilities/<kind>/<identifier>")
def vulnerabilities_api(kind: str = "", identifier: str = ""):
    require_admin()
    try:
        payload = vulnerabilities.detail(kind, identifier) if kind else vulnerabilities.overview()
    except ValueError:
        abort(404)
    except vulnerabilities.NotFound:
        abort(404, "Not in the latest vulnerability report")
    except (RuntimeError, psycopg.Error):
        app.logger.warning("vulnerability report unavailable", exc_info=True)
        abort(503, "The vulnerability report is temporarily unavailable")
    return Response(payload, mimetype="application/json")


@app.post("/security/bans/<address>/delete")
def security_delete(address: str):
    require_admin(); values = form(); verify_csrf(values.get("csrf", ""))
    try:
        parsed = ipaddress.ip_address(address)
        # Firewall decisions never carry an IPv6 zone ("fe80::1%eth0").
        if getattr(parsed, "scope_id", None):
            raise ValueError("scoped address")
        normalized = str(parsed)
        edge_security.delete(normalized)
    except ValueError:
        abort(400, "Invalid IP address")
    except (OSError, RuntimeError, subprocess.SubprocessError):
        app.logger.warning("edge security decision removal failed", exc_info=True)
        abort(502, "The distributed firewall did not accept the removal")
    app.logger.info("administrator removed distributed edge ban for %s", normalized)
    return redirect("/security?removed=" + urllib.parse.quote(normalized), code=303)


@app.post("/contact")
def contact():
    user = current_user(); values = form(); verify_csrf(values.get("csrf", ""))
    message = values.get("message", "").strip()[:4000]
    if len(message) < 10:
        abort(400, "Please provide a little more detail")
    email = EmailMessage(); email["From"] = os.environ["SMTP_USERNAME"]
    email["To"] = os.environ["CONTACT_RECIPIENT"]
    email["Subject"] = f"Cluster Factory contact from {user.get('preferred_username')}"
    email.set_content(f"User: {user.get('preferred_username')}\nSubject: {user.get('sub')}\n\n{message}")
    with smtplib.SMTP(os.getenv("SMTP_HOST", "smtp.gmail.com"),
                      int(os.getenv("SMTP_PORT", "587")), timeout=15) as smtp:
        smtp.starttls(); smtp.login(os.environ["SMTP_USERNAME"], os.environ["SMTP_PASSWORD"])
        smtp.send_message(email)
    return redirect("/clusters?contact=sent", code=303)


@app.get("/admin")
def admin():
    user = require_admin(); audits = []
    for cm in kube.labels("factory.d00s.org/type=audit"):
        try:
            audits.append(json.loads(cm["data"]["record.json"]))
        except (KeyError, json.JSONDecodeError):
            continue
    audits.sort(key=lambda item: item.get("submitted_at", ""), reverse=True)
    blocks = kube.read_json_configmap("cluster-factory-security-status", "blocks.json",
                                      {"active": [], "history": []})
    try:
        access_users = kube.access_records()
        access_error = None
    except kube.KubeError:
        app.logger.warning("Factory access review failed", exc_info=True)
        access_users = []
        access_error = "The Factory approval registry is temporarily unavailable"
    return page("admin.html", clusters=visible_records(user), audits=audits[:100],
                lifecycles=lifecycle_history(audits)[:250], policy=kube.policy(),
                inventory=kube.inventory(), blocks=blocks, access_users=access_users,
                access_error=access_error,
                pending_users=sum(1 for item in access_users if not item.get("approved")))


@app.post("/admin/users/<resource_name>/access")
def admin_user_access(resource_name: str):
    administrator = require_admin(); values = form(); verify_csrf(values.get("csrf", ""))
    try:
        changed = kube.update_access_record(
            resource_name,
            approved=values.get("approved") == "on",
            clusters=values.get("clusters") == "on",
            security=values.get("security") == "on",
            administrator=administrator,
        )
    except (ValueError, KeyError, json.JSONDecodeError):
        abort(400, "Invalid Factory access record")
    except kube.KubeError:
        app.logger.warning("Factory access update failed", exc_info=True)
        abort(502, "The Factory approval registry rejected the update")
    audit_id = secrets.token_hex(6)
    kube.audit(audit_id, {
        "schema": 1,
        "job_id": audit_id,
        "action": "access-update",
        "profile": "identity",
        "owner_sub": administrator["sub"],
        "owner": administrator.get("preferred_username"),
        "target_sub": changed["subject"],
        "target_user": changed["username"],
        "submitted_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "status": "succeeded",
        "entitlements": {key: changed[key] for key in ("approved", "clusters", "security")},
    })
    app.logger.info("administrator %s updated Factory access for %s",
                    administrator.get("preferred_username"), changed["username"])
    return redirect("/admin?access=updated#access-control", code=303)


@app.post("/admin/policy")
def admin_policy():
    require_admin(); values = form(); verify_csrf(values.get("csrf", "")); current = kube.policy()
    try:
        current["default_user_cluster_limit"] = max(1, min(int(values.get("default_limit", "1")), 10))
        override = max(1, min(int(values.get("user_limit", "1")), 10))
    except ValueError:
        abort(400, "Quota values must be integers")
    subject = values.get("user_sub", "").strip()
    if subject:
        current.setdefault("user_overrides", {})[subject] = override
    kube.update_policy(current)
    return redirect("/admin", code=303)
