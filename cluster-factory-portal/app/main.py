from __future__ import annotations

import json
import os
import smtplib
import threading
import time
from email.message import EmailMessage

from authlib.integrations.flask_client import OAuth
from flask import (Flask, Response, abort, redirect, render_template, request,
                   session, stream_with_context)
from werkzeug.middleware.proxy_fix import ProxyFix

from . import kube
from .security import (client_ip, csrf_token, current_user, groups, is_admin,
                       owner_id, require_admin, verify_csrf)

app = Flask(__name__, static_folder="static", template_folder="templates")
app.secret_key = os.environ["SESSION_SECRET"]
app.config.update(MAX_CONTENT_LENGTH=65536, SESSION_COOKIE_HTTPONLY=True,
                  SESSION_COOKIE_SECURE=True, SESSION_COOKIE_SAMESITE="Lax",
                  SESSION_COOKIE_NAME="__Host-factory_session",
                  SESSION_REFRESH_EACH_REQUEST=False, PERMANENT_SESSION_LIFETIME=28800)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

oauth = OAuth(app)
keycloak = oauth.register(
    "keycloak", client_id=os.environ["OIDC_CLIENT_ID"],
    client_secret=os.environ["OIDC_CLIENT_SECRET"],
    server_metadata_url=os.environ["OIDC_DISCOVERY_URL"],
    client_kwargs={"scope": "openid profile email groups", "code_challenge_method": "S256"})


@app.before_request
def enforce_host_and_form_type():
    if request.path == "/healthz":
        return None
    allowed = {item.strip() for item in os.getenv("ALLOWED_HOSTS", "factory.apps.d00s.org").split(",")}
    if request.host.split(":", 1)[0] not in allowed:
        abort(400, "Invalid host")
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
        return redirect("/clusters", code=303)
    return page("landing.html")


@app.get("/login")
def login():
    return keycloak.authorize_redirect(os.environ["OIDC_REDIRECT_URI"])


@app.get("/auth/callback")
def callback():
    token = keycloak.authorize_access_token()
    user = dict(token.get("userinfo") or keycloak.userinfo(token=token))
    allowed = {os.getenv("OIDC_USER_GROUP", "factory-users"),
               os.getenv("OIDC_ADMIN_GROUP", "factory-admins")}
    if not allowed & groups(user):
        abort(403, "Your account has not been granted factory access")
    session.clear()
    session["user"] = {key: user.get(key) for key in ("sub", "preferred_username", "groups")}
    session.permanent = True; csrf_token()
    return redirect("/clusters", code=303)


@app.post("/logout")
def logout():
    verify_csrf(form().get("csrf", "")); session.clear()
    return redirect("/", code=303)


@app.get("/clusters")
def clusters():
    user = current_user(); kube.reconcile()
    return page("clusters.html", clusters=visible_records(user), inventory=kube.inventory(),
                jobs=kube.active_jobs(), quota=kube.quota_for(user))


@app.get("/build")
def build_form():
    user = current_user()
    return page("build.html", profiles=kube.profiles(), versions=kube.versions(), quota=kube.quota_for(user))


@app.get("/clusters/<profile>")
def cluster_detail(profile: str):
    user = current_user()
    record = next((item for item in visible_records(user) if item["profile"] == profile), None)
    live = kube.inventory().get("clusters", {}).get(profile)
    if not record or not live:
        abort(404, "Cluster not found")
    return page("cluster.html", cluster=record, live=live)


@app.post("/build")
def build():
    user = current_user(); values = form(); verify_csrf(values.get("csrf", ""))
    profile = values.get("profile", "")
    if profile not in kube.profiles():
        abort(400, "Unknown profile")
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
    if not 1 <= control_planes <= 3 or not 0 <= workers <= 6:
        abort(400, "Requested topology is outside the supported range")
    request_data = {
        "name": profile, "profile": profile,
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
    user = current_user(); values = form(); verify_csrf(values.get("csrf", ""))
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


@app.get("/jobs/<job_id>")
def job_page(job_id: str):
    user = current_user()
    try:
        job = kube.operation_for(job_id)
    except KeyError:
        abort(404, "Job not found")
    if not is_admin(user) and job["metadata"]["labels"].get("factory.d00s.org/owner") != owner_id(user):
        abort(403, "This job belongs to another user")
    return page("job.html", job=job, job_id=job_id)


@app.get("/api/jobs/<job_id>/stream")
def job_stream(job_id: str):
    user = current_user()
    try:
        job = kube.operation_for(job_id)
    except KeyError:
        abort(404, "Job not found")
    if not is_admin(user) and job["metadata"]["labels"].get("factory.d00s.org/owner") != owner_id(user):
        abort(403, "This job belongs to another user")
    if job.get("kind") == "PendingFactoryRequest":
        return Response('event: stage\ndata: "queued"\n\n', mimetype="text/event-stream",
                        headers={"Retry-After": "2"})
    pods = kube.pods_for_job(job["metadata"]["name"])
    if not pods:
        return Response('event: stage\ndata: "queued"\n\n', mimetype="text/event-stream")
    pod = pods[0]["metadata"]["name"]

    @stream_with_context
    def events():
        seen = 0
        while True:
            try:
                lines = kube.pod_log(pod).splitlines()
                for line in lines[seen:]:
                    event = "stage" if "FACTORY_STAGE" in line else "log"
                    yield f"event: {event}\ndata: {json.dumps(line)}\n\n"
                seen = len(lines)
                if kube.terminal(kube.job_for(job_id)):
                    break
            except Exception as exc:
                yield f"event: error\ndata: {json.dumps(str(exc))}\n\n"; break
            yield ": keepalive\n\n"; time.sleep(2)
        yield "event: done\ndata: complete\n\n"

    return Response(events(), mimetype="text/event-stream", headers={"X-Accel-Buffering": "no"})


@app.get("/howto")
def howto():
    current_user(); return page("howto.html")


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
    return page("admin.html", clusters=visible_records(user), audits=audits[:100], policy=kube.policy(),
                inventory=kube.inventory(), blocks=blocks)


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
