from __future__ import annotations

import asyncio
import datetime as dt
import json
import os
import smtplib
import time
from email.message import EmailMessage

from authlib.integrations.starlette_client import OAuth
from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from kubernetes import client
from kubernetes.client.rest import ApiException
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from . import kube
from .security import (client_ip, csrf_token, current_user, groups, is_admin,
                       owner_id, require_admin, verify_csrf)

app = FastAPI(title="d00s Cluster Factory", docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=os.getenv("ALLOWED_HOSTS", "factory.apps.d00s.org").split(","))
app.add_middleware(SessionMiddleware, secret_key=os.environ["SESSION_SECRET"], https_only=True,
                   same_site="lax", max_age=28800)
app.mount("/static", StaticFiles(directory="/app/app/static"), name="static")
templates = Jinja2Templates(directory="/app/app/templates")

oauth = OAuth()
oauth.register("keycloak", client_id=os.environ["OIDC_CLIENT_ID"],
               client_secret=os.environ["OIDC_CLIENT_SECRET"],
               server_metadata_url=os.environ["OIDC_DISCOVERY_URL"],
               client_kwargs={"scope": "openid profile email groups"})


@app.on_event("startup")
async def start_reconciler():
    async def loop():
        while True:
            try:
                await asyncio.to_thread(kube.reconcile)
            except Exception:
                pass
            await asyncio.sleep(15)
    asyncio.create_task(loop())


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; "
        "connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'self'"
    )
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cache-Control"] = "no-store"
    return response


def context(request: Request, **extra):
    user = request.session.get("user")
    return {"request": request, "user": user, "admin": bool(user and is_admin(user)),
            "csrf": csrf_token(request), **extra}


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


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


@app.get("/", response_class=HTMLResponse)
def landing(request: Request):
    if request.session.get("user"):
        return RedirectResponse("/clusters", status_code=303)
    return templates.TemplateResponse("landing.html", context(request))


@app.get("/login")
async def login(request: Request):
    return await oauth.keycloak.authorize_redirect(request, os.environ["OIDC_REDIRECT_URI"])


@app.get("/auth/callback")
async def callback(request: Request):
    token = await oauth.keycloak.authorize_access_token(request)
    user = dict(token.get("userinfo") or await oauth.keycloak.userinfo(token=token))
    if not ({os.getenv("OIDC_USER_GROUP", "factory-users"), os.getenv("OIDC_ADMIN_GROUP", "factory-admins")} & groups(user)):
        raise HTTPException(status_code=403, detail="Your account has not been granted factory access")
    request.session.clear()
    request.session["user"] = {key: user.get(key) for key in ("sub", "preferred_username", "name", "email", "groups")}
    csrf_token(request)
    return RedirectResponse("/clusters", status_code=303)


@app.post("/logout")
def logout(request: Request, csrf: str = Form(...)):
    verify_csrf(request, csrf)
    request.session.clear()
    return RedirectResponse("/", status_code=303)


@app.get("/clusters", response_class=HTMLResponse)
def clusters(request: Request):
    user = current_user(request)
    kube.reconcile()
    records = visible_records(user)
    return templates.TemplateResponse("clusters.html", context(
        request, clusters=records, inventory=kube.inventory(), jobs=kube.active_jobs(), quota=kube.quota_for(user)))


@app.get("/build", response_class=HTMLResponse)
def build_form(request: Request):
    user = current_user(request)
    return templates.TemplateResponse("build.html", context(
        request, profiles=kube.profiles(), versions=kube.versions(), quota=kube.quota_for(user)))


@app.get("/clusters/{profile}", response_class=HTMLResponse)
def cluster_detail(profile: str, request: Request):
    user = current_user(request)
    record = next((item for item in visible_records(user) if item["profile"] == profile), None)
    live = kube.inventory().get("clusters", {}).get(profile)
    if not record or not live:
        raise HTTPException(404, "Cluster not found")
    return templates.TemplateResponse("cluster.html", context(request, cluster=record, live=live))


@app.post("/build")
async def build(request: Request):
    user = current_user(request)
    form = await request.form()
    verify_csrf(request, str(form.get("csrf", "")))
    profile = str(form.get("profile", ""))
    profiles = kube.profiles()
    if profile not in profiles:
        raise HTTPException(400, "Unknown profile")
    owned = [record for record in kube.cluster_records() if record.get("owner_sub") == user["sub"]]
    pending = [job for job in kube.active_jobs() if job.metadata.labels.get("factory.d00s.org/owner") == owner_id(user)]
    if not is_admin(user) and len(owned) + len(pending) >= kube.quota_for(user):
        raise HTTPException(409, "Your active cluster quota has been reached")
    if (any(record["profile"] == profile for record in kube.cluster_records())
            or profile in kube.inventory().get("clusters", {})):
        raise HTTPException(409, "This profile already has an active cluster")
    version_catalog = kube.versions()
    selected_versions = {}
    for component, allowed in version_catalog.items():
        value = str(form.get(f"version_{component}", ""))
        if value not in {item["value"] for item in allowed}:
            raise HTTPException(400, f"Invalid {component} version")
        selected_versions[component] = value
    ttl = str(form.get("ttl", "24h"))
    if not kube.TTL_RE.fullmatch(ttl):
        raise HTTPException(400, "TTL must look like 24h, 7d, or 2w")
    request_data = {
        "name": profile, "profile": profile,
        "kubernetes_version": selected_versions.pop("kubernetes"),
        "calico_version": selected_versions.pop("calico"),
        "containerd_version": selected_versions.pop("containerd"),
        "argo_chart_version": selected_versions.pop("argocd_chart"),
        "topology": {"control_planes": max(1, min(int(form.get("control_planes", 1)), 3)),
                     "workers": max(0, min(int(form.get("workers", 3)), 6))},
        "storage": {"mode": str(form.get("storage", "nfs"))},
        "addons": {"monitoring": form.get("monitoring") == "on",
                   "metrics_server": form.get("metrics_server") == "on",
                   "test_nginx": True},
        "lifecycle": {"ttl": ttl, "retain_data_on_expiry": False},
        "versions": selected_versions,
        "failure_policy": "rollback",
    }
    if request_data["storage"]["mode"] not in {"nfs", "ceph", "both"}:
        raise HTTPException(400, "Invalid storage selection")
    job_id = kube.submit("create", request_data, user, client_ip(request))
    return RedirectResponse(f"/jobs/{job_id}", status_code=303)


@app.post("/clusters/{profile}/delete")
async def delete_cluster(profile: str, request: Request, csrf: str = Form(...), retain_data: bool = Form(False)):
    user = current_user(request)
    verify_csrf(request, csrf)
    record = next((item for item in kube.cluster_records() if item["profile"] == profile), None)
    if not record:
        raise HTTPException(404, "Cluster record not found")
    if not is_admin(user) and record.get("owner_sub") != user["sub"]:
        raise HTTPException(403, "You do not own this cluster")
    if retain_data and not is_admin(user):
        raise HTTPException(403, "Only administrators can retain cluster data")
    payload = dict(record["request"])
    payload["retain_data"] = retain_data
    job_id = kube.submit("delete", payload, user, client_ip(request))
    return RedirectResponse(f"/jobs/{job_id}", status_code=303)


@app.get("/jobs/{job_id}", response_class=HTMLResponse)
def job_page(job_id: str, request: Request):
    user = current_user(request)
    try:
        job = kube.job_for(job_id)
    except KeyError:
        raise HTTPException(404, "Job not found")
    if not is_admin(user) and job.metadata.labels.get("factory.d00s.org/owner") != owner_id(user):
        raise HTTPException(403, "This job belongs to another user")
    return templates.TemplateResponse("job.html", context(request, job=job, job_id=job_id))


@app.get("/api/jobs/{job_id}/stream")
def job_stream(job_id: str, request: Request):
    user = current_user(request)
    job = kube.job_for(job_id)
    if not is_admin(user) and job.metadata.labels.get("factory.d00s.org/owner") != owner_id(user):
        raise HTTPException(403, "This job belongs to another user")
    pods = kube.core.list_namespaced_pod(kube.NAMESPACE, label_selector=f"job-name={job.metadata.name}").items
    if not pods:
        async def waiting():
            yield "event: stage\ndata: queued\n\n"
        return StreamingResponse(waiting(), media_type="text/event-stream")
    pod = pods[0].metadata.name

    def events():
        seen = 0
        try:
            while True:
                text = kube.core.read_namespaced_pod_log(name=pod, namespace=kube.NAMESPACE, timestamps=True)
                lines = text.splitlines()
                for line in lines[seen:]:
                    event = "stage" if "FACTORY_STAGE" in line else "log"
                    yield f"event: {event}\ndata: {json.dumps(line)}\n\n"
                seen = len(lines)
                state = kube.batch.read_namespaced_job(job.metadata.name, kube.NAMESPACE)
                if state.status.completion_time or (state.status.failed or 0):
                    break
                yield ": keepalive\n\n"
                time.sleep(2)
        except ApiException as exc:
            yield f"event: error\ndata: {json.dumps(str(exc))}\n\n"
        yield "event: done\ndata: complete\n\n"
    return StreamingResponse(events(), media_type="text/event-stream", headers={"X-Accel-Buffering": "no"})


@app.get("/howto", response_class=HTMLResponse)
def howto(request: Request):
    current_user(request)
    return templates.TemplateResponse("howto.html", context(request))


@app.post("/contact")
async def contact(request: Request, csrf: str = Form(...), message: str = Form(...)):
    user = current_user(request)
    verify_csrf(request, csrf)
    message = message.strip()[:4000]
    if len(message) < 10:
        raise HTTPException(400, "Please provide a little more detail")
    email = EmailMessage()
    email["From"] = os.environ["SMTP_USERNAME"]
    email["To"] = os.environ["CONTACT_RECIPIENT"]
    email["Subject"] = f"Cluster Factory contact from {user.get('preferred_username')}"
    email.set_content(f"User: {user.get('preferred_username')}\nSubject: {user.get('sub')}\n\n{message}")
    with smtplib.SMTP(os.getenv("SMTP_HOST", "smtp.gmail.com"), int(os.getenv("SMTP_PORT", "587")), timeout=15) as smtp:
        smtp.starttls(); smtp.login(os.environ["SMTP_USERNAME"], os.environ["SMTP_PASSWORD"]); smtp.send_message(email)
    return RedirectResponse("/clusters?contact=sent", status_code=303)


@app.get("/admin", response_class=HTMLResponse)
def admin(request: Request):
    require_admin(request)
    audits = []
    for cm in kube.labels("factory.d00s.org/type=audit"):
        try: audits.append(json.loads(cm.data["record.json"]))
        except Exception: pass
    audits.sort(key=lambda item: item.get("submitted_at", ""), reverse=True)
    blocks = kube.read_json_configmap("cluster-factory-security-status", "blocks.json", {"active": [], "history": []})
    return templates.TemplateResponse("admin.html", context(
        request, clusters=visible_records(request.session["user"]), audits=audits[:100], policy=kube.policy(),
        inventory=kube.inventory(), blocks=blocks))


@app.post("/admin/policy")
async def admin_policy(request: Request):
    require_admin(request)
    form = await request.form(); verify_csrf(request, str(form.get("csrf", "")))
    current = kube.policy()
    current["default_user_cluster_limit"] = max(1, min(int(form.get("default_limit", 1)), 10))
    subject = str(form.get("user_sub", "")).strip()
    if subject:
        current.setdefault("user_overrides", {})[subject] = max(1, min(int(form.get("user_limit", 1)), 10))
    kube.update_policy(current)
    return RedirectResponse("/admin", status_code=303)
