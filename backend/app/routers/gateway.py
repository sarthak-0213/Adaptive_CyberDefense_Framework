import logging
import os
import re
import json
import time
import urllib.parse
from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
import httpx

from app.core.config import settings
from app.core.database import SessionLocal
from app.utils.deps import get_db
from app.services.threat_correlation import threat_correlation
from app.services.threat_mitigation import threat_mitigation_service
from app.services.mtd_service import mtd_service
from app.services.risk_engine import risk_engine
from app.models.gateway_log import GatewayRequestLog
from app.models.threat_event import ThreatScore

logger = logging.getLogger("gateway")

router = APIRouter(prefix="/gateway", tags=["Security Gateway"])

UPSTREAM_BASE_URL = os.environ.get("SECURESHOP_UPSTREAM_URL", "http://127.0.0.1:8001").rstrip("/")

# Track rapid failed logins per IP: ip -> list of timestamps
_failed_login_tracker: Dict[str, List[float]] = defaultdict(list)

# Common web attack payload signatures
ATTACK_PATTERNS = [
    (re.compile(r"(\bor\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+|union\s+select|;\s*drop\s+table)", re.IGNORECASE), "sql_injection"),
    (re.compile(r"(<script.*?>|javascript:|onerror\s*=|onload\s*=)", re.IGNORECASE), "cross_site_scripting"),
    (re.compile(r"(\.\./\.\.|\.\./|\.\.\\|etc/passwd|windows/win\.ini)", re.IGNORECASE), "directory_traversal"),
]

# Gateway decoy paths that act as honeypots
GATEWAY_DECOYS = {
    "api/admin/debug",
    "admin/debug",
    "api/system/env",
    "admin/config.php",
    ".env",
    "wp-admin",
    "api/auth/keys",
}

# Permitted SecureShop API path prefixes (SSRF / Open Proxy prevention)
PERMITTED_PATH_PREFIXES = [
    "api/products",
    "api/orders",
    "api/auth",
    "api/admin/dashboard",
    "health",
    "api/health",
]

HOP_BY_HOP_HEADERS: Set[str] = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
}


def get_client_ip(request: Request) -> str:
    """Resolve client IP safely respecting trusted proxy headers."""
    x_forwarded_for = request.headers.get("x-forwarded-for")
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0].strip()
    return request.client.host if request.client else "127.0.0.1"


def get_current_risk_score(db: Session, ip_address: str) -> float:
    """Look up current risk score for telemetry logging."""
    score_rec = db.query(ThreatScore).filter(ThreatScore.ip_address == ip_address).first()
    return round(score_rec.current_score, 2) if score_rec else 0.0


def log_telemetry(
    db: Session,
    ip_address: str,
    method: str,
    endpoint: str,
    status_code: int,
    response_time_ms: float,
    classification: str,
    detection_result: Optional[str] = None,
    risk_score: Optional[float] = 0.0,
    mitigation_action: Optional[str] = "none",
) -> None:
    """Persist gateway request telemetry to the database."""
    try:
        log_entry = GatewayRequestLog(
            ip_address=ip_address,
            method=method[:10],
            endpoint=endpoint,
            status_code=status_code,
            response_time_ms=round(response_time_ms, 2),
            classification=classification,
            detection_result=detection_result,
            risk_score=risk_score,
            mitigation_action=mitigation_action,
        )
        db.add(log_entry)
        db.commit()
    except Exception as e:
        logger.error(f"[Gateway Telemetry] Failed to save request log: {e}")
        db.rollback()


def inspect_payload(content: str) -> Optional[str]:
    for pattern, attack_name in ATTACK_PATTERNS:
        if pattern.search(content):
            return attack_name
    return None


def is_path_permitted(normalized_path: str) -> bool:
    """Check if the requested path falls within permitted SecureShop API routes."""
    for prefix in PERMITTED_PATH_PREFIXES:
        if normalized_path == prefix or normalized_path.startswith(prefix + "/"):
            return True
    return False


async def handle_proxy_request(path: str, request: Request, db: Session, route_prefix: str = "/gateway") -> Response:
    """Core proxy and threat detection logic."""
    start_time = time.perf_counter()
    client_ip = get_client_ip(request)
    normalized_path = path.strip("/")
    endpoint_display = f"{route_prefix}/{normalized_path}"

    # ── 1. Check if client IP is blocked by Threat Mitigation ───────────────────
    if threat_mitigation_service.is_ip_blocked(db, client_ip):
        logger.warning(f"[Gateway] Blocked IP {client_ip} attempted to access {endpoint_display}")
        curr_score = get_current_risk_score(db, client_ip)
        latency = (time.perf_counter() - start_time) * 1000
        log_telemetry(
            db=db,
            ip_address=client_ip,
            method=request.method,
            endpoint=endpoint_display,
            status_code=status.HTTP_403_FORBIDDEN,
            response_time_ms=latency,
            classification="blocked",
            detection_result="ip_denylisted",
            risk_score=curr_score,
            mitigation_action="blocked_403",
        )
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"detail": "Forbidden: IP address is currently blocked by Adaptive Cyber Defense"}
        )

    # ── 2. Decoy / Honeypot Interception ─────────────────────────────────────────
    if normalized_path in GATEWAY_DECOYS:
        logger.warning(f"[Gateway] Honeypot triggered on {endpoint_display} by IP {client_ip}")
        headers = dict(request.headers)
        user_agent = headers.get("user-agent", "unknown")
        mtd_service.log_honeypot_trigger(
            path=endpoint_display,
            ip_address=client_ip,
            user_agent=user_agent,
            headers=headers
        )
        threat_correlation.on_honeypot_hit(db, client_ip, endpoint_display)
        curr_score = get_current_risk_score(db, client_ip)
        latency = (time.perf_counter() - start_time) * 1000
        log_telemetry(
            db=db,
            ip_address=client_ip,
            method=request.method,
            endpoint=endpoint_display,
            status_code=status.HTTP_404_NOT_FOUND,
            response_time_ms=latency,
            classification="honeypot",
            detection_result="honeypot_hit",
            risk_score=curr_score,
            mitigation_action="decoy_404",
        )
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"detail": "Not Found"}
        )

    # ── 3. SSRF & Path Whitelist Enforcement ────────────────────────────────────
    # Prevent arbitrary scheme injection, colon abuse, directory traversal
    if "://" in path or ".." in path or "\\" in path or not is_path_permitted(normalized_path):
        logger.warning(f"[Gateway] Blocked unauthorized or malformed endpoint access: {endpoint_display} from {client_ip}")
        risk_engine.record_event(
            db=db,
            ip_address=client_ip,
            event_type="direct_protected_path",
            source="gateway_filter",
            metadata={"path": endpoint_display, "reason": "unauthorized_endpoint_attempt"}
        )
        curr_score = get_current_risk_score(db, client_ip)
        latency = (time.perf_counter() - start_time) * 1000
        log_telemetry(
            db=db,
            ip_address=client_ip,
            method=request.method,
            endpoint=endpoint_display,
            status_code=status.HTTP_404_NOT_FOUND,
            response_time_ms=latency,
            classification="suspicious",
            detection_result="unauthorized_endpoint",
            risk_score=curr_score,
            mitigation_action="decoy_404",
        )
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"detail": "Not Found"}
        )

    # ── 4. WAF & Input Validation ────────────────────────────────────────────────
    raw_query_str = str(request.query_params)
    query_str = urllib.parse.unquote_plus(raw_query_str)
    attack_detected = inspect_payload(query_str)

    body_bytes = b""
    if request.method in ["POST", "PUT", "PATCH"]:
        body_bytes = await request.body()
        if not attack_detected and body_bytes:
            try:
                body_str = urllib.parse.unquote_plus(body_bytes.decode("utf-8", errors="ignore"))
                attack_detected = inspect_payload(body_str)
            except Exception:
                pass

    if attack_detected:
        logger.warning(f"[Gateway WAF] {attack_detected} detected from IP {client_ip} on {endpoint_display}")
        risk_engine.record_event(
            db=db,
            ip_address=client_ip,
            event_type="direct_protected_path",
            source="gateway_waf",
            metadata={"attack": attack_detected, "path": endpoint_display}
        )
        curr_score = get_current_risk_score(db, client_ip)
        latency = (time.perf_counter() - start_time) * 1000
        log_telemetry(
            db=db,
            ip_address=client_ip,
            method=request.method,
            endpoint=endpoint_display,
            status_code=status.HTTP_400_BAD_REQUEST,
            response_time_ms=latency,
            classification="attack",
            detection_result=attack_detected,
            risk_score=curr_score,
            mitigation_action="waf_rejected_400",
        )
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "detail": f"Security violation: {attack_detected.replace('_', ' ').title()} payload detected",
                "attack_type": attack_detected
            }
        )

    # ── 5. Forward Request to Upstream Service ──────────────────────────────────
    upstream_url = f"{UPSTREAM_BASE_URL}/{normalized_path}"
    if query_str:
        upstream_url = f"{upstream_url}?{query_str}"

    # Filter hop-by-hop headers to prevent connection corruptions
    forward_headers = {
        k: v for k, v in request.headers.items()
        if k.lower() not in HOP_BY_HOP_HEADERS
    }
    forward_headers["x-forwarded-for"] = client_ip

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            upstream_resp = await client.request(
                method=request.method,
                url=upstream_url,
                headers=forward_headers,
                content=body_bytes,
            )
    except httpx.ConnectError:
        logger.error(f"[Gateway] Failed to connect to upstream service at {UPSTREAM_BASE_URL}")
        curr_score = get_current_risk_score(db, client_ip)
        latency = (time.perf_counter() - start_time) * 1000
        log_telemetry(
            db=db,
            ip_address=client_ip,
            method=request.method,
            endpoint=endpoint_display,
            status_code=status.HTTP_502_BAD_GATEWAY,
            response_time_ms=latency,
            classification="suspicious",
            detection_result="upstream_unavailable",
            risk_score=curr_score,
            mitigation_action="none",
        )
        return JSONResponse(
            status_code=status.HTTP_502_BAD_GATEWAY,
            content={"detail": "Upstream test website service unavailable. Ensure SecureShop backend is running."}
        )
    except httpx.TimeoutException:
        logger.error(f"[Gateway] Request timed out connecting to {UPSTREAM_BASE_URL}")
        curr_score = get_current_risk_score(db, client_ip)
        latency = (time.perf_counter() - start_time) * 1000
        log_telemetry(
            db=db,
            ip_address=client_ip,
            method=request.method,
            endpoint=endpoint_display,
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            response_time_ms=latency,
            classification="suspicious",
            detection_result="upstream_timeout",
            risk_score=curr_score,
            mitigation_action="none",
        )
        return JSONResponse(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            content={"detail": "Gateway timed out waiting for upstream response."}
        )

    # ── 6. Post-Response Security Analysis (Auth Monitoring) ────────────────────
    classification = "legitimate"
    detection_result = "none"

    if normalized_path == "api/auth/login" and request.method == "POST":
        email = "unknown"
        try:
            body_json = json.loads(body_bytes.decode("utf-8", errors="ignore"))
            email = body_json.get("email", "unknown")
        except Exception:
            pass

        if upstream_resp.status_code == 401:
            classification = "suspicious"
            detection_result = "failed_login"
            logger.warning(f"[Gateway] Failed login attempt for '{email}' from IP {client_ip}")
            threat_correlation.on_failed_login(db, client_ip, email)

            # Rapid failed login check (sliding 30-second window)
            now_ts = datetime.now(timezone.utc).timestamp()
            recent_attempts = [t for t in _failed_login_tracker[client_ip] if now_ts - t < 30.0]
            recent_attempts.append(now_ts)
            _failed_login_tracker[client_ip] = recent_attempts

            if len(recent_attempts) >= 3:
                classification = "attack"
                detection_result = "brute_force"
                logger.warning(f"[Gateway] Rapid failed logins detected ({len(recent_attempts)}) from IP {client_ip}")
                threat_correlation.on_rapid_login_attempt(db, client_ip)

    curr_score = get_current_risk_score(db, client_ip)
    latency = (time.perf_counter() - start_time) * 1000

    log_telemetry(
        db=db,
        ip_address=client_ip,
        method=request.method,
        endpoint=endpoint_display,
        status_code=upstream_resp.status_code,
        response_time_ms=latency,
        classification=classification,
        detection_result=detection_result,
        risk_score=curr_score,
        mitigation_action="none",
    )

    # Pass through response excluding hop-by-hop headers
    resp_headers = {
        k: v for k, v in upstream_resp.headers.items()
        if k.lower() not in HOP_BY_HOP_HEADERS
    }

    return Response(
        content=upstream_resp.content,
        status_code=upstream_resp.status_code,
        headers=resp_headers,
        media_type=upstream_resp.headers.get("content-type")
    )


# Primary route for SecureShop: /gateway/secureshop/...
@router.api_route("/secureshop/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
async def gateway_proxy_secureshop(path: str, request: Request, db: Session = Depends(get_db)):
    return await handle_proxy_request(path, request, db, route_prefix="/gateway/secureshop")


# Backward-compatible route: /gateway/...
@router.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
async def gateway_proxy_general(path: str, request: Request, db: Session = Depends(get_db)):
    # If path already starts with secureshop/, handle it via secureshop prefix
    if path.startswith("secureshop/"):
        sub_path = path[len("secureshop/"):]
        return await handle_proxy_request(sub_path, request, db, route_prefix="/gateway/secureshop")
    return await handle_proxy_request(path, request, db, route_prefix="/gateway")
