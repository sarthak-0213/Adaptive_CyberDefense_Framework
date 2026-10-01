import pytest
from fastapi import status
from sqlalchemy.orm import Session
from app.models.audit_log import AuditLog
from app.models.security_assessment import SecurityAssessment, AssessmentResult, SecurityFinding


def _get_token_for_role(client, role: str):
    email = f"assessment_{role}@defense.com"
    try:
        client.post(
            "/api/v1/auth/register",
            json={"email": email, "password": "password123", "role": role}
        )
    except Exception:
        pass
    resp = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "password123"}
    )
    return resp.json()["access_token"]


def test_assessment_rbac_authorization(client):
    admin_token = _get_token_for_role(client, "admin")
    user_token = _get_token_for_role(client, "user")

    # 1. Unauthenticated request to run assessment -> 401
    resp_unauth = client.post(
        "/api/v1/security-assessment/run",
        json={"target": "localhost:8000", "authorized": True}
    )
    assert resp_unauth.status_code == status.HTTP_401_UNAUTHORIZED

    # 2. Normal user request to run assessment -> 403
    resp_user = client.post(
        "/api/v1/security-assessment/run",
        headers={"Authorization": f"Bearer {user_token}"},
        json={"target": "localhost:8000", "authorized": True}
    )
    assert resp_user.status_code == status.HTTP_403_FORBIDDEN

    # 3. Admin request to run assessment -> 200
    resp_admin = client.post(
        "/api/v1/security-assessment/run",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"target": "localhost:8000", "authorized": True}
    )
    assert resp_admin.status_code == status.HTTP_200_OK
    data = resp_admin.json()
    assert data["target"] == "localhost:8000"
    assert data["status"] == "completed"
    assert "summary" in data
    assert data["summary"]["total_checks"] > 0


def test_network_recon_endpoint(client):
    user_token = _get_token_for_role(client, "user")
    resp = client.get(
        "/api/v1/security-assessment/network?target=localhost:8000",
        headers={"Authorization": f"Bearer {user_token}"}
    )
    assert resp.status_code == status.HTTP_200_OK
    data = resp.json()
    assert data["target"] == "localhost:8000"
    assert "dns" in data
    assert "dhcp" in data
    assert "services" in data
    assert len(data["services"]) > 0


def test_portal_analysis_endpoint(client):
    user_token = _get_token_for_role(client, "user")
    resp = client.get(
        "/api/v1/security-assessment/portal?target=localhost:8000",
        headers={"Authorization": f"Bearer {user_token}"}
    )
    assert resp.status_code == status.HTTP_200_OK
    data = resp.json()
    assert "redirect_chain" in data
    assert len(data["redirect_chain"]) >= 1
    assert "auth_endpoint" in data


def test_http_https_analysis_endpoint(client):
    user_token = _get_token_for_role(client, "user")
    resp = client.get(
        "/api/v1/security-assessment/http-https?target=localhost:8000",
        headers={"Authorization": f"Bearer {user_token}"}
    )
    assert resp.status_code == status.HTTP_200_OK
    data = resp.json()
    assert "https_status" in data
    assert "redirect_status" in data
    assert "login_transport" in data
    assert "explanation" in data


def test_session_analysis_endpoint(client):
    user_token = _get_token_for_role(client, "user")
    resp = client.get(
        "/api/v1/security-assessment/session?target=localhost:8000",
        headers={"Authorization": f"Bearer {user_token}"}
    )
    assert resp.status_code == status.HTTP_200_OK
    data = resp.json()
    assert "JWT" in data["auth_mechanism"]
    assert "Configured" in data["expiration_configured"]
    assert data["logout_invalidation"] == "PASS"


def test_access_control_analysis_endpoint(client):
    user_token = _get_token_for_role(client, "user")
    resp = client.get(
        "/api/v1/security-assessment/access-control?target=localhost:8000",
        headers={"Authorization": f"Bearer {user_token}"}
    )
    assert resp.status_code == status.HTTP_200_OK
    data = resp.json()
    assert "test_cases" in data
    assert len(data["test_cases"]) >= 4
    # verify expected status codes exist in test cases
    expected_codes = [tc["expected"] for tc in data["test_cases"]]
    assert 401 in expected_codes
    assert 403 in expected_codes
    assert 200 in expected_codes


def test_segmentation_endpoint(client):
    user_token = _get_token_for_role(client, "user")
    resp = client.get(
        "/api/v1/security-assessment/segmentation?target=localhost:8000",
        headers={"Authorization": f"Bearer {user_token}"}
    )
    assert resp.status_code == status.HTTP_200_OK
    data = resp.json()
    assert "client_isolation" in data
    assert "authorized_paths" in data
    assert len(data["authorized_paths"]) > 0


def test_hardening_checklist_endpoint(client):
    user_token = _get_token_for_role(client, "user")
    resp = client.get(
        "/api/v1/security-assessment/hardening?target=localhost:8000",
        headers={"Authorization": f"Bearer {user_token}"}
    )
    assert resp.status_code == status.HTTP_200_OK
    data = resp.json()
    assert "categories" in data
    cat_names = [c["category"] for c in data["categories"]]
    assert "TRANSPORT SECURITY" in cat_names
    assert "SESSION SECURITY" in cat_names
    assert "ACCESS CONTROL" in cat_names
    assert "NETWORK SECURITY" in cat_names
    assert "APPLICATION SECURITY" in cat_names


def test_assessment_audit_logging(client, db_session: Session):
    admin_token = _get_token_for_role(client, "admin")

    resp = client.post(
        "/api/v1/security-assessment/run",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"target": "localhost:8000", "authorized": True}
    )
    assert resp.status_code == status.HTTP_200_OK

    logs = db_session.query(AuditLog).all()
    actions = [l.action for l in logs]
    assert "SECURITY_ASSESSMENT_STARTED" in actions
    assert "SECURITY_ASSESSMENT_COMPLETED" in actions


def test_report_generation_and_export_security_assessment(client):
    admin_token = _get_token_for_role(client, "admin")

    # 1. Generate Security Assessment Report
    resp = client.post(
        "/api/v1/reports/generate",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"report_type": "security_assessment", "format": "JSON"}
    )
    assert resp.status_code == status.HTTP_200_OK
    data = resp.json()
    assert data["title"] == "Security Assessment Report"
    assert len(data["data"]) > 0

    categories = set(d["category"] for d in data["data"])
    assert "1. Assessment Scope" in categories
    assert "2. Network Observations" in categories
    assert "4. HTTP/HTTPS Analysis" in categories
    assert "5. Session Analysis" in categories
    assert "6. Access-Control Results" in categories
    assert "7. Network Segmentation" in categories
    assert "10. Recommendations" in categories

    # 2. Export Security Assessment Report as CSV
    resp_csv = client.get(
        "/api/v1/reports/export/security_assessment?format=CSV",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert resp_csv.status_code == status.HTTP_200_OK
    assert "Category,Key,Value" in resp_csv.text
