"""
End-to-end backend API tests for Rebild Client Portal.
Covers: auth, admin client creation, invoices, updates, tickets, notifications,
role enforcement, services/addons seeded data, and password reset.
"""
import os
import time
import uuid
import requests
import pytest
from pathlib import Path
from dotenv import load_dotenv

# Load frontend .env to get external URL
load_dotenv(Path(__file__).resolve().parents[2] / "frontend" / ".env")

BASE_URL = os.environ["REACT_APP_BACKEND_URL"].rstrip("/")
ADMIN_EMAIL = "admin@rebild.com"
ADMIN_PASSWORD = "Rebild@2026"


# -------- Fixtures --------
@pytest.fixture(scope="session")
def admin_token():
    r = requests.post(f"{BASE_URL}/api/auth/login",
                      json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
                      timeout=15)
    assert r.status_code == 200, f"Admin login failed: {r.status_code} {r.text}"
    data = r.json()
    assert "token" in data and "user" in data
    assert data["user"]["role"] == "admin"
    return data["token"]


@pytest.fixture(scope="session")
def admin_headers(admin_token):
    return {"Authorization": f"Bearer {admin_token}", "Content-Type": "application/json"}


@pytest.fixture(scope="session")
def created_client(admin_headers):
    """Create a fresh test client - returns (client_user, password, token)."""
    suffix = uuid.uuid4().hex[:8]
    email = f"test_client_{suffix}@example.com"
    payload = {"name": f"Test Client {suffix}", "email": email, "company": "Acme", "phone": "+10000000000"}
    r = requests.post(f"{BASE_URL}/api/admin/clients", json=payload, headers=admin_headers, timeout=15)
    assert r.status_code == 200, f"Create client failed: {r.status_code} {r.text}"
    body = r.json()
    assert "user" in body and "generated_password" in body
    assert body["user"]["email"] == email
    assert body["user"]["role"] == "client"
    assert "password_hash" not in body["user"]
    pwd = body["generated_password"]
    # login as the client
    r2 = requests.post(f"{BASE_URL}/api/auth/login", json={"email": email, "password": pwd}, timeout=15)
    assert r2.status_code == 200, f"Client login failed: {r2.status_code} {r2.text}"
    token = r2.json()["token"]
    yield {"user": body["user"], "password": pwd, "token": token, "email": email}
    # teardown
    try:
        requests.delete(f"{BASE_URL}/api/admin/clients/{body['user']['id']}",
                        headers=admin_headers, timeout=15)
    except Exception:
        pass


@pytest.fixture(scope="session")
def client_headers(created_client):
    return {"Authorization": f"Bearer {created_client['token']}", "Content-Type": "application/json"}


# -------- Auth --------
class TestAuth:
    def test_admin_login(self, admin_token):
        assert isinstance(admin_token, str) and len(admin_token) > 20

    def test_auth_me(self, admin_headers):
        r = requests.get(f"{BASE_URL}/api/auth/me", headers=admin_headers, timeout=15)
        assert r.status_code == 200
        data = r.json()
        assert data["email"] == ADMIN_EMAIL
        assert data["role"] == "admin"
        assert "password_hash" not in data

    def test_login_invalid(self):
        r = requests.post(f"{BASE_URL}/api/auth/login",
                          json={"email": ADMIN_EMAIL, "password": "wrong"}, timeout=15)
        assert r.status_code == 401

    def test_me_without_token(self):
        r = requests.get(f"{BASE_URL}/api/auth/me", timeout=15)
        assert r.status_code == 401


# -------- Seeded catalog --------
class TestCatalog:
    def test_services_seeded(self, admin_headers):
        r = requests.get(f"{BASE_URL}/api/services", headers=admin_headers, timeout=15)
        assert r.status_code == 200
        items = r.json()
        assert isinstance(items, list) and len(items) >= 1
        assert all("id" in s and "name" in s for s in items)

    def test_addons_seeded(self, admin_headers):
        r = requests.get(f"{BASE_URL}/api/addons", headers=admin_headers, timeout=15)
        assert r.status_code == 200
        items = r.json()
        assert isinstance(items, list) and len(items) >= 1
        assert all("price" in a for a in items)

    def test_services_requires_auth(self):
        r = requests.get(f"{BASE_URL}/api/services", timeout=15)
        assert r.status_code == 401


# -------- Client lifecycle + login --------
class TestClientLifecycle:
    def test_client_can_login(self, created_client):
        assert created_client["token"]

    def test_admin_list_clients_includes_created(self, admin_headers, created_client):
        r = requests.get(f"{BASE_URL}/api/admin/clients", headers=admin_headers, timeout=15)
        assert r.status_code == 200
        emails = [c["email"] for c in r.json()]
        assert created_client["email"] in emails

    def test_reset_password_and_login(self, admin_headers, created_client):
        cid = created_client["user"]["id"]
        r = requests.post(f"{BASE_URL}/api/admin/clients/{cid}/reset-password",
                          json={}, headers=admin_headers, timeout=15)
        assert r.status_code == 200
        new_pwd = r.json()["generated_password"]
        assert new_pwd and new_pwd != created_client["password"]
        # old password should fail
        r_old = requests.post(f"{BASE_URL}/api/auth/login",
                              json={"email": created_client["email"], "password": created_client["password"]}, timeout=15)
        assert r_old.status_code == 401
        # new password should succeed
        r_new = requests.post(f"{BASE_URL}/api/auth/login",
                              json={"email": created_client["email"], "password": new_pwd}, timeout=15)
        assert r_new.status_code == 200
        # update fixture token for subsequent tests
        created_client["token"] = r_new.json()["token"]
        created_client["password"] = new_pwd


# -------- Role enforcement --------
class TestRoleEnforcement:
    def test_client_blocked_from_admin_endpoint(self, created_client):
        headers = {"Authorization": f"Bearer {created_client['token']}"}
        r = requests.get(f"{BASE_URL}/api/admin/clients", headers=headers, timeout=15)
        assert r.status_code == 403

    def test_client_blocked_from_admin_stats(self, created_client):
        headers = {"Authorization": f"Bearer {created_client['token']}"}
        r = requests.get(f"{BASE_URL}/api/admin/stats", headers=headers, timeout=15)
        assert r.status_code == 403


# -------- Dashboards --------
class TestDashboards:
    def test_admin_stats(self, admin_headers):
        r = requests.get(f"{BASE_URL}/api/admin/stats", headers=admin_headers, timeout=15)
        assert r.status_code == 200
        data = r.json()
        for key in ["total_clients", "active_clients", "open_invoices", "revenue",
                    "pending_revenue", "open_tickets", "addon_pending"]:
            assert key in data

    def test_client_dashboard(self, created_client):
        headers = {"Authorization": f"Bearer {created_client['token']}"}
        r = requests.get(f"{BASE_URL}/api/client/dashboard", headers=headers, timeout=15)
        assert r.status_code == 200
        data = r.json()
        assert "user" in data and data["user"]["email"] == created_client["email"]
        assert "open_invoices_count" in data


# -------- Invoices --------
class TestInvoices:
    invoice_id = None

    def test_create_invoice(self, admin_headers, created_client):
        payload = {
            "client_id": created_client["user"]["id"],
            "items": [{"description": "Ad management", "qty": 1, "unit_price": 1500.0}],
            "tax": 150.0, "memo": "TEST_INV"
        }
        r = requests.post(f"{BASE_URL}/api/admin/invoices", json=payload, headers=admin_headers, timeout=15)
        assert r.status_code == 200, r.text
        inv = r.json()
        assert inv["total"] == 1650.0
        assert inv["status"] == "open"
        assert inv["number"].startswith("INV-")
        TestInvoices.invoice_id = inv["id"]

    def test_client_sees_invoice(self, created_client):
        headers = {"Authorization": f"Bearer {created_client['token']}"}
        r = requests.get(f"{BASE_URL}/api/client/invoices", headers=headers, timeout=15)
        assert r.status_code == 200
        ids = [i["id"] for i in r.json()]
        assert TestInvoices.invoice_id in ids

    def test_client_pays_invoice(self, created_client):
        headers = {"Authorization": f"Bearer {created_client['token']}"}
        r = requests.post(f"{BASE_URL}/api/client/invoices/{TestInvoices.invoice_id}/pay",
                          headers=headers, timeout=15)
        assert r.status_code == 200
        # verify status persisted
        r2 = requests.get(f"{BASE_URL}/api/client/invoices", headers=headers, timeout=15)
        inv = next(i for i in r2.json() if i["id"] == TestInvoices.invoice_id)
        assert inv["status"] == "paid"
        assert inv["paid_at"]


# -------- Updates (broadcast) --------
class TestUpdates:
    def test_broadcast_update(self, admin_headers, created_client):
        payload = {"title": "TEST Broadcast", "body": "Hello all", "client_id": None, "category": "Announcement"}
        r = requests.post(f"{BASE_URL}/api/admin/updates", json=payload, headers=admin_headers, timeout=15)
        assert r.status_code == 200
        up = r.json()
        assert up["client_id"] is None
        # client should see it
        headers = {"Authorization": f"Bearer {created_client['token']}"}
        r2 = requests.get(f"{BASE_URL}/api/client/updates", headers=headers, timeout=15)
        assert r2.status_code == 200
        titles = [u["title"] for u in r2.json()]
        assert "TEST Broadcast" in titles


# -------- Tickets --------
class TestTickets:
    ticket_id = None

    def test_client_creates_ticket(self, created_client):
        headers = {"Authorization": f"Bearer {created_client['token']}"}
        payload = {"subject": "TEST_TICKET", "message": "Need help", "priority": "high"}
        r = requests.post(f"{BASE_URL}/api/client/tickets", json=payload, headers=headers, timeout=15)
        assert r.status_code == 200
        t = r.json()
        assert t["subject"] == "TEST_TICKET"
        assert len(t["messages"]) == 1
        TestTickets.ticket_id = t["id"]

    def test_admin_replies(self, admin_headers):
        r = requests.post(f"{BASE_URL}/api/admin/tickets/{TestTickets.ticket_id}/messages",
                          json={"message": "We are on it"}, headers=admin_headers, timeout=15)
        assert r.status_code == 200
        # verify reply persisted
        r2 = requests.get(f"{BASE_URL}/api/admin/tickets", headers=admin_headers, timeout=15)
        ticket = next(t for t in r2.json() if t["id"] == TestTickets.ticket_id)
        assert ticket["status"] == "pending"
        assert any(m["author_role"] == "admin" for m in ticket["messages"])


# -------- Notifications --------
class TestNotifications:
    def test_client_has_notifications(self, created_client):
        headers = {"Authorization": f"Bearer {created_client['token']}"}
        r = requests.get(f"{BASE_URL}/api/notifications", headers=headers, timeout=15)
        assert r.status_code == 200
        items = r.json()
        # we created invoice + broadcast update + ticket reply for this client
        assert isinstance(items, list) and len(items) >= 1

    def test_mark_all_read(self, created_client):
        headers = {"Authorization": f"Bearer {created_client['token']}"}
        r = requests.post(f"{BASE_URL}/api/notifications/mark-all-read", headers=headers, timeout=15)
        assert r.status_code == 200
        r2 = requests.get(f"{BASE_URL}/api/notifications", headers=headers, timeout=15)
        unread = [n for n in r2.json() if not n.get("read")]
        assert unread == []
