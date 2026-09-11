import os

os.environ["AUTH_USERS_JSON"] = (
    '[{"username":"student@example.com","role":"student","password":"student-pass"},'
    '{"username":"teacher@example.com","role":"teacher","password":"teacher-pass"},'
    '{"username":"admin@example.com","role":"admin","password":"admin-pass"}]'
)

from fastapi.testclient import TestClient

from src.app import app, active_tokens


client = TestClient(app)


def login(username, password):
    response = client.post("/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200
    return response.json()["access_token"]


def test_login_returns_token_without_storing_plaintext_passwords():
    response = client.post("/auth/login", json={"username": "student@example.com", "password": "student-pass"})

    assert response.status_code == 200
    assert "password" not in str(active_tokens)


def test_protected_enrollment_requires_authentication():
    response = client.post("/activities/Chess Club/signup", params={"email": "student@example.com"})

    assert response.status_code == 401


def test_student_cannot_modify_another_student_profile_or_enrollment():
    token = login("student@example.com", "student-pass")
    headers = {"Authorization": f"Bearer {token}"}

    profile_response = client.patch(
        "/users/teacher@example.com", json={"name": "Changed"}, headers=headers
    )
    enrollment_response = client.post(
        "/activities/Chess Club/signup",
        params={"email": "teacher@example.com"},
        headers=headers,
    )

    assert profile_response.status_code == 403
    assert enrollment_response.status_code == 403


def test_teacher_can_manage_enrollment_and_logout_invalidates_token():
    token = login("teacher@example.com", "teacher-pass")
    headers = {"Authorization": f"Bearer {token}"}

    signup_response = client.post(
        "/activities/Chess Club/signup",
        params={"email": "student2@example.com"},
        headers=headers,
    )
    logout_response = client.post("/auth/logout", headers=headers)
    after_logout_response = client.get("/auth/me", headers=headers)

    assert signup_response.status_code == 200
    assert logout_response.status_code == 200
    assert after_logout_response.status_code == 401