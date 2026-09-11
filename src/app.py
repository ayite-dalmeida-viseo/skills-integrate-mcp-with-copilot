"""
High School Management System API

A super simple FastAPI application that allows students to view and sign up
for extracurricular activities at Mergington High School.
"""

import hashlib
import json
import os
import secrets
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse

app = FastAPI(title="Mergington High School API",
              description="API for viewing and signing up for extracurricular activities")

# Mount the static files directory
current_dir = Path(__file__).parent
app.mount("/static", StaticFiles(directory=os.path.join(Path(__file__).parent,
          "static")), name="static")

security = HTTPBearer(auto_error=False)
PASSWORD_ITERATIONS = 600_000
VALID_ROLES = {"student", "teacher", "admin"}


def hash_password(password: str) -> str:
    """Create a salted PBKDF2 password hash for persistent configuration."""
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt, PASSWORD_ITERATIONS
    )
    return f"pbkdf2_sha256${PASSWORD_ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        algorithm, iterations, salt, expected = stored_hash.split("$")
        if algorithm != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), bytes.fromhex(salt), int(iterations)
        )
        return secrets.compare_digest(digest.hex(), expected)
    except (TypeError, ValueError):
        return False


def load_users() -> dict:
    """Load users from environment and retain only password hashes in memory."""
    configured_users = os.getenv("AUTH_USERS_JSON", "[]")
    try:
        user_records = json.loads(configured_users)
    except json.JSONDecodeError as error:
        raise RuntimeError("AUTH_USERS_JSON must contain valid JSON") from error

    users = {}
    for record in user_records:
        username = record.get("username")
        role = record.get("role")
        password = record.get("password")
        if not username or role not in VALID_ROLES or not password:
            raise RuntimeError(
                "Each configured user needs a username, role, and password"
            )
        users[username] = {"role": role, "password_hash": hash_password(password)}
    return users


users = load_users()
active_tokens = {}
profiles = {}


class LoginRequest(BaseModel):
    username: str
    password: str


class ProfileUpdate(BaseModel):
    name: str | None = None
    grade: str | None = None
    contact: str | None = None


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
):
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    username = active_tokens.get(credentials.credentials)
    if username is None or username not in users:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return {"username": username, "role": users[username]["role"]}

# In-memory activity database
activities = {
    "Chess Club": {
        "description": "Learn strategies and compete in chess tournaments",
        "schedule": "Fridays, 3:30 PM - 5:00 PM",
        "max_participants": 12,
        "participants": ["michael@mergington.edu", "daniel@mergington.edu"]
    },
    "Programming Class": {
        "description": "Learn programming fundamentals and build software projects",
        "schedule": "Tuesdays and Thursdays, 3:30 PM - 4:30 PM",
        "max_participants": 20,
        "participants": ["emma@mergington.edu", "sophia@mergington.edu"]
    },
    "Gym Class": {
        "description": "Physical education and sports activities",
        "schedule": "Mondays, Wednesdays, Fridays, 2:00 PM - 3:00 PM",
        "max_participants": 30,
        "participants": ["john@mergington.edu", "olivia@mergington.edu"]
    },
    "Soccer Team": {
        "description": "Join the school soccer team and compete in matches",
        "schedule": "Tuesdays and Thursdays, 4:00 PM - 5:30 PM",
        "max_participants": 22,
        "participants": ["liam@mergington.edu", "noah@mergington.edu"]
    },
    "Basketball Team": {
        "description": "Practice and play basketball with the school team",
        "schedule": "Wednesdays and Fridays, 3:30 PM - 5:00 PM",
        "max_participants": 15,
        "participants": ["ava@mergington.edu", "mia@mergington.edu"]
    },
    "Art Club": {
        "description": "Explore your creativity through painting and drawing",
        "schedule": "Thursdays, 3:30 PM - 5:00 PM",
        "max_participants": 15,
        "participants": ["amelia@mergington.edu", "harper@mergington.edu"]
    },
    "Drama Club": {
        "description": "Act, direct, and produce plays and performances",
        "schedule": "Mondays and Wednesdays, 4:00 PM - 5:30 PM",
        "max_participants": 20,
        "participants": ["ella@mergington.edu", "scarlett@mergington.edu"]
    },
    "Math Club": {
        "description": "Solve challenging problems and participate in math competitions",
        "schedule": "Tuesdays, 3:30 PM - 4:30 PM",
        "max_participants": 10,
        "participants": ["james@mergington.edu", "benjamin@mergington.edu"]
    },
    "Debate Team": {
        "description": "Develop public speaking and argumentation skills",
        "schedule": "Fridays, 4:00 PM - 5:30 PM",
        "max_participants": 12,
        "participants": ["charlotte@mergington.edu", "henry@mergington.edu"]
    }
}


@app.get("/")
def root():
    return RedirectResponse(url="/static/index.html")


@app.get("/activities")
def get_activities():
    return activities


@app.post("/auth/login")
def login(request: LoginRequest):
    user = users.get(request.username)
    if user is None or not verify_password(request.password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = secrets.token_urlsafe(32)
    active_tokens[token] = request.username
    return {"access_token": token, "token_type": "bearer", "role": user["role"]}


@app.post("/auth/logout")
def logout(
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
    current_user=Depends(get_current_user),
):
    active_tokens.pop(credentials.credentials, None)
    return {"message": f"Logged out {current_user['username']}"}


@app.get("/auth/me")
def get_current_profile(current_user=Depends(get_current_user)):
    profile = profiles.get(current_user["username"], {})
    return {"username": current_user["username"], "role": current_user["role"], **profile}


@app.get("/users/{username}")
def get_profile(username: str, current_user=Depends(get_current_user)):
    if current_user["role"] == "student" and current_user["username"] != username:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Students can only view their own profile")
    if username not in users:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return {"username": username, "role": users[username]["role"], **profiles.get(username, {})}


@app.patch("/users/{username}")
def update_profile(
    username: str,
    update: ProfileUpdate,
    current_user=Depends(get_current_user),
):
    if current_user["role"] != "admin" and current_user["username"] != username:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="You can only modify your own profile")
    if username not in users:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    profiles.setdefault(username, {}).update(update.model_dump(exclude_unset=True))
    return {"username": username, "role": users[username]["role"], **profiles[username]}


@app.post("/activities/{activity_name}/signup")
def signup_for_activity(activity_name: str, email: str,
                        current_user=Depends(get_current_user)):
    """Sign up a student for an activity"""
    if current_user["role"] == "student" and current_user["username"] != email:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Students can only manage their own enrollment")
    # Validate activity exists
    if activity_name not in activities:
        raise HTTPException(status_code=404, detail="Activity not found")

    # Get the specific activity
    activity = activities[activity_name]

    # Validate student is not already signed up
    if email in activity["participants"]:
        raise HTTPException(
            status_code=400,
            detail="Student is already signed up"
        )

    # Add student
    activity["participants"].append(email)
    return {"message": f"Signed up {email} for {activity_name}"}


@app.delete("/activities/{activity_name}/unregister")
def unregister_from_activity(activity_name: str, email: str,
                             current_user=Depends(get_current_user)):
    """Unregister a student from an activity"""
    if current_user["role"] == "student" and current_user["username"] != email:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Students can only manage their own enrollment")
    # Validate activity exists
    if activity_name not in activities:
        raise HTTPException(status_code=404, detail="Activity not found")

    # Get the specific activity
    activity = activities[activity_name]

    # Validate student is signed up
    if email not in activity["participants"]:
        raise HTTPException(
            status_code=400,
            detail="Student is not signed up for this activity"
        )

    # Remove student
    activity["participants"].remove(email)
    return {"message": f"Unregistered {email} from {activity_name}"}
