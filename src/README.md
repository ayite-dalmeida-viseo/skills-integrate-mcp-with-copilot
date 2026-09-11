# Mergington High School Activities API

A super simple FastAPI application that allows students to view and sign up for extracurricular activities.

## Features

- View all available extracurricular activities
- Sign up for activities with role-based access control

## Getting Started

1. Install the dependencies:

   ```
   pip install -r ../requirements.txt
   ```

2. Run the application:

   ```
   python app.py
   ```

3. Open your browser and go to:
   - API documentation: http://localhost:8000/docs
   - Alternative documentation: http://localhost:8000/redoc

## API Endpoints

| Method | Endpoint                                                          | Description                                                         |
| ------ | ----------------------------------------------------------------- | ------------------------------------------------------------------- |
| GET    | `/activities`                                                     | Get all activities with their details and current participant count |
| POST   | `/activities/{activity_name}/signup?email=student@mergington.edu` | Sign up for an activity                                             |

## Authentication

Set `AUTH_USERS_JSON` before starting the API. Passwords are hashed with PBKDF2
at startup and only the hashes are retained in memory. The configuration is
never committed to the repository. Example input:

```json
[{"username":"student@mergington.edu","role":"student","password":"change-me"}]
```

Use `POST /auth/login` to receive a bearer token. Authenticated users can call
`/auth/me`, `/users/{username}`, and the enrollment endpoints. Students may
only change their own profile and enrollment; teachers and administrators can
manage enrollment, while administrators can update any profile. `POST
/auth/logout` invalidates the current token.

## Data Model

The application uses a simple data model with meaningful identifiers:

1. **Activities** - Uses activity name as identifier:

   - Description
   - Schedule
   - Maximum number of participants allowed
   - List of student emails who are signed up

2. **Students** - Uses email as identifier:
   - Name
   - Grade level

All data is stored in memory, which means data will be reset when the server restarts.
