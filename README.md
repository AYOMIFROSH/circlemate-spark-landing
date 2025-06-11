# CircleMate API Documentation

**Base URL:**  
- Development: `http://localhost:3000/api/v1`
- Production: `https://<your-production-domain>/api/v1`

## Authentication

All endpoints that require authentication expect a valid JWT token in the `Authorization` header as `Bearer <token>`.

---

## Endpoints

### Auth

#### Signup

- **POST** `/api/v1/auth/signup`
- **Body:**
  ```json
  {
    "email": "user@example.com",
    "password": "yourPassword",
    "name": "User Name"
  }
  ```
- **Response:**
  - `201 Created` on success
  - `409 Conflict` if email already exists

#### Login

- **POST** `/api/v1/auth/login`
- **Body:**
  ```json
  {
    "email": "user@example.com",
    "password": "yourPassword"
  }
  ```
- **Response:**
  - `200 OK` with JWT token and user info
  - `401 Unauthorized` on invalid credentials

#### Logout

- **POST** `/api/v1/auth/logout`
- **Headers:** `Authorization: Bearer <token>`
- **Response:** `200 OK`

#### Email Verification

- **GET** `/api/v1/auth/verify/:userId/:uniqueString`
- **Response:**  
  - `200 OK` on success
  - `400/404` on failure

#### Forgot Password

- **POST** `/api/v1/auth/forgotpassword`
- **Body:**
  ```json
  {
    "email": "user@example.com"
  }
  ```
- **Response:** `200 OK` (email sent if user exists)

#### Reset Password

- **POST** `/api/v1/auth/reset-password/:token`
- **Body:**
  ```json
  {
    "password": "newPassword"
  }
  ```
- **Response:** `200 OK` on success

#### Get Current User

- **GET** `/api/v1/auth/me`
- **Headers:** `Authorization: Bearer <token>`
- **Response:** User info

#### Get Sessions

- **GET** `/api/v1/auth/sessions`
- **Headers:** `Authorization: Bearer <token>`
- **Response:** List of active sessions

#### Refresh Token

- **POST** `/api/v1/auth/refresh`
- **Body:** `{ "refreshToken": "<token>" }`
- **Response:** New JWT token

---

### Waitlist

#### Submit to Waitlist

- **POST** `/api/v1/waitlist/submit`
- **Body:**
  ```json
  {
    "email": "user@example.com",
    "name": "User Name"
  }
  ```
- **Response:** `201 Created`

#### Get All Waitlist Entries

- **GET** `/api/v1/waitlist`
- **Headers:** (Admin only, may require authentication)
- **Response:** List of waitlist entries

#### Export Waitlist

- **GET** `/api/v1/waitlist/export`
- **Response:** CSV file

#### Waitlist Stats

- **GET** `/api/v1/waitlist/stats`
- **Response:** Waitlist statistics

---

### Onboarding

All onboarding routes require authentication via `Authorization: Bearer <token>` header. Steps can be completed in any order unless otherwise specified.

#### Get Onboarding Status
- **GET** `/api/v1/onboarding/status`
- **Response:** Onboarding progress and completed steps.

#### Get Available Communities
- **GET** `/api/v1/onboarding/communities`
- **Response:** List of available communities for selection.

#### Community Selection
- **POST** `/api/v1/onboarding/community`
- **Body:**
  ```json
  {
    "communityId": "string" // or "inviteCode": "string"
  }
  ```
- **Response:** Community selection saved.

#### Profile Information
- **POST** `/api/v1/onboarding/profile`
- **Body:**
  ```json
  {
    "firstName": "Ada",
    "lastName": "Lovelace",
    "age": 28,
    "gender": "female",
    "bio": "Software engineer and AI enthusiast.",
    "occupation": "AI Researcher",
    "temperament": "analytical",
    "matchingStyle": "flexible",
    "ageRange": "26-35",
    "educationLevel": "master"
  }
  ```
- **Response:** Profile info saved.

#### Update Single Profile Field
- **PATCH** `/api/v1/onboarding/profile/:field`
- **Body:**
  ```json
  {
    "bio": "Updated bio text."
  }
  ```
- **Response:** Single profile field updated.

#### Location
- **POST** `/api/v1/onboarding/location`
- **Body:**
  ```json
  {
    "city": "London",
    "state": "Greater London",
    "country": "UK",
    "postalCode": "SW1A 1AA",
    "latitude": 51.5014,
    "longitude": -0.1419
  }
  ```
- **Response:** Location info saved.

#### Personality Traits
- **POST** `/api/v1/onboarding/personality`
- **Body:**
  ```json
  {
    "personalityTraits": ["analytical", "creative", "reliable"]
  }
  ```
- **Response:** Personality info saved.

#### Preferences
- **POST** `/api/v1/onboarding/preferences`
- **Body:**
  ```json
  {
    "connectionPurposes": ["friendship", "networking"],
    "interests": ["AI", "Machine Learning", "Music"],
    "connectionAgePreferences": {
      "friendship": { "min": 25, "max": 35 },
      "networking": { "min": 22, "max": 40 }
    }
  }
  ```
- **Response:** Preferences saved.

#### Availability
- **POST** `/api/v1/onboarding/availability`
- **Body:**
  ```json
  {
    "days": ["Monday", "Wednesday", "Friday"],
    "timePreferences": ["evening", "night"]
  }
  ```
- **Response:** Availability saved.

#### Photo Upload
- **POST** `/api/v1/onboarding/photos`
- **Body:** FormData with photo file(s)
- **Response:** Photo(s) uploaded.

#### Delete Photo
- **DELETE** `/api/v1/onboarding/photos/:photoId`
- **Response:** Photo deleted.

#### Complete Onboarding
- **POST** `/api/v1/onboarding/complete`
- **Response:** Onboarding marked as complete.

#### Skip Onboarding
- **POST** `/api/v1/onboarding/skip`
- **Body:**
  ```json
  {
    "reason": "string"
  }
  ```
- **Response:** Onboarding forcibly completed (for special cases).

#### Get Progress Summary
- **GET** `/api/v1/onboarding/progress`
- **Response:**
  ```json
  {
    "status": "success",
    "data": {
      "progress": {
        "community": true,
        "profile": true,
        "location": false,
        "personality": false,
        "preferences": false,
        "availability": false,
        "photos": false
      },
      "completed": 2,
      "total": 7,
      "percentage": 28,
      "canComplete": false
    }
  }
  ```

#### Bulk Update Onboarding
- **POST** `/api/v1/onboarding/bulk-update`
- **Body:**
  ```json
  {
    "community": { ... },
    "profile": { ... },
    "location": { ... },
    "personality": { ... },
    "preferences": { ... },
    "availability": { ... }
  }
  ```
- **Response:** Bulk update results for each step.

---

### Utility

#### Health Check

- **GET** `/health`
- **Response:**
  ```json
  {
    "uptime": 12345,
    "message": "OK",
    "timestamp": 1234567890,
    "environment": "development",
    "requestId": "uuid",
    "checks": {
      "database": "connected",
      "memory": { ... },
      "network": "connected"
    }
  }
  ```

#### API Documentation

- **GET** `/api/docs`
- **Response:** JSON with all endpoints and their paths

#### Static Assets

- **GET** `/assets/<filename>`
- **GET** `/favicon.ico` or `/favicon.png`

---

## Success Response Format

All successful responses (unless otherwise specified) follow this format:

```json
{
  "status": "success",
  "message": "Description of the success",
  "data": { /* optional, endpoint-specific */ },
  "requestId": "uuid"
}
```

- `status`: Always "success" for successful operations.
- `message`: Human-readable message describing the result.
- `data`: (optional) Contains the result or resource, if applicable.
- `requestId`: Unique request identifier for tracing/debugging.

## Error Handling & Error Response Format

All error responses follow this format:

```json
{
  "status": "FAILED" | "error",
  "message": "Error message",
  "requestId": "uuid",
  "stack": "..." // (only in development)
}
```

- `status`: "FAILED" or "error".
- `message`: Human-readable error message.
- `requestId`: Unique request identifier for tracing/debugging.
- `stack`: (development only) Stack trace for debugging.

### Common Error Codes & Messages

- `400 Bad Request`: Invalid input, validation errors.
- `401 Unauthorized`: Missing or invalid authentication.
- `403 Forbidden`: Not allowed to access resource.
- `404 Not Found`: Resource or route does not exist.
- `409 Conflict`: Duplicate resource (e.g., email already exists).
- `429 Too Many Requests`: Rate limit exceeded.
- `500 Internal Server Error`: Unexpected server error.
- `503 Service Unavailable`: Network/database unavailable.

### Validation Errors

For validation errors (e.g., missing fields, invalid data), the message will be:

```
Validation error: <comma-separated list of issues>
```

### MongoDB Errors

- Duplicate key: `<field> already exists` (409)
- Validation error: `Validation error: ...` (400)

### JWT Errors

- `Invalid token` (401)
- `Token has expired` (401)

### Network/Connectivity Errors

If the server cannot connect to the database or network, you will receive:

```json
{
  "status": "error",
  "message": "Network connection error. Please check your internet connection and try again.",
  "requestId": "uuid"
}
```

Or, for health checks:

```json
{
  "status": "error",
  "message": "Service degraded",
  ...
}
```

#### Special Error Code: `ERRORCONNECT` / `NETWORK_UNAVAILABLE`

If the server encounters a network error (e.g., MongoDB is unreachable), it will respond with:

- `statusCode`: 503
- `status`: "error"
- `message`: "Network connection error. Please check your internet connection and try again."
- `code`: `NETWORK_UNAVAILABLE` (if present)

**Client engineers should:**
- Detect 503 errors and the above message/code.
- Show a user-friendly message (e.g., "We are having trouble connecting. Please try again later.").
- Optionally, implement retry logic or offline handling.

---

## CORS

Allowed origins:
- `http://localhost:8080`
- `http://localhost:3000`
- `https://circlemate-spark-landing-mbh1.vercel.app`
- `https://www.mycirclemate.com`
- Value of `FRONTEND_URL` in environment

---

## Notes

- All endpoints are available under both `/api/v1/` and legacy `/api/` paths for backward compatibility.
- Use the `x-request-id` header in requests for traceability (optional, auto-generated if not provided).
- All requests and responses are JSON unless otherwise specified.

---

## Example Onboarding Data (for Frontend & AI Engineers)

```json
{
  "userId": "60f7c2b8e1b1c8a1b8e1b1c8",
  "firstName": "Ada",
  "lastName": "Lovelace",
  "age": 28,
  "gender": "female",
  "bio": "Software engineer and AI enthusiast.",
  "occupation": "AI Researcher",
  "temperament": "analytical",
  "matchingStyle": "flexible",
  "ageRange": "26-35",
  "educationLevel": "master",
  "location": {
    "city": "London",
    "state": "Greater London",
    "country": "UK",
    "postalCode": "SW1A 1AA",
    "coordinates": { "latitude": 51.5014, "longitude": -0.1419 }
  },
  "personalityTraits": ["analytical", "creative", "reliable"],
  "connectionPurposes": ["friendship", "networking"],
  "connectionAgePreferences": {
    "friendship": { "min": 25, "max": 35 },
    "networking": { "min": 22, "max": 40 }
  },
  "interests": ["AI", "Machine Learning", "Music"],
  "availability": {
    "days": ["Monday", "Wednesday", "Friday"],
    "timePreferences": ["evening", "night"]
  },
  "profilePhotos": [
    {
      "url": "https://res.cloudinary.com/demo/image/upload/v1620000000/profile1.jpg",
      "isPrimary": true
    },
    {
      "url": "https://res.cloudinary.com/demo/image/upload/v1620000000/profile2.jpg",
      "isPrimary": false
    }
  ],
  "communities": [
    {
      "communityId": "60f7c2b8e1b1c8a1b8e1b1c8",
      "joinedAt": "2025-06-10T12:00:00.000Z",
      "role": "member"
    }
  ],
  "onboardingStep": 7,
  "onboardingCompleted": true
}

```

- This example covers all onboarding steps and fields.
- Use this as a reference for frontend payloads and for AI/data engineers to understand the user profile structure.
- Adjust field values as needed for your use case.

---
