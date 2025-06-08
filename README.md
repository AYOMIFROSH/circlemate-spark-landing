# CircleMate API Documentation

## 🚀 Getting Started

### Base URL
```
Development: http://localhost:3000/api/v1
Production: https://your-domain.com/api/v1
```

### Authentication
All protected routes require a JWT token in the Authorization header:
```
Authorization: Bearer YOUR_JWT_TOKEN
```

## 📱 Client Integration Guide

### Step 1: Initial Setup
```javascript
// Configure your API client
const API_BASE = 'http://localhost:3000/api/v1';

// Add token to all requests
const apiCall = async (endpoint, options = {}) => {
  const token = localStorage.getItem('token');
  
  const response = await fetch(`${API_BASE}${endpoint}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(token && { 'Authorization': `Bearer ${token}` }),
      ...options.headers
    }
  });
  
  const data = await response.json();
  
  if (!response.ok) {
    throw data;
  }
  
  return data;
};
```

## 🔐 Authentication Flow

### 1. Sign Up
```javascript
// POST /api/v1/auth/signup
const signup = async (userData) => {
  const response = await apiCall('/auth/signup', {
    method: 'POST',
    body: JSON.stringify({
      userName: 'johndoe',
      firstName: 'John',
      lastName: 'Doe',
      email: 'john@example.com',
      password: 'SecurePass123' // Min 8 chars, must include letters & numbers
    })
  });
  
  // Response
  {
    status: 'PENDING',
    message: 'Verification email sent!',
    user: {
      _id: '123...',
      email: 'john@example.com',
      verified: false
    }
  }
};
```

### 2. Check Verification Status
```javascript
// GET /api/v1/auth/check-verification/:email
const checkVerification = async (email) => {
  const response = await apiCall(`/auth/check-verification/${email}`);
  
  // Response
  {
    status: 'success',
    data: {
      email: 'john@example.com',
      verified: true,
      userId: '123...'
    }
  }
};
```

### 3. Login
```javascript
// POST /api/v1/auth/login
const login = async (credentials) => {
  const response = await apiCall('/auth/login', {
    method: 'POST',
    body: JSON.stringify({
      email: 'john@example.com',
      password: 'SecurePass123',
      rememberMe: false // Optional: extends session to 30 days
    })
  });
  
  // Response
  {
    status: 'success',
    message: 'Logged in successfully.',
    token: 'eyJhbGc...',
    sessionToken: 'abc123...',
    user: {
      _id: '123...',
      userName: 'johndoe',
      firstName: 'John',
      lastName: 'Doe',
      email: 'john@example.com',
      role: 'user',
      verified: true
    }
  }
  
  // Save the token
  localStorage.setItem('token', response.token);
};
```

### 4. Resend Verification Email
```javascript
// POST /api/v1/auth/resend-verification
const resendVerification = async (email) => {
  await apiCall('/auth/resend-verification', {
    method: 'POST',
    body: JSON.stringify({ email })
  });
};
```

### 5. Forgot Password
```javascript
// POST /api/v1/auth/forgotpassword
const forgotPassword = async (email) => {
  await apiCall('/auth/forgotpassword', {
    method: 'POST',
    body: JSON.stringify({ email })
  });
  
  // Always returns success for security
  {
    status: 'success',
    message: 'If an account exists with this email, a password reset link has been sent.'
  }
};
```

### 6. Get Current User
```javascript
// GET /api/v1/auth/me (Protected)
const getCurrentUser = async () => {
  const response = await apiCall('/auth/me');
  
  // Response
  {
    status: 'success',
    user: {
      _id: '123...',
      userName: 'johndoe',
      firstName: 'John',
      lastName: 'Doe',
      email: 'john@example.com',
      role: 'user',
      verified: true
    }
  }
};
```

### 7. Logout
```javascript
// POST /api/v1/auth/logout (Protected)
const logout = async () => {
  await apiCall('/auth/logout', { method: 'POST' });
  localStorage.removeItem('token');
  window.location.href = '/login';
};
```

## 👤 Onboarding Flow

The onboarding process is flexible - users can complete steps in any order or skip steps entirely.

### Check Onboarding Status
```javascript
// GET /api/v1/onboarding/status (Protected)
const getOnboardingStatus = async () => {
  const response = await apiCall('/onboarding/status');
  
  // Response
  {
    status: 'success',
    data: {
      onboardingStep: 3,
      onboardingCompleted: false,
      profileCompleteness: 42,
      profile: { /* user profile data */ }
    }
  }
};
```

### Get Progress Summary
```javascript
// GET /api/v1/onboarding/progress (Protected)
const getProgress = async () => {
  const response = await apiCall('/onboarding/progress');
  
  // Response
  {
    status: 'success',
    data: {
      progress: {
        community: true,
        profile: true,
        location: true,
        personality: false,
        preferences: false,
        availability: false,
        photos: false
      },
      completed: 3,
      total: 7,
      percentage: 42,
      canComplete: true // Minimum requirements met
    }
  }
};
```

### Step 1: Join Community
```javascript
// GET /api/v1/onboarding/communities
const getCommunities = async () => {
  const response = await apiCall('/onboarding/communities?search=tech&page=1&limit=20');
  
  // Response includes communities with pagination
};

// POST /api/v1/onboarding/community
const joinCommunity = async (data) => {
  // Option 1: By ID
  await apiCall('/onboarding/community', {
    method: 'POST',
    body: JSON.stringify({ communityId: '123...' })
  });
  
  // Option 2: By Invite Code
  await apiCall('/onboarding/community', {
    method: 'POST',
    body: JSON.stringify({ inviteCode: 'TECH2024' })
  });
};
```

### Step 2: Update Profile
```javascript
// POST /api/v1/onboarding/profile
const updateProfile = async (profileData) => {
  await apiCall('/onboarding/profile', {
    method: 'POST',
    body: JSON.stringify({
      firstName: 'John',
      lastName: 'Doe',
      age: 25,
      gender: 'male', // Options: male, female
      bio: 'Software developer passionate about AI',
      occupation: 'Software Engineer',
      temperament: 'sanguine', // Options: choleric, sanguine, phlegmatic, melancholic
      matchingStyle: 'flexible', // Options: flexible, strict, auto
      ageRange: '26-35', // Options: 18-25, 26-35, 36-45, 46+
      educationLevel: 'bachelor' // See docs for all options
    })
  });
};
```

### Step 3: Set Location
```javascript
// POST /api/v1/onboarding/location
const updateLocation = async (locationData) => {
  await apiCall('/onboarding/location', {
    method: 'POST',
    body: JSON.stringify({
      city: 'Lagos',
      state: 'Lagos',
      country: 'Nigeria',
      postalCode: '100001',
      latitude: 6.5244, // Optional
      longitude: 3.3792 // Optional
    })
  });
};
```

### Step 4: Select Personality Traits
```javascript
// POST /api/v1/onboarding/personality
const updatePersonality = async (traits) => {
  await apiCall('/onboarding/personality', {
    method: 'POST',
    body: JSON.stringify({
      personalityTraits: ['creative', 'analytical', 'outgoing'] // Min 1, Max 5
    })
  });
};
```

### Step 5: Set Preferences
```javascript
// POST /api/v1/onboarding/preferences
const updatePreferences = async (preferences) => {
  await apiCall('/onboarding/preferences', {
    method: 'POST',
    body: JSON.stringify({
      connectionPurposes: ['friendship', 'dating'],
      interests: ['Photography', 'Travel', 'Technology'],
      preferredAges: {
        friendship: { min: 18, max: 100 },
        dating: { min: 25, max: 35 }
      }
    })
  });
};
```

### Step 6: Set Availability
```javascript
// POST /api/v1/onboarding/availability
const updateAvailability = async (availability) => {
  await apiCall('/onboarding/availability', {
    method: 'POST',
    body: JSON.stringify({
      days: ['Saturday', 'Sunday'],
      timePreferences: ['afternoon', 'evening']
    })
  });
};
```

### Step 7: Upload Photos (Optional)
```javascript
// POST /api/v1/onboarding/photos
const uploadPhotos = async (files) => {
  const formData = new FormData();
  files.forEach(file => formData.append('photos', file));
  
  await fetch(`${API_BASE}/onboarding/photos`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${localStorage.getItem('token')}`
    },
    body: formData
  });
};
```

### Complete Onboarding
```javascript
// POST /api/v1/onboarding/complete
const completeOnboarding = async () => {
  await apiCall('/onboarding/complete', {
    method: 'POST',
    body: JSON.stringify({})
  });
};

// Or skip onboarding entirely
const skipOnboarding = async () => {
  await apiCall('/onboarding/skip', {
    method: 'POST',
    body: JSON.stringify({ reason: 'Want to explore first' })
  });
};
```

## 📧 Waitlist (Public)

```javascript
// POST /api/v1/waitlist/submit
const joinWaitlist = async (data) => {
  await apiCall('/waitlist/submit', {
    method: 'POST',
    body: JSON.stringify({
      firstName: 'Jane',
      lastName: 'Smith',
      email: 'jane@example.com',
      interest: 'friendship' // Options: friendship, romance, professional, all
    })
  });
};
```

## ⚠️ Error Handling

### Error Response Format
```javascript
{
  status: 'FAILED',
  message: 'Human-readable error message',
  requestId: '550e8400-e29b-41d4-a716',
  errors: [ // Only for validation errors
    {
      field: 'email',
      message: 'Please provide a valid email address'
    }
  ]
}
```

### Common Error Codes
- `400` - Bad Request (validation failed)
- `401` - Unauthorized (invalid/missing token)
- `403` - Forbidden (insufficient permissions)
- `404` - Not Found
- `423` - Account Locked (too many failed attempts)
- `429` - Too Many Requests (rate limited)
- `503` - Service Unavailable (no internet/server down)

### Network Error Handling
```javascript
// Handle network errors
try {
  await apiCall('/some-endpoint');
} catch (error) {
  if (error.error === 'NETWORK_UNAVAILABLE') {
    alert('No internet connection. Please check your connection and try again.');
  } else if (error.status === 'FAILED') {
    alert(error.message);
  }
}
```

## 🔄 Token Refresh

When your token expires, the API will return a 401 error. You can either:
1. Redirect to login
2. Use the refresh endpoint (if you have a refresh token in cookies)

```javascript
// Handle 401 errors globally
if (error.status === 401) {
  localStorage.removeItem('token');
  window.location.href = '/login';
}
```

## 📝 Quick Reference

### Authentication Endpoints
| Method | Endpoint | Auth Required | Description |
|--------|----------|---------------|-------------|
| POST | `/auth/signup` | No | Create account |
| POST | `/auth/login` | No | Login |
| GET | `/auth/check-verification/:email` | No | Check if email verified |
| POST | `/auth/resend-verification` | No | Resend verification |
| POST | `/auth/forgotpassword` | No | Request password reset |
| GET | `/auth/me` | Yes | Get current user |
| POST | `/auth/logout` | Yes | Logout |

### Onboarding Endpoints
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/onboarding/status` | Get onboarding status |
| GET | `/onboarding/progress` | Get completion progress |
| GET | `/onboarding/communities` | List communities |
| POST | `/onboarding/community` | Join community |
| POST | `/onboarding/profile` | Update profile |
| POST | `/onboarding/location` | Set location |
| POST | `/onboarding/personality` | Set personality traits |
| POST | `/onboarding/preferences` | Set preferences |
| POST | `/onboarding/availability` | Set availability |
| POST | `/onboarding/photos` | Upload photos |
| POST | `/onboarding/complete` | Complete onboarding |
| POST | `/onboarding/skip` | Skip onboarding |

### Field Options Reference
```javascript
// Gender
['male', 'female']

// Temperament
['choleric', 'sanguine', 'phlegmatic', 'melancholic']

// Matching Style
['flexible', 'strict', 'auto']

// Age Range
['18-25', '26-35', '36-45', '46+']

// Education Level
[
  'no_formal',        // No Formal Education
  'primary',          // Primary School
  'lower_secondary',  // Middle School
  'upper_secondary',  // High School
  'vocational',       // Technical Certification
  'some_college',     // Some College
  'associate',        // Associate Degree
  'bachelor',         // Bachelor's Degree
  'postgrad_diploma', // Postgraduate Diploma
  'master',           // Master's Degree
  'doctorate'         // PhD
]

// Personality Traits (max 5)
['adventurous', 'analytical', 'creative', 'empathetic',
 'organized', 'outgoing', 'relaxed', 'ambitious',
 'thoughtful', 'practical', 'curious', 'reliable']

// Connection Purposes
['friendship', 'dating', 'networking', 'activities']

// Days
['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']

// Time Preferences
['morning', 'afternoon', 'evening', 'night']
```