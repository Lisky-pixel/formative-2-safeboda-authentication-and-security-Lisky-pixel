# SafeBoda Authentication API Documentation

## Overview

This document provides comprehensive documentation for the SafeBoda Authentication and Security system. The system implements multiple authentication methods, security features, and compliance measures for the SafeBoda Rwanda platform.

## Base URL
```
http://localhost:8000/api/
```

## Authentication Methods

The system supports three distinct authentication methods:

### 1. Basic Authentication
- **Purpose**: API testing and development
- **Endpoint**: `POST /api/auth/basic/`
- **Use Case**: Development and testing environments

### 2. Session Authentication
- **Purpose**: Web dashboard users
- **Endpoints**: 
  - `POST /api/auth/session/login/`
  - `POST /api/auth/session/logout/`
- **Use Case**: Web-based admin panels and dashboards

### 3. JWT Authentication
- **Purpose**: Mobile applications
- **Endpoints**:
  - `POST /api/auth/jwt-token/`
  - `POST /api/auth/jwt/refresh/`
  - `POST /api/auth/jwt/verify/`
- **Use Case**: Mobile apps and stateless API access

## API Endpoints

### Authentication Endpoints

#### 1. Basic Authentication
```http
POST /api/auth/basic/
Content-Type: application/json

{
    "username": "your_username",
    "password": "your_password"
}
```

**Response (Success):**
```json
{
    "message": "Authentication successful",
    "user": {
        "id": "uuid",
        "username": "username",
        "email": "email@example.com",
        "phone_number": "+250788123456",
        "is_phone_verified": false,
        "is_email_verified": false,
        "date_joined": "2024-01-01T00:00:00Z",
        "last_login": "2024-01-01T00:00:00Z"
    }
}
```

#### 2. Session Login
```http
POST /api/auth/session/login/
Content-Type: application/json

{
    "username": "your_username",
    "password": "your_password",
    "remember_me": false
}
```

**Response (Success):**
```json
{
    "message": "Login successful",
    "user": {
        "id": "uuid",
        "username": "username",
        "email": "email@example.com",
        "phone_number": "+250788123456",
        "is_phone_verified": false,
        "is_email_verified": false,
        "date_joined": "2024-01-01T00:00:00Z",
        "last_login": "2024-01-01T00:00:00Z"
    }
}
```

#### 3. Session Logout
```http
POST /api/auth/session/logout/
Authorization: Session (automatic with cookies)
```

**Response (Success):**
```json
{
    "message": "Logout successful"
}
```

#### 4. JWT Token Generation
```http
POST /api/auth/jwt-token/
Content-Type: application/json

{
    "username": "your_username",
    "password": "your_password"
}
```

**Response (Success):**
```json
{
    "access": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
    "refresh": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
    "user": {
        "id": "uuid",
        "username": "username",
        "email": "email@example.com",
        "phone_number": "+250788123456",
        "is_phone_verified": false,
        "is_email_verified": false,
        "date_joined": "2024-01-01T00:00:00Z",
        "last_login": "2024-01-01T00:00:00Z"
    }
}
```

#### 5. JWT Token Refresh
```http
POST /api/auth/jwt/refresh/
Content-Type: application/json

{
    "refresh": "your_refresh_token"
}
```

**Response (Success):**
```json
{
    "access": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
    "refresh": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
}
```

#### 6. JWT Token Verification
```http
POST /api/auth/jwt/verify/
Authorization: Bearer your_access_token
```

**Response (Success):**
```json
{
    "message": "Token is valid",
    "user": {
        "id": "uuid",
        "username": "username",
        "email": "email@example.com",
        "phone_number": "+250788123456",
        "is_phone_verified": false,
        "is_email_verified": false,
        "date_joined": "2024-01-01T00:00:00Z",
        "last_login": "2024-01-01T00:00:00Z"
    }
}
```

#### 7. Available Authentication Methods
```http
GET /api/auth/methods/
```

**Response:**
```json
{
    "methods": [
        {
            "name": "Basic Authentication",
            "endpoint": "/api/auth/basic/",
            "description": "For API testing and development",
            "type": "basic"
        },
        {
            "name": "Session Authentication",
            "endpoint": "/api/auth/session/login/",
            "description": "For web dashboard users",
            "type": "session"
        },
        {
            "name": "JWT Authentication",
            "endpoint": "/api/auth/jwt-token/",
            "description": "For mobile applications",
            "type": "jwt"
        }
    ],
    "total": 3
}
```

#### 8. User Registration
```http
POST /api/auth/register/
Content-Type: application/json

{
    "username": "new_user",
    "email": "user@example.com",
    "phone_number": "+250788123456",
    "password": "secure_password",
    "password_confirm": "secure_password",
    "first_name": "John",
    "last_name": "Doe"
}
```

**Response (Success):**
```json
{
    "message": "User registered successfully",
    "user": {
        "id": "uuid",
        "username": "new_user",
        "email": "user@example.com",
        "phone_number": "+250788123456",
        "is_phone_verified": false,
        "is_email_verified": false,
        "date_joined": "2024-01-01T00:00:00Z",
        "last_login": null
    }
}
```

## Security Features

### 1. Account Lockout
- Failed login attempts are tracked
- Accounts are locked after multiple failed attempts
- Lock duration is configurable (default: 30 minutes)

### 2. Security Event Logging
All authentication events are logged with:
- User information
- IP address
- User agent
- Timestamp
- Event type

### 3. Password Security
- Strong password validation
- Password confirmation required
- Secure password hashing

### 4. Session Management
- Configurable session timeouts
- Remember me functionality
- Secure session cookies

## Error Responses

### Authentication Errors
```json
{
    "error": "Invalid credentials"
}
```

```json
{
    "error": "Account is disabled"
}
```

```json
{
    "error": "Account is locked"
}
```

### Validation Errors
```json
{
    "username": ["This field is required."],
    "password": ["This field is required."]
}
```

### Rate Limiting
```json
{
    "error": "Rate limit exceeded. Please try again later.",
    "retry_after": 60
}
```

## Interactive API Documentation

The system includes interactive API documentation available at:
- **Swagger UI**: `http://localhost:8000/api/docs/`
- **ReDoc**: `http://localhost:8000/api/redoc/`
- **OpenAPI Schema**: `http://localhost:8000/api/schema/`

## Testing

### Test User Credentials
- **Username**: `admin`
- **Password**: `admin123`

### Running Tests
```bash
python test_auth.py
```

## UAS (User Authentication Service) Endpoints

### User Registration with Rwanda Integration
```http
POST /api/uas/register/
Content-Type: application/json

{
    "username": "new_user",
    "email": "user@example.com",
    "phone_number": "+250788123456",
    "password": "secure_password",
    "password_confirm": "secure_password",
    "first_name": "John",
    "last_name": "Doe",
    "national_id": "123456789012",
    "district_id": 1,
    "address": "Kigali, Rwanda",
    "emergency_contact": "+250788654321",
    "emergency_contact_name": "Jane Doe"
}
```

**Response (Success):**
```json
{
    "message": "User registered successfully",
    "user": {
        "id": "uuid",
        "username": "new_user",
        "email": "user@example.com",
        "phone_number": "+250788123456",
        "is_phone_verified": false,
        "is_email_verified": false,
        "is_active": true,
        "date_joined": "2024-01-01T00:00:00Z",
        "last_login": null,
        "profile": {
            "national_id": "123456789012",
            "district": 1,
            "district_name": "Gasabo",
            "district_code": "GSB",
            "address": "Kigali, Rwanda",
            "emergency_contact": "+250788654321",
            "emergency_contact_name": "Jane Doe",
            "profile_completeness": 100,
            "created_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-01-01T00:00:00Z"
        },
        "district_name": "Gasabo"
    }
}
```

### Phone Verification
```http
POST /api/uas/verify-phone/
Authorization: Bearer your_access_token
Content-Type: application/json

{
    "phone_number": "+250788123456"
}
```

**Response (Success):**
```json
{
    "message": "Verification code sent to phone number",
    "phone_number": "+250788123456",
    "expires_in": 10
}
```

### Phone Verification Confirmation
```http
POST /api/uas/verify-phone/confirm/
Authorization: Bearer your_access_token
Content-Type: application/json

{
    "code": "123456",
    "phone_number": "+250788123456"
}
```

**Response (Success):**
```json
{
    "message": "Phone number verified successfully",
    "is_phone_verified": true
}
```

### Email Verification
```http
POST /api/uas/verify-email/
Authorization: Bearer your_access_token
Content-Type: application/json

{
    "email": "user@example.com"
}
```

**Response (Success):**
```json
{
    "message": "Verification code sent to email",
    "email": "user@example.com",
    "expires_in": 30
}
```

### Email Verification Confirmation
```http
POST /api/uas/verify-email/confirm/
Authorization: Bearer your_access_token
Content-Type: application/json

{
    "code": "123456",
    "email": "user@example.com"
}
```

**Response (Success):**
```json
{
    "message": "Email address verified successfully",
    "is_email_verified": true
}
```

### Password Reset Request
```http
POST /api/uas/password-reset/
Content-Type: application/json

{
    "email": "user@example.com"
}
```

**Alternative methods:**
```json
{
    "phone_number": "+250788123456"
}
```

```json
{
    "national_id": "123456789012"
}
```

**Response (Success):**
```json
{
    "message": "Password reset code sent to your email",
    "expires_in": 30
}
```

### Password Reset Confirmation
```http
POST /api/uas/password-reset/confirm/
Content-Type: application/json

{
    "code": "123456",
    "new_password": "new_secure_password",
    "new_password_confirm": "new_secure_password"
}
```

**Response (Success):**
```json
{
    "message": "Password reset successfully"
}
```

### Account Status
```http
GET /api/uas/account/status/
Authorization: Bearer your_access_token
```

**Response:**
```json
{
    "id": "uuid",
    "username": "username",
    "email": "user@example.com",
    "phone_number": "+250788123456",
    "is_phone_verified": true,
    "is_email_verified": true,
    "is_active": true,
    "date_joined": "2024-01-01T00:00:00Z",
    "last_login": "2024-01-01T00:00:00Z",
    "profile": {
        "national_id": "123456789012",
        "district": 1,
        "district_name": "Gasabo",
        "district_code": "GSB",
        "address": "Kigali, Rwanda",
        "emergency_contact": "+250788654321",
        "emergency_contact_name": "Jane Doe",
        "profile_completeness": 100,
        "created_at": "2024-01-01T00:00:00Z",
        "updated_at": "2024-01-01T00:00:00Z"
    },
    "district_name": "Gasabo"
}
```

### Account Recovery
```http
POST /api/uas/account/recover/
Content-Type: application/json

{
    "recovery_method": "phone",
    "recovery_value": "+250788123456"
}
```

**Alternative methods:**
```json
{
    "recovery_method": "email",
    "recovery_value": "user@example.com"
}
```

```json
{
    "recovery_method": "national_id",
    "recovery_value": "123456789012"
}
```

**Response (Success):**
```json
{
    "message": "Account recovery code sent to your phone number",
    "recovery_id": "uuid",
    "expires_in": 30
}
```

### Rwanda Districts
```http
GET /api/uas/districts/
```

**Response:**
```json
{
    "districts": [
        {
            "id": 1,
            "name": "Gasabo",
            "code": "GSB",
            "province": "Kigali City",
            "is_active": true
        },
        {
            "id": 2,
            "name": "Nyarugenge",
            "code": "NYG",
            "province": "Kigali City",
            "is_active": true
        }
    ],
    "total": 29
}
```

## Rwanda-Specific Features

### National ID Validation
- **Format**: 12 digits
- **Validation**: Birth year extraction and age calculation
- **Integration**: Automatic profile completion tracking

### District Integration
- **29 Rwanda districts** available for registration
- **Province-based organization** (Kigali City, Northern, Eastern, Southern, Western)
- **Active/inactive status** management

### Phone Number Validation
- **Rwanda format**: +250XXXXXXXXX
- **SMS verification** (design implementation)
- **International support** for tourists

## Implementation Status

### ✅ Completed (Task 1 & 2)
- [x] Basic Authentication endpoint
- [x] Session Authentication endpoints
- [x] JWT Authentication endpoints
- [x] Security event logging
- [x] User registration
- [x] Account lockout protection
- [x] Password validation
- [x] OpenAPI documentation
- [x] **UAS User Registration with Rwanda integration**
- [x] **Rwanda National ID validation**
- [x] **SMS/Email verification system**
- [x] **Password reset functionality**
- [x] **Account recovery procedures**
- [x] **Rwanda districts integration**
- [x] **Profile completeness tracking**

### 🔄 In Progress
- [ ] Task 3: Personal Data Protection & Compliance
- [ ] Task 4: Role-Based Access Control

## Next Steps

1. **Task 2**: Implement UAS with Rwanda National ID integration
2. **Task 3**: Add GDPR-style data protection features
3. **Task 4**: Implement role-based access control
4. **Testing**: Comprehensive security testing
5. **Documentation**: Complete API documentation

## Security Considerations

- All endpoints use HTTPS in production
- Sensitive data is encrypted
- Security events are logged and monitored
- Rate limiting prevents abuse
- Account lockout prevents brute force attacks
- JWT tokens have configurable expiration times
- Session cookies are secure and HTTP-only

## Rwanda-Specific Features

- Phone number validation for Rwanda format (+250)
- Support for Rwanda National ID integration (planned)
- District-based user registration (planned)
- Government integration capabilities (planned)
