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

## Privacy and Data Protection Endpoints (Task 3)

### Data Export (GDPR Right to Data Portability)
```http
GET /api/privacy/data-export/
Authorization: Bearer your_access_token
```

**Response (Success):**
```json
{
    "user_info": {
        "id": "uuid",
        "username": "username",
        "email": "user@example.com",
        "phone_number": "+250788123456",
        "first_name": "John",
        "last_name": "Doe",
        "date_joined": "2024-01-01T00:00:00Z",
        "last_login": "2024-01-01T00:00:00Z",
        "is_active": true,
        "is_phone_verified": true,
        "is_email_verified": true
    },
    "profile_data": {
        "national_id": "123456789012",
        "district": "Gasabo",
        "address": "Kigali, Rwanda",
        "emergency_contact": "+250788654321",
        "emergency_contact_name": "Jane Doe",
        "profile_completeness": 100,
        "created_at": "2024-01-01T00:00:00Z",
        "updated_at": "2024-01-01T00:00:00Z"
    },
    "consent_data": [
        {
            "consent_type": "Analytics and Performance",
            "category": "analytics",
            "status": "granted",
            "granted_at": "2024-01-01T00:00:00Z",
            "expires_at": "2025-01-01T00:00:00Z",
            "version": "1.0"
        }
    ],
    "privacy_settings": {
        "allow_data_sharing": false,
        "allow_analytics": true,
        "allow_marketing": false,
        "allow_location_tracking": true,
        "email_notifications": true,
        "sms_notifications": false,
        "push_notifications": true,
        "notify_on_data_access": true,
        "monthly_privacy_report": true
    },
    "access_logs": [
        {
            "access_type": "read",
            "data_category": "personal_info",
            "purpose": "Data portability request",
            "timestamp": "2024-01-01T00:00:00Z",
            "accessed_by": "System"
        }
    ],
    "export_metadata": {
        "export_date": "2024-01-01T00:00:00Z",
        "request_id": "uuid",
        "format": "json",
        "expires_at": "2024-01-31T00:00:00Z"
    }
}
```

### Data Deletion (GDPR Right to be Forgotten)
```http
DELETE /api/privacy/data-deletion/
Authorization: Bearer your_access_token
Content-Type: application/json

{
    "request_type": "full_deletion",
    "data_types": ["user_profile", "contact_info"],
    "reason": "Privacy concerns"
}
```

**Alternative request types:**
```json
{
    "request_type": "partial_deletion",
    "data_types": ["location_data", "analytics_data"],
    "reason": "Remove specific data only"
}
```

```json
{
    "request_type": "anonymization",
    "data_types": ["user_profile"],
    "reason": "Keep data but remove personal identifiers"
}
```

**Response (Success):**
```json
{
    "message": "Data deletion request submitted successfully",
    "request_id": "uuid",
    "status": "completed"
}
```

### Audit Log (Personal Data Access Log)
```http
GET /api/privacy/audit-log/?days=30&access_type=read
Authorization: Bearer your_access_token
```

**Response (Success):**
```json
{
    "logs": [
        {
            "id": "uuid",
            "user": "uuid",
            "user_username": "username",
            "accessed_by": "uuid",
            "accessed_by_username": "admin",
            "access_type": "read",
            "data_category": "personal_info",
            "data_fields": ["username", "email"],
            "purpose": "Administrative access",
            "ip_address": "127.0.0.1",
            "user_agent": "Mozilla/5.0...",
            "timestamp": "2024-01-01T00:00:00Z",
            "retention_until": "2031-01-01T00:00:00Z"
        }
    ],
    "total": 25,
    "period_days": 30,
    "access_type_filter": "read"
}
```

### Consent Management
```http
GET /api/privacy/consent/
Authorization: Bearer your_access_token
```

**Response (Success):**
```json
{
    "consent_status": [
        {
            "consent_type_id": "uuid",
            "consent_type_name": "Analytics and Performance",
            "consent_type_category": "analytics",
            "status": "granted",
            "is_valid": true,
            "granted_at": "2024-01-01T00:00:00Z",
            "expires_at": "2025-01-01T00:00:00Z"
        },
        {
            "consent_type_id": "uuid",
            "consent_type_name": "Marketing Communications",
            "consent_type_category": "marketing",
            "status": "denied",
            "is_valid": false,
            "granted_at": null,
            "expires_at": null
        }
    ],
    "total_consent_types": 7
}
```

**Update Consent:**
```http
POST /api/privacy/consent/
Authorization: Bearer your_access_token
Content-Type: application/json

{
    "consent_type_id": "uuid",
    "status": "granted"
}
```

**Response (Success):**
```json
{
    "message": "Consent granted successfully",
    "consent_type": "Analytics and Performance",
    "status": "granted"
}
```

### Data Anonymization
```http
POST /api/privacy/anonymize/
Authorization: Bearer your_access_token
Content-Type: application/json

{
    "data_types": ["user_profile", "contact_info"],
    "anonymization_method": "pseudonymization",
    "reason": "Privacy protection"
}
```

**Available anonymization methods:**
- `pseudonymization`: Replace with pseudonyms
- `generalization`: Replace with general categories
- `suppression`: Remove specific fields
- `randomization`: Randomize data values

**Response (Success):**
```json
{
    "message": "Data anonymization completed successfully",
    "anonymization_method": "pseudonymization",
    "anonymized_data": {
        "basic_info": true,
        "contact_info": true,
        "profile_data": true
    },
    "reason": "Privacy protection"
}
```

### Data Retention Policy Information
```http
GET /api/privacy/retention-policy/
Authorization: Bearer your_access_token
```

**Response (Success):**
```json
{
    "retention_policies": [
        {
            "data_type": "user_profile",
            "retention_period_days": 2555,
            "retention_basis": "legal_requirement",
            "description": "User profile data retained for legal compliance and audit purposes.",
            "auto_delete": false,
            "requires_consent": true
        },
        {
            "data_type": "contact_info",
            "retention_period_days": 365,
            "retention_basis": "business_necessity",
            "description": "Contact information retained for service delivery and communication.",
            "auto_delete": true,
            "requires_consent": true
        }
    ],
    "total_policies": 7,
    "note": "These policies define how long your data is retained and under what legal basis."
}
```

### Privacy Settings
```http
GET /api/privacy/settings/
Authorization: Bearer your_access_token
```

**Response (Success):**
```json
{
    "id": "uuid",
    "user": "uuid",
    "user_username": "username",
    "allow_data_sharing": false,
    "allow_analytics": true,
    "allow_marketing": false,
    "allow_location_tracking": true,
    "email_notifications": true,
    "sms_notifications": false,
    "push_notifications": true,
    "auto_delete_after_inactivity": false,
    "inactivity_period_days": 365,
    "notify_on_data_access": true,
    "monthly_privacy_report": true,
    "created_at": "2024-01-01T00:00:00Z",
    "updated_at": "2024-01-01T00:00:00Z"
}
```

**Update Privacy Settings:**
```http
PUT /api/privacy/settings/
Authorization: Bearer your_access_token
Content-Type: application/json

{
    "allow_data_sharing": true,
    "allow_analytics": false,
    "email_notifications": false
}
```

**Response (Success):**
```json
{
    "message": "Privacy settings updated successfully",
    "settings": {
        "id": "uuid",
        "user": "uuid",
        "user_username": "username",
        "allow_data_sharing": true,
        "allow_analytics": false,
        "allow_marketing": false,
        "allow_location_tracking": true,
        "email_notifications": false,
        "sms_notifications": false,
        "push_notifications": true,
        "auto_delete_after_inactivity": false,
        "inactivity_period_days": 365,
        "notify_on_data_access": true,
        "monthly_privacy_report": true,
        "created_at": "2024-01-01T00:00:00Z",
        "updated_at": "2024-01-01T00:00:00Z"
    }
}
```

## Implementation Status

### ✅ Completed (Task 1, 2 & 3)
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
- [x] **Data Export functionality (GDPR Right to Data Portability)**
- [x] **Data Deletion functionality (GDPR Right to be Forgotten)**
- [x] **Comprehensive Audit Logging (GDPR Article 30)**
- [x] **Consent Management System**
- [x] **Data Anonymization Features**
- [x] **Data Retention Policy Management**
- [x] **Privacy Settings Management**
- [x] **Field-level Data Encryption**

### 🔄 In Progress
- [ ] Task 4: Role-Based Access Control

## Next Steps

1. **Task 4**: Implement role-based access control
2. **Testing**: Comprehensive security testing
3. **Documentation**: Complete API documentation

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
