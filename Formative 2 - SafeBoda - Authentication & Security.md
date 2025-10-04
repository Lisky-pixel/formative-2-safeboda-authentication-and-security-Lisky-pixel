# Formative 2 - SafeBoda - Authentication & Security

# Scenario Overview

SafeBoda Rwanda has successfully launched its MVP and attracted  $500+$  early users in Kigali. However, the Rwanda Utilities Regulatory Authority (RURA) has requested enhanced security measures and data protection compliance before approving nationwide expansion.

As the security-focused developer on the team, you must implement comprehensive authentication systems that comply with Rwanda's emerging data protection regulations while maintaining an excellent user experience.

# Business Context:

- RURA requires multi-factor authentication for driver accounts  
- Personal data must be encrypted and auditable  
- The system must support government integration for license verification  
- International users (tourists) need simplified authentication  
- Mobile-first design is essential for Rwanda's smartphone adoption patterns

# Assignment Tasks

# Task 1: Multi-Method Authentication System

Scenario: Different user types need different authentication methods. Drivers require high security for income protection, while passengers need convenient access.

# Requirements:

- Basic Authentication for API testing and development  
- Session Authentication for web dashboard users  
- JWT Authentication for mobile applications  
- Rate limiting and security logging

- Multi-factor authentication preparation

# Deliverables:

- Three distinct authentication classes  
- Security middleware implementation  
- Rate limiting system  
Authentication API endpoints  
- OpenAPI specification for authentication endpoints  
Security audit logging

# Required API Endpoints:

- POST /api/auth/basic/ - Basic authentication endpoint  
- POST /api/auth/session/login/ - Session-based login  
- POST /api/auth/session/login/ - Session logout  
- POST /api/auth/jwt-token/ - JWT token generation  
- POST /api/auth/jwt/refresh/ - JWT token refresh  
- POST /api/auth/jwt/verify/ - JWT token verification  
- GET /api/auth/methods/ - Available authentication methods

# Key Features to Implement:

- Custom authentication callbacks  
- Secure session management  
- JWT token generation and validation  
- Password strength enforcement  
- Account lockout policies  
- Rate limiting per IP address  
- Security event logging

# OpenAPI Documentation Requirements:

- Complete authentication API specification  
- Security scheme definitions for all three methods  
- Request/response schemas for each auth type  
- Error response documentation  
- Rate limiting headers documentation

# Assessment Criteria:

- All three authentication methods are properly implemented with security  
- Rate limiting and security logging functional  
- Proper error handling and status codes  
- Security best practices implementation

- Complete OpenAPI documentation

# Task 2:User Authentication Service (UAS)

Scenario: Create a centralized authentication service that can eventually be used by other Rwanda transport platforms (shared infrastructure approach).

# Requirements:

Centralized user management  
- Rwanda National ID integration  
SMS verification system design  
- Password reset functionality  
- Account recovery procedures

# Deliverables:

- Complete UAS API specification  
- User registration workflow  
- Account verification system  
- Password management features  
- OpenAPI specification for UAS endpoints  
- Integration documentation

# Required API Endpoints:

- POST /api/uas/register/ - User registration with verification  
- POST /api/uas/verify-phone/ - SMS verification endpoint  
- POST /api/uas/verify-email/ - Email verification endpoint  
- POST /api/uas/password-reset/ - Password reset request  
- POST /api/uas/password-reset/confirm/ - Password reset confirmation  
- GET /api/uas/account/status/ - Account verification status  
- POST /api/uas/account/recover/ - Account recovery  
- GET /api/uas/districts/ - Rwanda districts for registration

# Key Features to Implement:

- Rwanda National ID validation algorithm  
- SMS verification workflow (design only - no actual SMS)  
- Email verification system  
- Account status management  
- User profile completeness tracking  
Emergency account recovery  
- Multi-step registration process

# OpenAPI Documentation Requirements:

- Centralized authentication service specification  
- Multi-step verification workflow documentation  
- Account status and recovery schemas  
- Integration guidelines for other services  
- Rwanda-specific validation schemas

# Assessment Criteria:

- Comprehensive UAS implementation with all endpoints  
- Rwanda National ID validation is working correctly  
- Multi-step verification process implemented  
- Account recovery and status management  
- Clear integration documentation

# Task 3: Personal Data Protection & Compliance

Scenario: Rwanda is developing data protection laws similar to GDPR. SafeBoda wants to be ahead of regulations and build user trust through transparent data handling.

# Requirements:

Data encryption for sensitive information  
- Audit trail for all personal data access  
- User consent management  
Data export functionality  
Data retention policies

# Deliverables:

Data protection service implementation  
- Personal data encryption system  
- Audit logging mechanism  
- User privacy dashboard API  
- OpenAPI specification for data protection endpoints  
- Compliance documentation

# Required API Endpoints:

- GET /api/privacy/data-export/ - Export user data  
- DELETE /api/privacy/data-deletion/ - Request data deletion  
- GET /api/privacy/audit-log/ - Personal data access log  
- POST /api/privacy/consent/- Update consent preferences  
- GET /api/privacy/consent/ - Get current consent status  
- POST /api/privacy/anonymize/ - Anonymize user data  
- GET /api/privacy/retention-policy/ - Data retention information

# Key Features to Implement:

- Field-level data encryption  
- Access logging and monitoring  
- Consent tracking system  
Data anonymization tools  
- User data export functionality  
- GDPR-style compliance features  
Audit trail for regulatory reporting

# OpenAPI Documentation Requirements:

Data protection and privacy API specification  
- Consent management schemas  
Data export format documentation  
- Audit logging schemas  
- Anonymization request/response formats

# Assessment Criteria:

- Proper encryption implementation for sensitive data  
- Comprehensive audit logging system  
- GDPR-style compliance features (export, anonymization)  
- The consent management system is working  
Data retention and deletion policies implemented

# Task 4: Role-Based Access Control

Scenario: The platform needs different permission levels for passengers, drivers, administrators, and government officials accessing data for regulatory purposes.

# Requirements:

- Flexible role and permission system  
- Government data access controls  
- Driver income privacy protection  
- Administrative oversight capabilities

# Deliverables:

- Role-based permission system  
- Access control middleware  
- Administrative interface APIs  
- Government reporting endpoints  
- OpenAPI specification for RBAC endpoints  
- Permission documentation

# Required API Endpoints:

- GET /api/rbac/roles/ - List available roles  
- POST /api/rbac/assign-role/ - Assign role to user  
- GET /api/rbac/permissions/ - List user permissions  
- GET /api/rbac/admin/users/ - Administrative user management  
- POST /api/rbac/government/access-request/ - Government data access  
- GET /api/rbac/audit/permissions/ - Permission audit log  
- POST /api/rbac/create-role/ - Create custom role (super admin)

# Key Features to Implement:

- Role hierarchy system (passenger < driver < admin < super_admin)  
- Permission-based endpoint protection  
Government official access controls  
- Administrative oversight dashboard APIs  
- Driver earnings privacy protection  
- Audit logging for permission changes

# OpenAPI Documentation Requirements:

- Role-based access control API specification  
- Permission schemas and role definitions  
- Administrative endpoint documentation  
- Government access request workflows  
- Security requirements for each role level

# Assessment Criteria:

- Flexible role and permission system implemented  
- Administrative interface APIs are functional  
- Government access controls are working  
- Permission audit logging system  
- Proper access control middleware


# Submission Requirements

# 1. GitHub Repository:

Feature branches for each authentication method  
o Comprehensive commit history  
Security-focused code reviews

# 2. Technical Documentation:

Complete OpenAPI 3.0 specification for all endpoints  
- Interactive API documentation at /api/docs/  
Authentication architecture overview  
Security threat model and mitigations  
Data protection implementation plan (max 5 pages)

# 3. Compliance Report:

Rwanda data protection alignment  
- International best practices implementation  
Future scalability considerations (max 3 pages)

# 4. Video Demonstration:

10-minute walkthrough of authentication flows  
Security features explanation  
• Rwanda-specific adaptations discussion

# Support & Submission

For Support: Use the provided Office Hours link for any clarifications or technical assistance.

Submission: All submissions must be done via GitHub Classroom. No individual GitHub URLs will be accepted.

# GitHub Classroom Link:

Click Here to Accept the Assignment (https://classroom.github.com/a/5emJLnQY)

For any support or clarifications, please use this Office Hour link  $\rightarrow$

(https://calendar.app.google/2SUGrmmXKsfb9scu8)

Safe boda - Formative 2

<table><tr><td>Criteria</td><td colspan="4">Ratings</td><td>Pts</td></tr><tr><td>Authentication Implementation</td><td>20 to &gt;16.0 ptsExcellentAll three methods properlyimplemented withexcellent security</td><td>16 to &gt;12.0 ptsGoodTwo methodsworking well withgood security</td><td>12 to &gt;6.0 ptsSatisfactoryOne method fullyfunctional</td><td>6 to &gt;0 ptsNeedsImprovementIncomplete orinsecureimplementation</td><td>20 pts</td></tr><tr><td>UASImplementation</td><td>20 to &gt;16.0 ptsExcellentComprehensive service with all endpoints and Rwanda integration</td><td>16 to &gt;12.0 ptsGoodGood service with minor gaps</td><td>12 to &gt;6.0 ptsSatisfactoryBasic servicefunctionality</td><td>6 to &gt;0 ptsNeedsImprovementIncomplete ornon-functionalservice</td><td>20 pts</td></tr><tr><td>Data Protection</td><td>10 to &gt;8.0 ptsExcellentFull compliance with encryption, auditing, and GDPR-style features</td><td>8 to &gt;6.0 ptsGoodGood protection with minor issues</td><td>6 to &gt;3.0 ptsSatisfactoryBasic protection measures</td><td>3 to &gt;0 ptsNeedsImprovementInadequate ormissing protection</td><td>10 pts</td></tr><tr><td>RBAC System</td><td>20 to &gt;16.0 ptsExcellentComplete role-based system with government integration</td><td>16 to &gt;12.0 ptsGoodGood RBAC with most features working</td><td>12 to &gt;6.0 ptsSatisfactoryBasic permission system</td><td>6 to &gt;0 ptsNeedsImprovementPoor or missingaccess controls</td><td>20 pts</td></tr><tr><td>Open APIDocumentation</td><td>10 to &gt;8.0 ptsExcellentComplete specification with security schemes and interactive docs</td><td>8 to &gt;6.0 ptsGoodGood documentation with minor gaps</td><td>6 to &gt;3.0 ptsSatisfactoryBasic APIdocumentation</td><td>3 to &gt;0 ptsNeedsImprovementPoor or missingdocumentation</td><td>10 pts</td></tr><tr><td>Security Best Practices</td><td>10 to &gt;8.0 ptsExcellentExcellent security implementation</td><td>8 to &gt;6.0 ptsGoodGood security with minor</td><td>6 to &gt;3.0 ptsSatisfactory</td><td>3 to &gt;0 ptsNeedsImprovement</td><td>10 pts</td></tr><tr><td></td><td>with comprehensive logging</td><td>vulnerabilities</td><td>Acceptable security measures</td><td>Poor or missing security practices</td><td></td></tr><tr><td>Rwanda Context</td><td>10 to &gt;8.0 ptsExcellentDeep integration of local requirements and regulatory compliance</td><td>8 to &gt;6.0 ptsGoodGood local considerations</td><td>6 to &gt;3.0 ptsSatisfactoryBasic local adaptations</td><td>3 to &gt;0 ptsNeedsImprovementMinimal local context</td><td>10 pts</td></tr></table>

Total Points: 100
