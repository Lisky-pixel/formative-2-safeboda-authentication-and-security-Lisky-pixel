"""
URL configuration for authentication app.
"""

from django.urls import path
from . import views

urlpatterns = [
    # Basic Authentication
    path('basic/', views.BasicAuthenticationView.as_view(), name='basic_auth'),
    
    # Session Authentication
    path('session/login/', views.SessionLoginView.as_view(), name='session_login'),
    path('session/logout/', views.SessionLogoutView.as_view(), name='session_logout'),
    
    # JWT Authentication
    path('jwt-token/', views.JWTTokenView.as_view(), name='jwt_token'),
    path('jwt/refresh/', views.JWTRefreshView.as_view(), name='jwt_refresh'),
    path('jwt/verify/', views.JWTVerifyView.as_view(), name='jwt_verify'),
    
    # General endpoints
    path('methods/', views.AuthMethodsView.as_view(), name='auth_methods'),
    path('register/', views.UserRegistrationView.as_view(), name='user_registration'),
]
