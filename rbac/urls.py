"""
URL configuration for RBAC app.
"""

from django.urls import path
from . import views

urlpatterns = [
    # RBAC endpoints will be implemented in Task 4
    path('', views.PlaceholderView.as_view(), name='rbac_placeholder'),
]
