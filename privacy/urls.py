"""
URL configuration for privacy app.
"""

from django.urls import path
from . import views

urlpatterns = [
    # Privacy endpoints will be implemented in Task 3
    path('', views.PlaceholderView.as_view(), name='privacy_placeholder'),
]
