"""
URL configuration for UAS app.
"""

from django.urls import path
from . import views

urlpatterns = [
    # UAS endpoints will be implemented in Task 2
    path('', views.PlaceholderView.as_view(), name='uas_placeholder'),
]
