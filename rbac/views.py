"""
RBAC views - placeholder for Task 4.
"""

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status


class PlaceholderView(APIView):
    """Placeholder view for RBAC endpoints."""
    
    def get(self, request):
        return Response({
            'message': 'RBAC endpoints will be implemented in Task 4'
        }, status=status.HTTP_200_OK)