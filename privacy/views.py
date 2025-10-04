"""
Privacy views - placeholder for Task 3.
"""

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status


class PlaceholderView(APIView):
    """Placeholder view for privacy endpoints."""
    
    def get(self, request):
        return Response({
            'message': 'Privacy endpoints will be implemented in Task 3'
        }, status=status.HTTP_200_OK)