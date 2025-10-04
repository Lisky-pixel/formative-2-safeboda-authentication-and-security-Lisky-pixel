"""
UAS views - placeholder for Task 2.
"""

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status


class PlaceholderView(APIView):
    """Placeholder view for UAS endpoints."""
    
    def get(self, request):
        return Response({
            'message': 'UAS endpoints will be implemented in Task 2'
        }, status=status.HTTP_200_OK)