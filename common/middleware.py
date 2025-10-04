"""
Security audit middleware for SafeBoda authentication system.
Logs security events and implements rate limiting.
"""

import logging
from django.utils.deprecation import MiddlewareMixin
from django.http import JsonResponse
from django.core.cache import cache
from django.conf import settings
import time

logger = logging.getLogger('security')


class SecurityAuditMiddleware(MiddlewareMixin):
    """
    Middleware to log security events and implement basic rate limiting.
    """
    
    def process_request(self, request):
        """Process incoming requests for security auditing."""
        # Get client IP
        client_ip = self.get_client_ip(request)
        
        # Log authentication attempts
        if request.path.startswith('/api/auth/'):
            self.log_auth_attempt(request, client_ip)
        
        # Basic rate limiting for auth endpoints
        if request.path.startswith('/api/auth/'):
            if self.is_rate_limited(client_ip, request.path):
                logger.warning(f"Rate limit exceeded for IP {client_ip} on {request.path}")
                return JsonResponse({
                    'error': 'Rate limit exceeded. Please try again later.',
                    'retry_after': 60
                }, status=429)
        
        return None
    
    def process_response(self, request, response):
        """Process outgoing responses for security auditing."""
        # Log failed authentication attempts
        if request.path.startswith('/api/auth/') and response.status_code == 401:
            client_ip = self.get_client_ip(request)
            logger.warning(f"Failed authentication attempt from IP {client_ip} on {request.path}")
        
        # Log successful authentication
        if request.path.startswith('/api/auth/') and response.status_code == 200:
            client_ip = self.get_client_ip(request)
            logger.info(f"Successful authentication from IP {client_ip} on {request.path}")
        
        return response
    
    def get_client_ip(self, request):
        """Extract client IP address from request."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
    
    def log_auth_attempt(self, request, client_ip):
        """Log authentication attempt details."""
        logger.info(f"Authentication attempt from IP {client_ip} on {request.path} using {request.method}")
    
    def is_rate_limited(self, client_ip, path):
        """Check if client is rate limited."""
        cache_key = f"rate_limit_{client_ip}_{path}"
        attempts = cache.get(cache_key, 0)
        
        # Allow 5 attempts per minute for auth endpoints
        if attempts >= 5:
            return True
        
        # Increment counter
        cache.set(cache_key, attempts + 1, 60)  # 60 seconds
        return False
