# (C) Datadog, Inc. 2025-present
# All rights reserved
# Licensed under a 3-clause BSD style license (see LICENSE)

"""
OIDC authentication callbacks for MongoDB integration.

This module provides OIDC callback implementations for AKS and GKE workload identity
authentication mechanisms, allowing Kubernetes workloads to authenticate to MongoDB
without requiring explicit credentials.
"""

import json
import os
import time
from typing import Any, Dict, Optional
from urllib.request import Request, urlopen
from urllib.parse import urlencode
from urllib.error import URLError

try:
    from pymongo.auth_oidc import OIDCCallback, OIDCCallbackContext, OIDCCallbackResult
except ImportError:
    # Fallback for older pymongo versions or when pymongo is not installed
    class OIDCCallback:
        pass
    
    class OIDCCallbackContext:
        pass
    
    class OIDCCallbackResult:
        pass


class AzureWorkloadIdentityCallback(OIDCCallback):
    """
    OIDC callback for Azure AKS workload identity authentication.
    
    This callback leverages Azure's workload identity feature to obtain JWT tokens
    from the Azure Instance Metadata Service (IMDS) endpoint that can be used for
    MongoDB OIDC authentication.
    """
    
    def __init__(self, timeout: int = 30):
        """
        Initialize the Azure workload identity callback.
        
        Args:
            timeout: Timeout in seconds for HTTP requests to Azure IMDS.
        """
        self.timeout = timeout
        self._token_cache = {}
        
    def fetch(self, context: OIDCCallbackContext) -> OIDCCallbackResult:
        """
        Fetch an OIDC token from Azure workload identity.
        
        Args:
            context: The OIDC callback context from pymongo.
            
        Returns:
            OIDCCallbackResult containing the access token.
            
        Raises:
            Exception: If token acquisition fails.
        """
        # Check for cached token
        cached_token = self._get_cached_token()
        if cached_token:
            return OIDCCallbackResult(access_token=cached_token)
        
        # Azure workload identity environment variables
        client_id = os.environ.get('AZURE_CLIENT_ID')
        tenant_id = os.environ.get('AZURE_TENANT_ID')
        token_file = os.environ.get('AZURE_FEDERATED_TOKEN_FILE')
        
        if not all([client_id, tenant_id, token_file]):
            raise Exception(
                "Azure workload identity not configured. Required environment variables: "
                "AZURE_CLIENT_ID, AZURE_TENANT_ID, AZURE_FEDERATED_TOKEN_FILE"
            )
        
        try:
            # Read the service account token
            with open(token_file, 'r') as f:
                federated_token = f.read().strip()
            
            # Exchange the federated token for an Azure access token
            token_endpoint = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
            
            data = {
                'client_id': client_id,
                'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                'client_assertion': federated_token,
                'scope': 'https://graph.microsoft.com/.default',
                'grant_type': 'client_credentials'
            }
            
            request = Request(
                token_endpoint,
                data=urlencode(data).encode('utf-8'),
                headers={'Content-Type': 'application/x-www-form-urlencoded'}
            )
            
            with urlopen(request, timeout=self.timeout) as response:
                token_response = json.loads(response.read().decode('utf-8'))
            
            access_token = token_response.get('access_token')
            if not access_token:
                raise Exception(f"No access token in response: {token_response}")
            
            # Cache the token with expiration
            expires_in = token_response.get('expires_in', 3600)
            self._cache_token(access_token, expires_in)
            
            return OIDCCallbackResult(access_token=access_token)
            
        except Exception as e:
            raise Exception(f"Failed to acquire Azure workload identity token: {e}")
    
    def _get_cached_token(self) -> Optional[str]:
        """Get cached token if still valid."""
        if 'token' in self._token_cache and 'expires_at' in self._token_cache:
            if time.time() < self._token_cache['expires_at']:
                return self._token_cache['token']
        return None
    
    def _cache_token(self, token: str, expires_in: int):
        """Cache token with expiration time."""
        # Add 5 minute buffer before expiration
        expires_at = time.time() + expires_in - 300
        self._token_cache = {
            'token': token,
            'expires_at': expires_at
        }


class GCPWorkloadIdentityCallback(OIDCCallback):
    """
    OIDC callback for GCP GKE workload identity authentication.
    
    This callback leverages GCP's workload identity feature to obtain JWT tokens
    from the GCP metadata service that can be used for MongoDB OIDC authentication.
    """
    
    def __init__(self, timeout: int = 30):
        """
        Initialize the GCP workload identity callback.
        
        Args:
            timeout: Timeout in seconds for HTTP requests to GCP metadata service.
        """
        self.timeout = timeout
        self._token_cache = {}
        
    def fetch(self, context: OIDCCallbackContext) -> OIDCCallbackResult:
        """
        Fetch an OIDC token from GCP workload identity.
        
        Args:
            context: The OIDC callback context from pymongo.
            
        Returns:
            OIDCCallbackResult containing the access token.
            
        Raises:
            Exception: If token acquisition fails.
        """
        # Check for cached token
        cached_token = self._get_cached_token()
        if cached_token:
            return OIDCCallbackResult(access_token=cached_token)
        
        # GCP workload identity uses the metadata service
        try:
            # Get service account email from metadata
            service_account = self._get_service_account()
            
            # Request access token from metadata service
            token_url = (
                f"http://metadata.google.internal/computeMetadata/v1/"
                f"instance/service-accounts/{service_account}/token"
            )
            
            request = Request(
                token_url,
                headers={'Metadata-Flavor': 'Google'}
            )
            
            with urlopen(request, timeout=self.timeout) as response:
                token_response = json.loads(response.read().decode('utf-8'))
            
            access_token = token_response.get('access_token')
            if not access_token:
                raise Exception(f"No access token in response: {token_response}")
            
            # Cache the token with expiration
            expires_in = token_response.get('expires_in', 3600)
            self._cache_token(access_token, expires_in)
            
            return OIDCCallbackResult(access_token=access_token)
            
        except Exception as e:
            raise Exception(f"Failed to acquire GCP workload identity token: {e}")
    
    def _get_service_account(self) -> str:
        """Get the default service account email from metadata service."""
        try:
            sa_url = (
                "http://metadata.google.internal/computeMetadata/v1/"
                "instance/service-accounts/default/email"
            )
            
            request = Request(
                sa_url,
                headers={'Metadata-Flavor': 'Google'}
            )
            
            with urlopen(request, timeout=self.timeout) as response:
                return response.read().decode('utf-8').strip()
                
        except Exception as e:
            raise Exception(f"Failed to get service account from GCP metadata: {e}")
    
    def _get_cached_token(self) -> Optional[str]:
        """Get cached token if still valid."""
        if 'token' in self._token_cache and 'expires_at' in self._token_cache:
            if time.time() < self._token_cache['expires_at']:
                return self._token_cache['token']
        return None
    
    def _cache_token(self, token: str, expires_in: int):
        """Cache token with expiration time."""
        # Add 5 minute buffer before expiration
        expires_at = time.time() + expires_in - 300
        self._token_cache = {
            'token': token,
            'expires_at': expires_at
        }


def create_oidc_callback(provider: str, **kwargs) -> OIDCCallback:
    """
    Factory function to create OIDC callbacks for different providers.
    
    Args:
        provider: The workload identity provider ('azure' or 'gcp').
        **kwargs: Additional arguments to pass to the callback constructor.
        
    Returns:
        An instance of the appropriate OIDC callback.
        
    Raises:
        ValueError: If the provider is not supported.
    """
    provider = provider.lower()
    
    if provider in ('azure', 'aks'):
        return AzureWorkloadIdentityCallback(**kwargs)
    elif provider in ('gcp', 'gke', 'google'):
        return GCPWorkloadIdentityCallback(**kwargs)
    else:
        raise ValueError(
            f"Unsupported OIDC provider: {provider}. "
            f"Supported providers: azure, aks, gcp, gke, google"
        )