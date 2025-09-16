# (C) Datadog, Inc. 2025-present
# All rights reserved
# Licensed under a 3-clause BSD style license (see LICENSE)

import os
import tempfile
import time
from unittest.mock import Mock, patch, mock_open

import pytest

from datadog_checks.mongo.oidc_callbacks import (
    AzureWorkloadIdentityCallback,
    GCPWorkloadIdentityCallback,
    create_oidc_callback,
    OIDCCallback,
    OIDCCallbackContext,
    OIDCCallbackResult,
)


class TestAzureWorkloadIdentityCallback:
    def test_missing_environment_variables(self):
        """Test that missing environment variables raise an exception."""
        callback = AzureWorkloadIdentityCallback()
        context = Mock()
        
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(Exception) as exc_info:
                callback.fetch(context)
            
            assert "Azure workload identity not configured" in str(exc_info.value)
            assert "AZURE_CLIENT_ID" in str(exc_info.value)

    def test_successful_token_fetch(self):
        """Test successful token fetch from Azure workload identity."""
        callback = AzureWorkloadIdentityCallback()
        context = Mock()
        
        # Mock environment variables
        env_vars = {
            'AZURE_CLIENT_ID': 'test-client-id',
            'AZURE_TENANT_ID': 'test-tenant-id',
            'AZURE_FEDERATED_TOKEN_FILE': '/tmp/test-token'
        }
        
        # Mock token file content
        federated_token = 'mock-federated-token'
        
        # Mock Azure token response
        azure_response = {
            'access_token': 'mock-access-token',
            'expires_in': 3600
        }
        
        with patch.dict(os.environ, env_vars):
            with patch('builtins.open', mock_open(read_data=federated_token)):
                with patch('datadog_checks.mongo.oidc_callbacks.urlopen') as mock_urlopen:
                    # Mock the HTTP response
                    mock_response = Mock()
                    mock_response.read.return_value = b'{"access_token": "mock-access-token", "expires_in": 3600}'
                    mock_urlopen.return_value.__enter__.return_value = mock_response
                    
                    result = callback.fetch(context)
                    
                    assert isinstance(result, OIDCCallbackResult)
                    assert result.access_token == 'mock-access-token'

    def test_token_caching(self):
        """Test that tokens are properly cached and reused."""
        callback = AzureWorkloadIdentityCallback()
        
        # Manually set a cached token
        callback._cache_token('cached-token', 3600)
        
        # Fetch should return cached token without making HTTP requests
        context = Mock()
        result = callback.fetch(context)
        
        assert result.access_token == 'cached-token'

    def test_expired_token_cache(self):
        """Test that expired tokens are not used from cache."""
        callback = AzureWorkloadIdentityCallback()
        
        # Set an expired token (expires 1 second ago)
        callback._token_cache = {
            'token': 'expired-token',
            'expires_at': time.time() - 1
        }
        
        assert callback._get_cached_token() is None


class TestGCPWorkloadIdentityCallback:
    def test_successful_token_fetch(self):
        """Test successful token fetch from GCP workload identity."""
        callback = GCPWorkloadIdentityCallback()
        context = Mock()
        
        # Mock GCP metadata responses
        service_account_email = 'test@project.iam.gserviceaccount.com'
        token_response = {
            'access_token': 'mock-gcp-token',
            'expires_in': 3600
        }
        
        with patch('datadog_checks.mongo.oidc_callbacks.urlopen') as mock_urlopen:
            # Mock service account response
            sa_response = Mock()
            sa_response.read.return_value = service_account_email.encode('utf-8')
            
            # Mock token response
            token_resp = Mock()
            token_resp.read.return_value = b'{"access_token": "mock-gcp-token", "expires_in": 3600}'
            
            # Configure side_effect to return different responses for different calls
            mock_urlopen.return_value.__enter__.side_effect = [sa_response, token_resp]
            
            result = callback.fetch(context)
            
            assert isinstance(result, OIDCCallbackResult)
            assert result.access_token == 'mock-gcp-token'

    def test_service_account_fetch_failure(self):
        """Test failure when unable to fetch service account email."""
        callback = GCPWorkloadIdentityCallback()
        context = Mock()
        
        with patch('datadog_checks.mongo.oidc_callbacks.urlopen') as mock_urlopen:
            mock_urlopen.side_effect = Exception("Network error")
            
            with pytest.raises(Exception) as exc_info:
                callback.fetch(context)
            
            assert "Failed to acquire GCP workload identity token" in str(exc_info.value)

    def test_token_caching(self):
        """Test that GCP tokens are properly cached and reused."""
        callback = GCPWorkloadIdentityCallback()
        
        # Manually set a cached token
        callback._cache_token('cached-gcp-token', 3600)
        
        # Fetch should return cached token without making HTTP requests
        context = Mock()
        result = callback.fetch(context)
        
        assert result.access_token == 'cached-gcp-token'


class TestCreateOIDCCallback:
    def test_azure_provider_aliases(self):
        """Test that various Azure provider aliases work."""
        for provider in ['azure', 'aks']:
            callback = create_oidc_callback(provider)
            assert isinstance(callback, AzureWorkloadIdentityCallback)

    def test_gcp_provider_aliases(self):
        """Test that various GCP provider aliases work."""
        for provider in ['gcp', 'gke', 'google']:
            callback = create_oidc_callback(provider)
            assert isinstance(callback, GCPWorkloadIdentityCallback)

    def test_case_insensitive_providers(self):
        """Test that provider names are case insensitive."""
        callback1 = create_oidc_callback('AZURE')
        callback2 = create_oidc_callback('GCP')
        
        assert isinstance(callback1, AzureWorkloadIdentityCallback)
        assert isinstance(callback2, GCPWorkloadIdentityCallback)

    def test_unsupported_provider(self):
        """Test that unsupported providers raise ValueError."""
        with pytest.raises(ValueError) as exc_info:
            create_oidc_callback('unsupported')
        
        assert "Unsupported OIDC provider" in str(exc_info.value)

    def test_kwargs_passed_to_callback(self):
        """Test that additional kwargs are passed to callback constructors."""
        with patch('datadog_checks.mongo.oidc_callbacks.AzureWorkloadIdentityCallback') as mock_azure:
            create_oidc_callback('azure', timeout=60, custom_param='test')
            mock_azure.assert_called_once_with(timeout=60, custom_param='test')