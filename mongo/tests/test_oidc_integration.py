# (C) Datadog, Inc. 2025-present
# All rights reserved
# Licensed under a 3-clause BSD style license (see LICENSE)

"""
Integration tests for OIDC workload identity functionality.
"""

import os
from unittest.mock import Mock, patch

import pytest

from datadog_checks.mongo.api import MongoApi
from datadog_checks.mongo.config import MongoConfig
from datadog_checks.mongo.mongo import MongoDb


class TestOIDCWorkloadIdentityIntegration:
    """Test OIDC workload identity functionality end-to-end."""

    def test_oidc_azure_configuration_end_to_end(self):
        """Test that Azure OIDC configuration is properly applied to MongoClient."""
        instance = {
            'hosts': ['localhost:27017'],
            'oidc_workload_identity': {
                'enabled': True,
                'provider': 'azure',
                'timeout': 45,
                'auth_source': 'external'
            }
        }
        
        log = Mock()
        init_config = {}
        
        # Test configuration parsing
        config = MongoConfig(instance, log, init_config)
        
        assert config.use_oidc_workload_identity is True
        assert config.oidc_workload_identity['provider'] == 'azure'
        assert config.oidc_workload_identity['timeout'] == 45
        assert config.do_auth is True
        
        # Test MongoApi setup with mocked MongoClient
        with patch('datadog_checks.mongo.api.MongoClient') as mock_mongo_client:
            with patch('datadog_checks.mongo.oidc_callbacks.create_oidc_callback') as mock_create_callback:
                # Mock the OIDC callback
                mock_callback = Mock()
                mock_create_callback.return_value = mock_callback
                
                # Create the MongoApi instance
                api = MongoApi(config, log)
                
                # Verify MongoClient was called with correct OIDC configuration
                mock_mongo_client.assert_called_once()
                call_args = mock_mongo_client.call_args[1]
                
                # Should have OIDC authentication mechanism
                assert call_args['authMechanism'] == 'MONGODB-OIDC'
                assert 'authMechanismProperties' in call_args
                assert call_args['authMechanismProperties']['OIDC_CALLBACK'] == mock_callback
                assert call_args['authSource'] == 'external'
                
                # Verify callback was created with correct parameters
                mock_create_callback.assert_called_once_with('azure', timeout=45)

    def test_oidc_gcp_configuration_end_to_end(self):
        """Test that GCP OIDC configuration is properly applied to MongoClient."""
        instance = {
            'hosts': ['localhost:27017'],
            'oidc_workload_identity': {
                'enabled': True,
                'provider': 'gcp',
                'timeout': 60
            },
            'database': 'testdb'
        }
        
        log = Mock()
        init_config = {}
        
        # Test configuration parsing
        config = MongoConfig(instance, log, init_config)
        
        assert config.use_oidc_workload_identity is True
        assert config.oidc_workload_identity['provider'] == 'gcp'
        assert config.oidc_workload_identity['timeout'] == 60
        
        # Test MongoApi setup with mocked MongoClient
        with patch('datadog_checks.mongo.api.MongoClient') as mock_mongo_client:
            with patch('datadog_checks.mongo.oidc_callbacks.create_oidc_callback') as mock_create_callback:
                # Mock the OIDC callback
                mock_callback = Mock()
                mock_create_callback.return_value = mock_callback
                
                # Create the MongoApi instance
                api = MongoApi(config, log)
                
                # Verify MongoClient was called with correct OIDC configuration
                mock_mongo_client.assert_called_once()
                call_args = mock_mongo_client.call_args[1]
                
                # Should have OIDC authentication mechanism
                assert call_args['authMechanism'] == 'MONGODB-OIDC'
                assert call_args['authMechanismProperties']['OIDC_CALLBACK'] == mock_callback
                # Should use database as auth source when no specific auth_source provided
                assert call_args['authSource'] == 'testdb'
                
                # Verify callback was created with correct parameters
                mock_create_callback.assert_called_once_with('gcp', timeout=60)

    def test_oidc_with_standard_auth_fallback(self):
        """Test that OIDC takes precedence when both OIDC and standard auth are configured."""
        instance = {
            'hosts': ['localhost:27017'],
            'username': 'regular_user',
            'password': 'regular_password',
            'oidc_workload_identity': {
                'enabled': True,
                'provider': 'azure'
            }
        }
        
        log = Mock()
        init_config = {}
        
        config = MongoConfig(instance, log, init_config)
        
        # Should use OIDC, not standard auth
        assert config.use_oidc_workload_identity is True
        assert config.username == 'regular_user'  # Still stored
        assert config.password == 'regular_password'  # Still stored
        
        with patch('datadog_checks.mongo.api.MongoClient') as mock_mongo_client:
            with patch('datadog_checks.mongo.oidc_callbacks.create_oidc_callback') as mock_create_callback:
                mock_callback = Mock()
                mock_create_callback.return_value = mock_callback
                
                api = MongoApi(config, log)
                
                call_args = mock_mongo_client.call_args[1]
                
                # Should use OIDC, not username/password
                assert call_args['authMechanism'] == 'MONGODB-OIDC'
                assert 'username' not in call_args
                assert 'password' not in call_args
                assert call_args['authMechanismProperties']['OIDC_CALLBACK'] == mock_callback

    def test_oidc_disabled_falls_back_to_standard_auth(self):
        """Test that when OIDC is disabled, standard authentication is used."""
        instance = {
            'hosts': ['localhost:27017'],
            'username': 'regular_user',
            'password': 'regular_password',
            'oidc_workload_identity': {
                'enabled': False,
                'provider': 'azure'
            }
        }
        
        log = Mock()
        init_config = {}
        
        config = MongoConfig(instance, log, init_config)
        
        # Should not use OIDC
        assert config.use_oidc_workload_identity is False
        
        with patch('datadog_checks.mongo.api.MongoClient') as mock_mongo_client:
            api = MongoApi(config, log)
            
            call_args = mock_mongo_client.call_args[1]
            
            # Should use standard username/password auth
            assert 'authMechanism' not in call_args
            assert call_args['username'] == 'regular_user'
            assert call_args['password'] == 'regular_password'

    def test_oidc_error_handling(self):
        """Test error handling when OIDC callback creation fails."""
        instance = {
            'hosts': ['localhost:27017'],
            'oidc_workload_identity': {
                'enabled': True,
                'provider': 'invalid_provider'
            }
        }
        
        log = Mock()
        init_config = {}
        
        config = MongoConfig(instance, log, init_config)
        
        # Should attempt to use OIDC
        assert config.use_oidc_workload_identity is True
        
        with patch('datadog_checks.mongo.api.MongoClient') as mock_mongo_client:
            with patch('datadog_checks.mongo.oidc_callbacks.create_oidc_callback') as mock_create_callback:
                # Make callback creation fail
                mock_create_callback.side_effect = ValueError("Unsupported OIDC provider")
                
                # Should raise exception during API initialization
                with pytest.raises(ValueError, match="Unsupported OIDC provider"):
                    api = MongoApi(config, log)

    def test_mongo_check_with_oidc_integration(self):
        """Test that the main MongoDb check class works with OIDC configuration."""
        instance = {
            'hosts': ['localhost:27017'],
            'oidc_workload_identity': {
                'enabled': True,
                'provider': 'azure'
            }
        }
        
        init_config = {}
        
        # Mock the connection attempt to avoid actually connecting
        with patch('datadog_checks.mongo.api.MongoClient') as mock_mongo_client:
            with patch('datadog_checks.mongo.oidc_callbacks.create_oidc_callback') as mock_create_callback:
                mock_callback = Mock()
                mock_create_callback.return_value = mock_callback
                
                # Mock successful connection
                mock_client_instance = Mock()
                mock_client_instance.__getitem__.return_value.command.return_value = {}
                mock_mongo_client.return_value = mock_client_instance
                
                # Create the check
                check = MongoDb('mongo', init_config, [instance])
                
                # Should create config without errors
                assert len(check._config.instances) == 1
                assert check._config.instances[0].use_oidc_workload_identity is True