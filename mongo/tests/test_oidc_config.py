# (C) Datadog, Inc. 2025-present
# All rights reserved
# Licensed under a 3-clause BSD style license (see LICENSE)

from unittest.mock import Mock, patch

import pytest

from datadog_checks.mongo.config import MongoConfig


class TestOIDCWorkloadIdentityConfig:
    def test_oidc_disabled_by_default(self):
        """Test that OIDC workload identity is disabled by default."""
        instance = {'hosts': ['localhost:27017']}
        log = Mock()
        init_config = {}
        
        config = MongoConfig(instance, log, init_config)
        
        assert config.oidc_workload_identity == {}
        assert config.use_oidc_workload_identity is False

    def test_oidc_enabled_with_provider(self):
        """Test that OIDC is enabled when configured with a provider."""
        instance = {
            'hosts': ['localhost:27017'],
            'oidc_workload_identity': {
                'enabled': True,
                'provider': 'azure'
            }
        }
        log = Mock()
        init_config = {}
        
        config = MongoConfig(instance, log, init_config)
        
        assert config.oidc_workload_identity['enabled'] is True
        assert config.oidc_workload_identity['provider'] == 'azure'
        assert config.use_oidc_workload_identity is True

    def test_oidc_disabled_without_provider(self):
        """Test that OIDC is disabled when enabled but no provider specified."""
        instance = {
            'hosts': ['localhost:27017'],
            'oidc_workload_identity': {
                'enabled': True
                # No provider specified
            }
        }
        log = Mock()
        init_config = {}
        
        config = MongoConfig(instance, log, init_config)
        
        assert config.use_oidc_workload_identity is False

    def test_oidc_config_options(self):
        """Test that OIDC configuration options are properly stored."""
        instance = {
            'hosts': ['localhost:27017'],
            'oidc_workload_identity': {
                'enabled': True,
                'provider': 'gcp',
                'timeout': 60,
                'auth_source': 'external'
            }
        }
        log = Mock()
        init_config = {}
        
        config = MongoConfig(instance, log, init_config)
        
        assert config.oidc_workload_identity['provider'] == 'gcp'
        assert config.oidc_workload_identity['timeout'] == 60
        assert config.oidc_workload_identity['auth_source'] == 'external'
        assert config.use_oidc_workload_identity is True

    def test_oidc_authentication_enabled_without_username(self):
        """Test that authentication is enabled with OIDC even without username."""
        instance = {
            'hosts': ['localhost:27017'],
            'oidc_workload_identity': {
                'enabled': True,
                'provider': 'azure'
            }
            # No username or password
        }
        log = Mock()
        init_config = {}
        
        config = MongoConfig(instance, log, init_config)
        
        assert config.do_auth is True
        assert config.use_oidc_workload_identity is True

    def test_standard_auth_disabled_without_username(self):
        """Test that standard authentication is disabled without username when not using OIDC."""
        instance = {
            'hosts': ['localhost:27017']
            # No username, password, or OIDC config
        }
        log = Mock()
        init_config = {}
        
        config = MongoConfig(instance, log, init_config)
        
        assert config.do_auth is False
        assert config.use_oidc_workload_identity is False

    def test_oidc_with_standard_auth_fields(self):
        """Test that OIDC can coexist with standard auth fields (though OIDC takes precedence)."""
        instance = {
            'hosts': ['localhost:27017'],
            'username': 'testuser',
            'password': 'testpass',
            'oidc_workload_identity': {
                'enabled': True,
                'provider': 'gcp'
            }
        }
        log = Mock()
        init_config = {}
        
        config = MongoConfig(instance, log, init_config)
        
        assert config.username == 'testuser'
        assert config.password == 'testpass'
        assert config.use_oidc_workload_identity is True
        assert config.do_auth is True