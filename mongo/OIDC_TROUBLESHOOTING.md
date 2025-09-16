# MongoDB OIDC Workload Identity Troubleshooting Guide

This guide helps troubleshoot common issues when using OIDC workload identity authentication with the MongoDB Datadog integration.

## Prerequisites Verification

### Azure AKS Workload Identity

Before using Azure workload identity, verify these prerequisites:

1. **Environment Variables**: Ensure these environment variables are set in your pod:
   ```bash
   echo $AZURE_CLIENT_ID        # Should show your Azure application ID
   echo $AZURE_TENANT_ID        # Should show your Azure tenant ID  
   echo $AZURE_FEDERATED_TOKEN_FILE  # Should show path to token file (usually /var/run/secrets/azure/tokens/azure-identity-token)
   ```

2. **Token File Access**: Verify the token file exists and is readable:
   ```bash
   ls -la $AZURE_FEDERATED_TOKEN_FILE
   cat $AZURE_FEDERATED_TOKEN_FILE  # Should show a JWT token
   ```

3. **Pod Configuration**: Your pod should have the workload identity service account annotation:
   ```yaml
   metadata:
     annotations:
       azure.workload.identity/service-account-token-expiration: "3600"
   spec:
     serviceAccountName: workload-identity-sa
   ```

### Google GKE Workload Identity

For GKE workload identity, verify:

1. **Metadata Service Access**: Test access to the metadata service:
   ```bash
   curl -H "Metadata-Flavor: Google" \
     http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email
   ```

2. **Service Account**: Verify your pod is using the correct service account:
   ```bash
   kubectl get pod $POD_NAME -o yaml | grep serviceAccountName
   ```

3. **Workload Identity Binding**: Ensure the Kubernetes service account is bound to a Google service account:
   ```bash
   kubectl describe serviceaccount $SERVICE_ACCOUNT_NAME
   # Should show annotation: iam.gke.io/gcp-service-account=GSA_NAME@PROJECT_ID.iam.gserviceaccount.com
   ```

## Common Issues and Solutions

### Issue: "Azure workload identity not configured"

**Symptoms**: Error message mentioning missing environment variables.

**Solutions**:
1. Verify all required environment variables are set (see prerequisites above)
2. Check that your pod is properly configured with workload identity
3. Ensure the Azure workload identity webhook is running in your cluster

### Issue: "Failed to acquire Azure workload identity token"

**Symptoms**: Token acquisition fails even with environment variables set.

**Solutions**:
1. Check token file permissions: `ls -la $AZURE_FEDERATED_TOKEN_FILE`
2. Verify the token file contains a valid JWT: `cat $AZURE_FEDERATED_TOKEN_FILE | cut -d. -f2 | base64 -d`
3. Check network connectivity to Azure endpoints
4. Verify your Azure application has the necessary permissions

### Issue: "Failed to acquire GCP workload identity token"

**Symptoms**: GCP token acquisition fails.

**Solutions**:
1. Test metadata service connectivity: `curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/`
2. Check service account permissions in GCP IAM
3. Verify workload identity binding: `gcloud iam service-accounts get-iam-policy GSA_NAME@PROJECT_ID.iam.gserviceaccount.com`

### Issue: "Unsupported OIDC provider"

**Symptoms**: Error about unsupported provider even with correct configuration.

**Solutions**:
1. Check provider name spelling - supported values: `azure`, `aks`, `gcp`, `gke`, `google`
2. Verify YAML configuration syntax
3. Ensure provider name is lowercase

### Issue: MongoDB connection fails with OIDC authentication

**Symptoms**: MongoDB rejects OIDC authentication.

**Solutions**:
1. Verify MongoDB is configured for OIDC authentication
2. Check that the MongoDB user/role is properly configured for OIDC
3. Verify the auth_source setting matches your MongoDB configuration
4. Check MongoDB logs for authentication errors

### Issue: Token caching problems

**Symptoms**: Frequent re-authentication or token refresh failures.

**Solutions**:
1. Check system clock synchronization
2. Verify token expiration times in logs
3. Consider adjusting the timeout setting in configuration

## Debug Mode

To enable debug logging for troubleshooting:

```yaml
init_config:
  log_level: DEBUG

instances:
  - hosts:
      - your-mongodb-host:27017
    oidc_workload_identity:
      enabled: true
      provider: azure
    # ... rest of config
```

This will provide detailed logging about token acquisition and authentication steps.

## Testing Configuration

You can test your workload identity setup outside of the Datadog agent:

### Test Azure workload identity:
```bash
# Test token acquisition
curl -X POST -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=$AZURE_CLIENT_ID&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer&client_assertion=$(cat $AZURE_FEDERATED_TOKEN_FILE)&scope=https://graph.microsoft.com/.default&grant_type=client_credentials" \
  https://login.microsoftonline.com/$AZURE_TENANT_ID/oauth2/v2.0/token
```

### Test GCP workload identity:
```bash
# Test token acquisition
curl -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
```

## Getting Help

If you continue to experience issues:

1. Check the Datadog Agent logs for detailed error messages
2. Verify your cloud provider's workload identity documentation
3. Test MongoDB connectivity and authentication separately
4. Contact Datadog support with relevant logs and configuration details