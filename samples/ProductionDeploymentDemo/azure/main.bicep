// PostQuantum.Jwt ProductionDeploymentDemo — Azure Container Apps deployment.
//
// Deploys three Container Apps inside one managed Environment:
//   - issuerapi   (public ingress, scale-to-zero, rate-limited)
//   - ordersapi   (public ingress, scale-to-zero, rate-limited)
//   - redis       (internal-only ingress on port 6379, sidecar replay store)
//
// All three pull images from a public registry (default: ghcr.io). No Container
// Registry pull secret is needed for public images. Logs go to a Log Analytics
// workspace created here so `az containerapp logs show` works out of the box.
//
// Cost shape: scale-to-zero on all three apps. With no traffic, monthly cost
// rounds to $0 (Container Apps' free tier covers ~180k vCPU-seconds and
// ~360k GiB-seconds per month). Log Analytics has a 5 GB/month free tier.
// Idle Redis Container App also scales to zero.
//
// Demo only — never trust tokens issued from this deployment. The IssuerApi
// uses ephemeral keys that reset on every cold start.

@description('Resource name prefix. Final names become `<prefix>-issuer`, etc.')
param namePrefix string = 'pqjwt-demo'

@description('Azure region.')
param location string = resourceGroup().location

@description('Image for the IssuerApi container.')
param issuerImage string = 'ghcr.io/systemslibrarian/pqjwt-demo-issuer:latest'

@description('Image for the OrdersApi container.')
param ordersImage string = 'ghcr.io/systemslibrarian/pqjwt-demo-orders:latest'

@description('Image for the Redis sidecar (used purely as a replay-cache backend).')
param redisImage string = 'redis:7-alpine'

@description('Per-IP fixed-window permits for the IssuerApi rate limiter.')
@minValue(1)
@maxValue(1000)
param issuerRateLimitPermits int = 10

@description('Per-IP fixed-window permits for the OrdersApi rate limiter.')
@minValue(1)
@maxValue(1000)
param ordersRateLimitPermits int = 20

@description('Window in seconds for both rate limiters.')
@minValue(1)
@maxValue(3600)
param rateLimitWindowSeconds int = 60

// -------- Log Analytics --------
resource logs 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: '${namePrefix}-logs'
  location: location
  properties: {
    retentionInDays: 30
    sku: { name: 'PerGB2018' }
  }
}

// -------- Container Apps Environment --------
resource env 'Microsoft.App/managedEnvironments@2024-03-01' = {
  name: '${namePrefix}-env'
  location: location
  properties: {
    appLogsConfiguration: {
      destination: 'log-analytics'
      logAnalyticsConfiguration: {
        customerId: logs.properties.customerId
        sharedKey: logs.listKeys().primarySharedKey
      }
    }
  }
}

// -------- Redis (internal-only, replay backend) --------
resource redis 'Microsoft.App/containerApps@2024-03-01' = {
  name: '${namePrefix}-redis'
  location: location
  properties: {
    managedEnvironmentId: env.id
    configuration: {
      ingress: {
        external: false
        targetPort: 6379
        exposedPort: 6379
        transport: 'tcp'
        allowInsecure: true
      }
    }
    template: {
      containers: [
        {
          name: 'redis'
          image: redisImage
          resources: {
            cpu: json('0.25')
            memory: '0.5Gi'
          }
        }
      ]
      scale: {
        minReplicas: 0
        maxReplicas: 1
      }
    }
  }
}

// -------- OrdersApi --------
resource orders 'Microsoft.App/containerApps@2024-03-01' = {
  name: '${namePrefix}-orders'
  location: location
  properties: {
    managedEnvironmentId: env.id
    configuration: {
      ingress: {
        external: true
        targetPort: 8080
        transport: 'auto'
        allowInsecure: false
      }
    }
    template: {
      containers: [
        {
          name: 'ordersapi'
          image: ordersImage
          resources: {
            cpu: json('0.5')
            memory: '1.0Gi'
          }
          env: [
            { name: 'ASPNETCORE_HTTP_PORTS', value: '8080' }
            { name: 'PQJWT_ISSUER', value: 'https://${namePrefix}-issuer-demo.local' }
            { name: 'PQJWT_AUDIENCE', value: 'https://${namePrefix}-orders-demo.local' }
            { name: 'ISSUER_KEYS_URL', value: 'https://${namePrefix}-issuer.${env.properties.defaultDomain}/.well-known/pqjwt-keys' }
            { name: 'REDIS_CONNECTION', value: '${namePrefix}-redis:6379' }
            { name: 'PQJWT_KEY_REFRESH_SECONDS', value: '5' }
            { name: 'ALLOW_INSECURE_KEY_DIRECTORY', value: 'false' }
            { name: 'RATE_LIMIT_PERMITS', value: string(ordersRateLimitPermits) }
            { name: 'RATE_LIMIT_WINDOW_SECONDS', value: string(rateLimitWindowSeconds) }
          ]
          probes: [
            {
              type: 'liveness'
              httpGet: { path: '/health', port: 8080 }
              initialDelaySeconds: 10
              periodSeconds: 30
            }
          ]
        }
      ]
      scale: {
        minReplicas: 0
        maxReplicas: 1
      }
    }
  }
  dependsOn: [redis]
}

// -------- IssuerApi --------
resource issuer 'Microsoft.App/containerApps@2024-03-01' = {
  name: '${namePrefix}-issuer'
  location: location
  properties: {
    managedEnvironmentId: env.id
    configuration: {
      ingress: {
        external: true
        targetPort: 8080
        transport: 'auto'
        allowInsecure: false
      }
    }
    template: {
      containers: [
        {
          name: 'issuerapi'
          image: issuerImage
          resources: {
            cpu: json('0.5')
            memory: '1.0Gi'
          }
          env: [
            { name: 'ASPNETCORE_HTTP_PORTS', value: '8080' }
            { name: 'PQJWT_ISSUER', value: 'https://${namePrefix}-issuer-demo.local' }
            { name: 'PQJWT_AUDIENCE', value: 'https://${namePrefix}-orders-demo.local' }
            { name: 'PQJWT_ENCRYPTED_TOKENS', value: 'true' }
            { name: 'ORDERS_RECIPIENT_KEY_URL', value: 'https://${namePrefix}-orders.${env.properties.defaultDomain}/.well-known/pqjwt-recipient-key' }
            { name: 'PQJWT_RECIPIENT_KEY_REFRESH_SECONDS', value: '60' }
            { name: 'RATE_LIMIT_PERMITS', value: string(issuerRateLimitPermits) }
            { name: 'RATE_LIMIT_WINDOW_SECONDS', value: string(rateLimitWindowSeconds) }
          ]
          probes: [
            {
              type: 'liveness'
              httpGet: { path: '/health', port: 8080 }
              initialDelaySeconds: 10
              periodSeconds: 30
            }
          ]
        }
      ]
      scale: {
        minReplicas: 0
        maxReplicas: 1
      }
    }
  }
  dependsOn: [orders]
}

output issuerFqdn string = issuer.properties.configuration.ingress.fqdn
output ordersFqdn string = orders.properties.configuration.ingress.fqdn
output environmentDefaultDomain string = env.properties.defaultDomain
output logAnalyticsWorkspaceId string = logs.id
