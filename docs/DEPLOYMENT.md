# Imladris Deployment Guide

Procedures for deploying services and managing the platform.

## Overview

The deployment flow follows GitOps principles:

```
Code Push → Policy Validation → Container Build → GitOps Sync → Kubernetes → Running Service
(GitHub)      (Conftest/OPA)      (ECR/Docker)     (ArgoCD)       (EKS)
```

All deployments are initiated through Git commits to the GitOps repository.

## Deploying a New Service

### 1. Create Service from Template

```bash
# Clone the service template
git clone https://github.com/your-org/imladris-service-template.git my-service
cd my-service

# Configure for your service
export SERVICE_NAME="payment-processor"
export NAMESPACE="banking-core"
export AWS_ACCOUNT_ID="123456789012"
export AWS_ECR_REPO="123456789012.dkr.ecr.us-east-1.amazonaws.com"

# Replace template values
sed -i "s/banking-core-service/$SERVICE_NAME/g" k8s/deployment.yaml k8s/service.yaml main.go
sed -i "s|banking-core-service|$AWS_ECR_REPO/$SERVICE_NAME|g" k8s/deployment.yaml
```

### 2. Implement Service Logic

Modify `main.go` to implement your business logic:

```go
// Add your API endpoints
func handleAccounts(w http.ResponseWriter, r *http.Request) {
    // Your implementation
}

// Register route
http.HandleFunc("/api/v1/accounts", handleAccounts)
```

### 3. Local Testing

```bash
# Install dependencies
go mod download

# Run tests
go test -v ./...

# Run locally
go run main.go

# Test endpoint
curl http://localhost:8080/health
curl http://localhost:8080/api/v1/accounts
```

### 4. Container Building and Testing

```bash
# Build container image
docker build -t $AWS_ECR_REPO/$SERVICE_NAME:latest .

# Run container locally
docker run -p 8080:8080 -p 9090:9090 \
  -e SERVICE_NAME=$SERVICE_NAME \
  $AWS_ECR_REPO/$SERVICE_NAME:latest

# Security scan with Trivy
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  aquasec/trivy image $AWS_ECR_REPO/$SERVICE_NAME:latest

# Push to ECR (if tests pass)
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin $AWS_ECR_REPO
docker push $AWS_ECR_REPO/$SERVICE_NAME:latest
```

### 5. Deploy with GitOps

#### Create GitOps Manifests

Create a directory in the GitOps repository:

```bash
# In imladris-gitops repository
mkdir -p tenants/$NAMESPACE/$SERVICE_NAME
cd tenants/$NAMESPACE/$SERVICE_NAME
```

Create `namespace.yaml`:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: $NAMESPACE
  labels:
    name: $NAMESPACE
    tier: application
    compliance: pci-dss
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: $NAMESPACE
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
```

Create `deployment.yaml`:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: $SERVICE_NAME
  namespace: $NAMESPACE
  labels:
    app: $SERVICE_NAME
    tier: application
spec:
  replicas: 2
  selector:
    matchLabels:
      app: $SERVICE_NAME
  template:
    metadata:
      labels:
        app: $SERVICE_NAME
    spec:
      serviceAccountName: $SERVICE_NAME
      containers:
      - name: $SERVICE_NAME
        image: $AWS_ECR_REPO/$SERVICE_NAME:latest
        imagePullPolicy: Always
        ports:
        - name: http
          containerPort: 8080
        - name: metrics
          containerPort: 9090
        env:
        - name: SERVICE_NAME
          value: $SERVICE_NAME
        - name: ENVIRONMENT
          value: prod
        - name: LOG_LEVEL
          value: info
        livenessProbe:
          httpGet:
            path: /health
            port: http
          initialDelaySeconds: 10
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: http
          initialDelaySeconds: 5
          periodSeconds: 5
        resources:
          requests:
            cpu: "100m"
            memory: "128Mi"
            ephemeral-storage: "100Mi"
          limits:
            cpu: "500m"
            memory: "512Mi"
            ephemeral-storage: "1Gi"
        securityContext:
          runAsNonRoot: true
          runAsUser: 65534
          readOnlyRootFilesystem: true
          allowPrivilegeEscalation: false
          capabilities:
            drop:
            - ALL
```

Create `service.yaml`:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: $SERVICE_NAME
  namespace: $NAMESPACE
  labels:
    app: $SERVICE_NAME
  annotations:
    prometheus.io/scrape: "true"
    prometheus.io/port: "9090"
    prometheus.io/path: "/metrics"
spec:
  type: ClusterIP
  selector:
    app: $SERVICE_NAME
  ports:
  - name: http
    port: 80
    targetPort: http
  - name: metrics
    port: 9090
    targetPort: metrics
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: $SERVICE_NAME
  namespace: $NAMESPACE
```

Create `vpc-lattice-service.yaml`:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: $SERVICE_NAME-lattice
  namespace: $NAMESPACE
  labels:
    app: $SERVICE_NAME
  annotations:
    service.beta.kubernetes.io/aws-load-balancer-type: "external"
    service.beta.kubernetes.io/aws-load-balancer-scheme: "internal"
    vpc.amazonaws.com/nlb-target-type: "ip"
spec:
  type: LoadBalancer
  selector:
    app: $SERVICE_NAME
  ports:
  - protocol: TCP
    port: 443
    targetPort: http
    name: https
```

#### Commit and Push

```bash
git add .
git commit -m "Deploy $SERVICE_NAME to $NAMESPACE namespace"
git push origin main
```

### 6. Verify Deployment

Monitor deployment progress:

```bash
# Watch ArgoCD sync
argocd app list
argocd app get root --refresh
argocd app watch root

# Check Kubernetes resources
kubectl get pods -n $NAMESPACE
kubectl get services -n $NAMESPACE
kubectl get networkpolicies -n $NAMESPACE

# Check pod logs
kubectl logs -f deployment/$SERVICE_NAME -n $NAMESPACE

# Verify health
kubectl port-forward -n $NAMESPACE svc/$SERVICE_NAME 8080:80
curl http://localhost:8080/health
```

## Updating a Service

### Update Code

```bash
# Make changes to main.go
# Commit changes
git add main.go
git commit -m "Update payment processor logic"
git push origin main
```

### Trigger CI/CD

GitHub Actions workflow automatically:
1. Builds container image
2. Runs security scans
3. Validates policies
4. Pushes to ECR
5. Updates GitOps manifests
6. Triggers ArgoCD sync

### Verify Update

```bash
# Monitor deployment rollout
kubectl rollout status deployment/$SERVICE_NAME -n $NAMESPACE

# Check logs
kubectl logs -f deployment/$SERVICE_NAME -n $NAMESPACE

# Verify service is responding
curl http://localhost:8080/health
```

## Scaling Services

### Manual Scaling

```bash
# Scale up to 5 replicas
kubectl scale deployment $SERVICE_NAME --replicas=5 -n $NAMESPACE

# Or edit deployment
kubectl edit deployment $SERVICE_NAME -n $NAMESPACE
# Change spec.replicas to desired number
```

### Automatic Scaling

Add HorizontalPodAutoscaler:

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: $SERVICE_NAME-hpa
  namespace: $NAMESPACE
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: $SERVICE_NAME
  minReplicas: 2
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
```

## Canary Deployments

Deploy new versions to subset of replicas:

```bash
# Create canary deployment
kubectl set image deployment/$SERVICE_NAME \
  $SERVICE_NAME=$AWS_ECR_REPO/$SERVICE_NAME:canary \
  --record -n $NAMESPACE

# Monitor canary
kubectl rollout status deployment/$SERVICE_NAME -n $NAMESPACE
kubectl get pods -n $NAMESPACE -L version

# Promote canary if healthy
kubectl set image deployment/$SERVICE_NAME \
  $SERVICE_NAME=$AWS_ECR_REPO/$SERVICE_NAME:latest \
  --record -n $NAMESPACE

# Rollback if issues
kubectl rollout undo deployment/$SERVICE_NAME -n $NAMESPACE
```

## Rollback Procedures

### Using ArgoCD

```bash
# View revision history
argocd app history $SERVICE_NAME

# Rollback to previous revision
argocd app rollback $SERVICE_NAME 1

# Verify rollback
argocd app get $SERVICE_NAME
```

### Using kubectl

```bash
# View rollout history
kubectl rollout history deployment/$SERVICE_NAME -n $NAMESPACE

# Rollback to previous version
kubectl rollout undo deployment/$SERVICE_NAME -n $NAMESPACE

# Rollback to specific revision
kubectl rollout undo deployment/$SERVICE_NAME --to-revision=2 -n $NAMESPACE

# Verify rollback
kubectl rollout status deployment/$SERVICE_NAME -n $NAMESPACE
```

## Network Policy Management

### View Active Policies

```bash
kubectl get networkpolicies -n $NAMESPACE
kubectl describe networkpolicy default-deny-all -n $NAMESPACE
```

### Update Network Policies

Edit and apply NetworkPolicy resources:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-payment-to-database
  namespace: banking-core
spec:
  podSelector:
    matchLabels:
      app: payment-processor
  policyTypes:
  - Egress
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: database
    ports:
    - protocol: TCP
      port: 5432
```

Apply the policy:

```bash
kubectl apply -f network-policy.yaml
```

## VPC Lattice Service Registration

Verify service is registered with VPC Lattice:

```bash
# List VPC Lattice services
aws vpc-lattice list-services

# Get service details
aws vpc-lattice get-service \
  --service-identifier $SERVICE_NAME-$NAMESPACE \
  --query 'service'

# List service targets
aws vpc-lattice list-target-groups \
  --vpc-identifier vpc-xxx
```

Test cross-namespace communication via VPC Lattice:

```bash
# From another pod, call the service
kubectl run -it --rm debug --image=curlimages/curl:latest \
  --restart=Never -n kube-system -- \
  curl https://$SERVICE_NAME.$NAMESPACE.local/health
```

## Monitoring and Observability

### View Metrics

Port forward to Prometheus:

```bash
kubectl port-forward -n monitoring svc/prometheus 9090:9090
# Access at http://localhost:9090
```

View service metrics:

```bash
# HTTP request rate
rate(http_requests_total{job="$SERVICE_NAME"}[5m])

# Error rate
rate(http_requests_total{job="$SERVICE_NAME",status_code=~"5.."}[5m])

# P95 latency
histogram_quantile(0.95, http_request_duration_seconds_bucket{job="$SERVICE_NAME"})
```

### View Logs

```bash
# View logs from all replicas
kubectl logs -f deployment/$SERVICE_NAME -n $NAMESPACE --all-containers

# View logs from specific pod
kubectl logs -f pod/$SERVICE_NAME-xxx -n $NAMESPACE

# Stream logs with timestamps
kubectl logs -f deployment/$SERVICE_NAME -n $NAMESPACE --timestamps
```

## Compliance Verification

### Policy Validation

Policies are automatically validated in CI/CD pipeline, but can be manually tested:

```bash
# Validate deployment against policies
conftest verify --policy imladris-governance/policies \
  tenants/$NAMESPACE/$SERVICE_NAME/deployment.yaml

# Validate terraform plan
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json
conftest verify --policy imladris-governance/policies tfplan.json
```

### Audit Trail

View all changes in Git history:

```bash
git log --oneline tenants/$NAMESPACE/$SERVICE_NAME/
git diff HEAD~1 tenants/$NAMESPACE/$SERVICE_NAME/deployment.yaml
```

View ArgoCD sync events:

```bash
argocd app history $SERVICE_NAME
argocd app events $SERVICE_NAME
```

## Emergency Procedures

### Emergency Stop

Suspend service:

```bash
kubectl delete deployment $SERVICE_NAME -n $NAMESPACE
```

Or scale to zero:

```bash
kubectl scale deployment $SERVICE_NAME --replicas=0 -n $NAMESPACE
```

### Break Glass Deployment

Bypass GitOps for emergency fixes:

```bash
# Suspend ArgoCD automatic sync
argocd app patch root --patch '{"spec":{"syncPolicy":null}}'

# Apply hotfix directly
kubectl set image deployment/$SERVICE_NAME \
  $SERVICE_NAME=$AWS_ECR_REPO/$SERVICE_NAME:hotfix \
  -n $NAMESPACE

# Re-enable automatic sync when issue resolved
argocd app patch root --patch '{"spec":{"syncPolicy":{"automated":{"prune":true,"selfHeal":true}}}}'
```

### Disaster Recovery

Restore from previous deployment:

```bash
# List previous commits
git log --oneline tenants/$NAMESPACE/$SERVICE_NAME/

# Checkout previous version
git checkout <commit-hash> tenants/$NAMESPACE/$SERVICE_NAME/

# Push recovery commit
git commit -m "Recovery: revert to previous deployment"
git push origin main

# ArgoCD automatically syncs
```

## Troubleshooting

### Pod won't start

```bash
# Check pod status
kubectl describe pod $SERVICE_NAME-xxx -n $NAMESPACE

# Check pod logs
kubectl logs -f pod/$SERVICE_NAME-xxx -n $NAMESPACE

# Check resource availability
kubectl top nodes
kubectl top pods -n $NAMESPACE

# Check network policies
kubectl get networkpolicies -n $NAMESPACE
kubectl describe networkpolicy default-deny-all -n $NAMESPACE
```

### Health check failures

```bash
# Test endpoint manually
kubectl port-forward -n $NAMESPACE svc/$SERVICE_NAME 8080:80
curl -v http://localhost:8080/health

# Check probe configuration
kubectl get deployment $SERVICE_NAME -n $NAMESPACE -o yaml | grep -A 20 livenessProbe

# Check logs around probe time
kubectl logs deployment/$SERVICE_NAME -n $NAMESPACE --tail=50
```

### VPC Lattice connectivity issues

```bash
# Check service registration
aws vpc-lattice list-services

# Test DNS resolution
kubectl run -it --rm debug --image=busybox --restart=Never -- \
  nslookup $SERVICE_NAME.$NAMESPACE.local

# Check security group rules
aws ec2 describe-security-groups --query 'SecurityGroups[].IpPermissions[]'
```

## References

- [Kubernetes Documentation](https://kubernetes.io/docs/)
- [ArgoCD Documentation](https://argo-cd.readthedocs.io/)
- [VPC Lattice Documentation](https://docs.aws.amazon.com/vpc-lattice/)
- [Imladris Platform README](./README.md)
- [Imladris Setup Guide](./SETUP.md)
