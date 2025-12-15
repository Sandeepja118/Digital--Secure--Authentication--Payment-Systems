# Kubernetes Deployment Guide for Django Application

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Architecture Overview](#architecture-overview)
3. [Deployment Steps](#deployment-steps)
4. [Managing Secrets](#managing-secrets)
5. [Scaling](#scaling)
6. [Database Migrations](#database-migrations)
7. [Monitoring and Logging](#monitoring-and-logging)
8. [Rolling Updates](#rolling-updates)
9. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### Required Tools
- **kubectl** (v1.24+): Kubernetes command-line tool
  ```bash
  # Install kubectl
  curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
  sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl
  ```

- **Docker**: For building and pushing container images
  ```bash
  # Verify installation
  docker --version
  ```

- **Helm** (v3+): Package manager for Kubernetes (optional but recommended)
  ```bash
  curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
  ```

### Kubernetes Cluster
- A running Kubernetes cluster (1.24 or higher)
  - Local: minikube, Docker Desktop, or kind
  - Cloud: EKS, GKE, AKS, or any managed Kubernetes service

### Docker Registry
- Access to a Docker registry (Docker Hub, ECR, GCR, or private registry)
- Authenticated credentials for pushing images

### Application Requirements
- Django application with proper Python dependencies in `requirements.txt`
- `.env` file or environment variable configuration
- Database URL for PostgreSQL (or your chosen database)
- Redis URL for caching/sessions (if using)

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                      Load Balancer / Ingress                │
└──────────────────────┬──────────────────────────────────────┘
                       │
        ┌──────────────┴──────────────┐
        │                             │
   ┌────▼────┐                  ┌────▼────┐
   │ Django  │                  │ Django  │
   │Pod (1)  │                  │Pod (2)  │
   └────┬────┘                  └────┬────┘
        │                             │
        └──────────────┬──────────────┘
                       │
        ┌──────────────┴──────────────┐
        │                             │
   ┌────▼────┐                  ┌────▼────┐
   │PostgreSQL│                  │Redis    │
   │StatefulSet│                 │Cache    │
   └──────────┘                  └────────┘
```

---

## Deployment Steps

### Step 1: Build and Push Docker Image

```bash
# Clone the repository
git clone https://github.com/Sandeepja118/Digital--Secure--Authentication--Payment-Systems.git
cd Digital--Secure--Authentication--Payment-Systems

# Build Docker image
docker build -t your-registry/django-app:latest .

# Push to registry
docker push your-registry/django-app:latest
```

**Sample Dockerfile** (if not present):
```dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Copy and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create non-root user
RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app
USER appuser

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8000/health/')"

# Start gunicorn
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "4", "--timeout", "120", "config.wsgi:application"]
```

### Step 2: Create Kubernetes Namespace

```bash
# Create namespace for the application
kubectl create namespace django-app

# Verify creation
kubectl get namespace django-app
```

### Step 3: Deploy PostgreSQL Database

**Create PersistentVolume and PersistentVolumeClaim:**
```yaml
# postgres-pvc.yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: postgres-pvc
  namespace: django-app
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 10Gi
  storageClassName: standard
```

**Deploy PostgreSQL StatefulSet:**
```yaml
# postgres-deployment.yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: postgres
  namespace: django-app
spec:
  serviceName: postgres
  replicas: 1
  selector:
    matchLabels:
      app: postgres
  template:
    metadata:
      labels:
        app: postgres
    spec:
      containers:
      - name: postgres
        image: postgres:15-alpine
        ports:
        - containerPort: 5432
          name: postgres
        env:
        - name: POSTGRES_USER
          valueFrom:
            secretKeyRef:
              name: db-secret
              key: username
        - name: POSTGRES_PASSWORD
          valueFrom:
            secretKeyRef:
              name: db-secret
              key: password
        - name: POSTGRES_DB
          value: "django_db"
        - name: PGDATA
          value: /var/lib/postgresql/data/pgdata
        volumeMounts:
        - name: postgres-storage
          mountPath: /var/lib/postgresql/data
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          exec:
            command:
            - /bin/sh
            - -c
            - pg_isready -U $POSTGRES_USER
          initialDelaySeconds: 30
          periodSeconds: 10
  volumeClaimTemplates:
  - metadata:
      name: postgres-storage
    spec:
      accessModes: [ "ReadWriteOnce" ]
      resources:
        requests:
          storage: 10Gi
---
apiVersion: v1
kind: Service
metadata:
  name: postgres
  namespace: django-app
spec:
  clusterIP: None
  selector:
    app: postgres
  ports:
  - port: 5432
    targetPort: 5432
```

### Step 4: Deploy Django Application

**Create Django Deployment:**
```yaml
# django-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: django-app
  namespace: django-app
  labels:
    app: django-app
spec:
  replicas: 3
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 0
  selector:
    matchLabels:
      app: django-app
  template:
    metadata:
      labels:
        app: django-app
    spec:
      serviceAccountName: django-app
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
      containers:
      - name: django
        image: your-registry/django-app:latest
        imagePullPolicy: Always
        ports:
        - containerPort: 8000
          name: http
        env:
        - name: ENVIRONMENT
          value: "production"
        - name: DEBUG
          value: "False"
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: db-secret
              key: database-url
        - name: SECRET_KEY
          valueFrom:
            secretKeyRef:
              name: django-secret
              key: secret-key
        - name: ALLOWED_HOSTS
          valueFrom:
            configMapKeyRef:
              name: django-config
              key: allowed-hosts
        - name: REDIS_URL
          valueFrom:
            secretKeyRef:
              name: redis-secret
              key: redis-url
        livenessProbe:
          httpGet:
            path: /health/
            port: 8000
          initialDelaySeconds: 30
          periodSeconds: 10
          timeoutSeconds: 5
          failureThreshold: 3
        readinessProbe:
          httpGet:
            path: /ready/
            port: 8000
          initialDelaySeconds: 10
          periodSeconds: 5
          timeoutSeconds: 3
          failureThreshold: 2
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: false
          capabilities:
            drop:
            - ALL
      affinity:
        podAntiAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
          - weight: 100
            podAffinityTerm:
              labelSelector:
                matchExpressions:
                - key: app
                  operator: In
                  values:
                  - django-app
              topologyKey: kubernetes.io/hostname
---
apiVersion: v1
kind: Service
metadata:
  name: django-app
  namespace: django-app
  labels:
    app: django-app
spec:
  type: ClusterIP
  selector:
    app: django-app
  ports:
  - port: 80
    targetPort: 8000
    protocol: TCP
    name: http
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: django-app
  namespace: django-app
```

### Step 5: Create Ingress

```yaml
# ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: django-ingress
  namespace: django-app
  annotations:
    nginx.ingress.kubernetes.io/rewrite-target: /
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
spec:
  ingressClassName: nginx
  tls:
  - hosts:
    - yourdomain.com
    - www.yourdomain.com
    secretName: django-tls
  rules:
  - host: yourdomain.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: django-app
            port:
              number: 80
  - host: www.yourdomain.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: django-app
            port:
              number: 80
```

### Step 6: Apply Manifests

```bash
# Create PVC
kubectl apply -f postgres-pvc.yaml

# Deploy PostgreSQL
kubectl apply -f postgres-deployment.yaml

# Wait for PostgreSQL to be ready
kubectl wait --for=condition=ready pod -l app=postgres -n django-app --timeout=300s

# Deploy Django application
kubectl apply -f django-deployment.yaml

# Create Ingress
kubectl apply -f ingress.yaml

# Verify deployment
kubectl get pods -n django-app
kubectl get svc -n django-app
kubectl get ingress -n django-app
```

---

## Managing Secrets

### Create Database Secret

```bash
# Create secret from literal values
kubectl create secret generic db-secret \
  --from-literal=username=django_user \
  --from-literal=password=$(openssl rand -base64 32) \
  --from-literal=database-url="postgresql://django_user:PASSWORD@postgres:5432/django_db" \
  -n django-app

# Verify secret
kubectl get secrets -n django-app
kubectl describe secret db-secret -n django-app
```

### Create Django Secret

```bash
# Generate Django SECRET_KEY
DJANGO_SECRET_KEY=$(python -c 'from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())')

# Create secret
kubectl create secret generic django-secret \
  --from-literal=secret-key="$DJANGO_SECRET_KEY" \
  -n django-app
```

### Create Redis Secret

```bash
kubectl create secret generic redis-secret \
  --from-literal=redis-url="redis://redis:6379/0" \
  -n django-app
```

### Create Configuration Map

```yaml
# django-configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: django-config
  namespace: django-app
data:
  allowed-hosts: "yourdomain.com,www.yourdomain.com,localhost"
  log-level: "INFO"
  static-root: "/app/staticfiles"
```

```bash
kubectl apply -f django-configmap.yaml
```

### Update Secrets

```bash
# Delete and recreate secret
kubectl delete secret db-secret -n django-app
kubectl create secret generic db-secret \
  --from-literal=username=django_user \
  --from-literal=password=new_password \
  --from-literal=database-url="postgresql://django_user:new_password@postgres:5432/django_db" \
  -n django-app

# Rolling restart to apply new secrets
kubectl rollout restart deployment/django-app -n django-app
```

---

## Scaling

### Manual Scaling

```bash
# Scale to 5 replicas
kubectl scale deployment django-app --replicas=5 -n django-app

# Check scaling status
kubectl get deployment django-app -n django-app
kubectl get pods -n django-app
```

### Horizontal Pod Autoscaler (HPA)

```yaml
# hpa.yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: django-hpa
  namespace: django-app
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: django-app
  minReplicas: 3
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
  behavior:
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
      - type: Percent
        value: 50
        periodSeconds: 15
    scaleUp:
      stabilizationWindowSeconds: 0
      policies:
      - type: Percent
        value: 100
        periodSeconds: 15
      - type: Pods
        value: 2
        periodSeconds: 15
      selectPolicy: Max
```

```bash
# Deploy HPA
kubectl apply -f hpa.yaml

# Monitor HPA
kubectl get hpa -n django-app
kubectl describe hpa django-hpa -n django-app

# Watch scaling in real-time
kubectl get hpa django-hpa -n django-app --watch
```

### Vertical Pod Autoscaler (VPA)

```yaml
# vpa.yaml
apiVersion: autoscaling.k8s.io/v1
kind: VerticalPodAutoscaler
metadata:
  name: django-vpa
  namespace: django-app
spec:
  targetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: django-app
  updatePolicy:
    updateMode: "Auto"
```

---

## Database Migrations

### Run Migrations with Job

```yaml
# migration-job.yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: django-migrate
  namespace: django-app
spec:
  backoffLimit: 3
  template:
    spec:
      serviceAccountName: django-app
      containers:
      - name: django-migrate
        image: your-registry/django-app:latest
        command: ["python", "manage.py", "migrate"]
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: db-secret
              key: database-url
        - name: SECRET_KEY
          valueFrom:
            secretKeyRef:
              name: django-secret
              key: secret-key
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
      restartPolicy: Never
```

### Run Migration Commands

```bash
# Create and run migration job
kubectl apply -f migration-job.yaml

# Check job status
kubectl get job -n django-app
kubectl logs -n django-app -l job-name=django-migrate

# Wait for job completion
kubectl wait --for=condition=complete job/django-migrate -n django-app --timeout=300s

# Run additional management commands
kubectl run django-manage --rm -i --tty --image=your-registry/django-app:latest \
  --env="DATABASE_URL=postgresql://django_user:password@postgres:5432/django_db" \
  --env="SECRET_KEY=$(kubectl get secret django-secret -o jsonpath='{.data.secret-key}' -n django-app | base64 -d)" \
  -- python manage.py shell
```

### Pre-deployment Migration Hook

Add to your deployment specification:
```yaml
lifecycle:
  postStart:
    exec:
      command: ["/bin/sh", "-c", "python manage.py migrate --no-input && python manage.py collectstatic --no-input"]
```

---

## Monitoring and Logging

### Enable Metrics Server

```bash
# Install metrics-server for HPA
kubectl apply -f https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml

# Verify installation
kubectl get deployment metrics-server -n kube-system
```

### View Logs

```bash
# View logs from a single pod
kubectl logs -n django-app <pod-name>

# View logs from all pods of a deployment
kubectl logs -n django-app -l app=django-app --all-containers=true

# Stream logs in real-time
kubectl logs -n django-app -f -l app=django-app

# View logs from previous pod instance
kubectl logs -n django-app <pod-name> --previous

# Get logs from a specific container in a pod with multiple containers
kubectl logs -n django-app <pod-name> -c django
```

### Monitor Resource Usage

```bash
# Check current resource usage
kubectl top nodes
kubectl top pods -n django-app

# Get detailed metrics
kubectl describe node <node-name>
kubectl describe pod <pod-name> -n django-app
```

### Install Prometheus & Grafana (Optional)

```bash
# Add Prometheus Helm repository
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo update

# Install Prometheus
helm install prometheus prometheus-community/kube-prometheus-stack \
  --namespace monitoring --create-namespace

# Install Grafana
helm install grafana grafana/grafana \
  --namespace monitoring --create-namespace

# Access Grafana (port-forward)
kubectl port-forward -n monitoring svc/grafana 3000:80
```

### Configure Alerting

```yaml
# alerting-rules.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: prometheus-rules
  namespace: monitoring
data:
  alert-rules.yaml: |
    groups:
    - name: django-app
      interval: 30s
      rules:
      - alert: HighPodCPUUsage
        expr: sum(rate(container_cpu_usage_seconds_total{pod=~"django-app-.*"}[5m])) > 0.8
        for: 5m
        annotations:
          summary: "High CPU usage detected in Django pods"
      
      - alert: PodMemoryUsageHigh
        expr: sum(container_memory_usage_bytes{pod=~"django-app-.*"}) > 500000000
        for: 5m
        annotations:
          summary: "High memory usage detected in Django pods"
      
      - alert: PodRestartingTooOften
        expr: rate(kube_pod_container_status_restarts_total{pod=~"django-app-.*"}[1h]) > 0
        for: 5m
        annotations:
          summary: "Pod is restarting too frequently"
```

---

## Rolling Updates

### Perform Rolling Update

```bash
# Update image
kubectl set image deployment/django-app \
  django=your-registry/django-app:v2.0 \
  -n django-app --record

# Check rollout status
kubectl rollout status deployment/django-app -n django-app

# View rollout history
kubectl rollout history deployment/django-app -n django-app

# Show details of specific revision
kubectl rollout history deployment/django-app --revision=2 -n django-app
```

### Rollback to Previous Version

```bash
# Rollback to previous revision
kubectl rollout undo deployment/django-app -n django-app

# Rollback to specific revision
kubectl rollout undo deployment/django-app --to-revision=1 -n django-app

# Check rollback status
kubectl rollout status deployment/django-app -n django-app
```

### Configure Deployment Update Strategy

```yaml
spec:
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1          # One extra pod during update
      maxUnavailable: 0    # Zero unavailable pods during update
  minReadySeconds: 30      # Wait 30 seconds before marking pod ready
```

### Blue-Green Deployment (Alternative)

```bash
# Deploy new version (green) alongside old version (blue)
kubectl apply -f django-deployment-v2.yaml

# Switch traffic to new version
kubectl patch service django-app -n django-app \
  --type merge -p '{"spec":{"selector":{"version":"v2"}}}'

# Monitor for issues, rollback if needed
kubectl patch service django-app -n django-app \
  --type merge -p '{"spec":{"selector":{"version":"v1"}}}'
```

---

## Troubleshooting

### Pod Status and Events

```bash
# Check pod status
kubectl get pods -n django-app -o wide
kubectl describe pod <pod-name> -n django-app

# View pod events
kubectl get events -n django-app --sort-by='.lastTimestamp'

# Get detailed pod information
kubectl get pod <pod-name> -n django-app -o yaml
```

### Common Issues and Solutions

#### 1. Pod Stuck in Pending State

```bash
# Check for resource constraints
kubectl describe node
kubectl top nodes

# Check for PVC issues
kubectl get pvc -n django-app
kubectl describe pvc postgres-pvc -n django-app

# Debug pending pod
kubectl describe pod <pod-name> -n django-app
```

#### 2. CrashLoopBackOff Error

```bash
# Check logs for errors
kubectl logs <pod-name> -n django-app --previous

# Check resource limits
kubectl describe pod <pod-name> -n django-app | grep -A 5 "Limits\|Requests"

# Increase resource limits in deployment
kubectl set resources deployment django-app \
  -c django \
  --limits=cpu=1000m,memory=1Gi \
  -n django-app
```

#### 3. Image Pull Errors

```bash
# Check image registry credentials
kubectl get secrets -n django-app
kubectl describe secret <secret-name> -n django-app

# Create image pull secret
kubectl create secret docker-registry registry-credentials \
  --docker-server=your-registry \
  --docker-username=username \
  --docker-password=password \
  -n django-app

# Use in deployment
imagePullSecrets:
- name: registry-credentials
```

#### 4. Database Connection Issues

```bash
# Check database connectivity
kubectl run -it --rm debug --image=postgres:15 --restart=Never -n django-app -- \
  psql -h postgres -U django_user -d django_db -c "SELECT 1"

# Verify database credentials
kubectl get secret db-secret -n django-app -o yaml

# Check database pod logs
kubectl logs -n django-app postgres-0
```

#### 5. Insufficient Resources

```bash
# Check cluster capacity
kubectl describe nodes

# Check pod resource requests
kubectl describe pod <pod-name> -n django-app | grep -A 10 "Requests\|Limits"

# Add more nodes or increase cluster size
# (This depends on your cloud provider)
```

### Debugging Commands

```bash
# Execute command in running pod
kubectl exec -it <pod-name> -n django-app -- /bin/bash

# Copy files from pod
kubectl cp django-app/<pod-name>:/app/logs ./logs

# Port-forward to access service directly
kubectl port-forward -n django-app svc/django-app 8000:80

# Check environment variables in pod
kubectl exec <pod-name> -n django-app -- env

# Check disk usage
kubectl exec <pod-name> -n django-app -- df -h

# Monitor in real-time
watch kubectl get pods -n django-app
watch kubectl top pods -n django-app
```

### Health Checks

```bash
# Check liveness probe
kubectl describe pod <pod-name> -n django-app | grep -A 10 "Liveness"

# Check readiness probe
kubectl describe pod <pod-name> -n django-app | grep -A 10 "Readiness"

# Manually test health endpoint
kubectl port-forward -n django-app svc/django-app 8000:80
curl http://localhost:8000/health/
```

### Network Debugging

```bash
# Check DNS resolution in cluster
kubectl run -it --rm debug --image=busybox --restart=Never -n django-app -- \
  nslookup postgres

# Test connectivity between pods
kubectl run -it --rm debug --image=busybox --restart=Never -n django-app -- \
  wget -O- http://django-app/

# Check network policies
kubectl get networkpolicies -n django-app

# Verify service endpoints
kubectl get endpoints -n django-app
kubectl describe svc django-app -n django-app
```

---

## Best Practices

### Security
- Always use private Docker registries for production
- Store secrets in Kubernetes Secrets, not in ConfigMaps
- Use Network Policies to restrict traffic between pods
- Implement RBAC for service accounts
- Run containers as non-root users
- Use read-only root filesystems where possible

### Performance
- Set appropriate resource requests and limits
- Use Horizontal Pod Autoscaler (HPA) for load-based scaling
- Implement caching with Redis
- Use database connection pooling
- Monitor resource usage continuously

### Reliability
- Configure liveness and readiness probes
- Implement health check endpoints in Django
- Use multiple replicas for high availability
- Implement automated backups for databases
- Use StatefulSets for stateful components like databases

### Operations
- Keep container images small and up-to-date
- Use meaningful labels and annotations
- Implement proper logging and monitoring
- Document all deployment procedures
- Use infrastructure-as-code for all configurations

---

## Additional Resources

- [Kubernetes Documentation](https://kubernetes.io/docs/)
- [Django Deployment Guide](https://docs.djangoproject.com/en/stable/howto/deployment/)
- [PostgreSQL Kubernetes Operator](https://github.com/zalando/postgres-operator)
- [Helm Charts Repository](https://artifacthub.io/)
- [Kubernetes Best Practices](https://kubernetes.io/docs/concepts/configuration/overview/)

---

## Support and Maintenance

For issues or questions:
1. Check Kubernetes events: `kubectl get events -n django-app`
2. Review pod logs: `kubectl logs -n django-app <pod-name>`
3. Consult Kubernetes documentation
4. Contact your Kubernetes cluster administrator

---

**Last Updated**: 2025-12-15
**Maintained By**: Sandeepja118
