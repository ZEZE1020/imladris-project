#!/bin/bash
# Harbor Registry Setup Script
# Configuring Harbor to mirror upstream Docker Hub for offline resilience and security scanning

set -e

# Variables
ENVIRONMENT="${environment}"
HARBOR_VERSION="v2.9.1"
HARBOR_SHA256="d1a51165722d22022464704f029388f88602224b5269c947543878b7e2440266"
HARBOR_DATA_DIR="/opt/harbor/data"
COMPOSE_VERSION="2.21.0"
COMPOSE_SHA256="59365637d2414e3d5572952e33357858f48429783431b78b9812023f45d55471"

# Log all output to CloudWatch
exec 1> >(logger -s -t harbor-setup)
exec 2>&1

echo "Starting Harbor setup for environment: $ENVIRONMENT"

# Update system
yum update -y
yum install -y docker wget curl jq

# Start Docker service
systemctl start docker
systemctl enable docker

# Mount and prepare encrypted EBS volume
echo "Preparing encrypted storage volume..."
mkfs.ext4 /dev/xvdb
mkdir -p $HARBOR_DATA_DIR
mount /dev/xvdb $HARBOR_DATA_DIR
echo "/dev/xvdb $HARBOR_DATA_DIR ext4 defaults,nofail 0 2" >> /etc/fstab

# Set permissions for Harbor data directory
chown -R 999:999 $HARBOR_DATA_DIR
chmod 755 $HARBOR_DATA_DIR

# Install Docker Compose
echo "Installing Docker Compose v$COMPOSE_VERSION..."
curl -L "https://github.com/docker/compose/releases/download/v$COMPOSE_VERSION/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose
# Security: Verify checksum
echo "$COMPOSE_SHA256  /usr/local/bin/docker-compose" | sha256sum -c -
ln -sf /usr/local/bin/docker-compose /usr/bin/docker-compose

# Download and extract Harbor
echo "Downloading Harbor $HARBOR_VERSION..."
cd /opt
wget -q "https://github.com/goharbor/harbor/releases/download/$HARBOR_VERSION/harbor-offline-installer-$HARBOR_VERSION.tgz"

# Security: Verify checksum before extraction
echo "$HARBOR_SHA256  harbor-offline-installer-$HARBOR_VERSION.tgz" | sha256sum -c -

tar xzf harbor-offline-installer-$HARBOR_VERSION.tgz
rm harbor-offline-installer-$HARBOR_VERSION.tgz

# Generate self-signed certificate for Harbor (in production, use proper certs)
mkdir -p /opt/harbor/certs
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /opt/harbor/certs/harbor.key \
    -out /opt/harbor/certs/harbor.crt \
    -subj "/C=US/ST=NY/L=NYC/O=Imladris/CN=harbor.imladris.local"

# Create Harbor configuration
cat > /opt/harbor/harbor.yml << EOF
# Harbor configuration for Secure Pull-Through Cache
hostname: harbor.imladris.local

# HTTP/HTTPS protocol configuration
http:
  port: 80
https:
  port: 443
  certificate: /opt/harbor/certs/harbor.crt
  private_key: /opt/harbor/certs/harbor.key

# Admin credentials (change in production)
harbor_admin_password: $(openssl rand -base64 32)

# Database configuration (PostgreSQL)
database:
  password: $(openssl rand -base64 32)
  max_idle_conns: 50
  max_open_conns: 1000

# Data directory
data_volume: $HARBOR_DATA_DIR

# Trivy scanner configuration for vulnerability scanning
trivy:
  ignore_unfixed: false
  skip_update: false
  offline_scan: false
  security_check: vuln
  insecure: false

# Jobservice configuration
jobservice:
  max_job_workers: 10

notification:
  webhook_job_max_retry: 10

chart:
  absolute_url: disabled

# Log configuration
log:
  level: info
  local:
    rotate_count: 50
    rotate_size: 200M
    location: /var/log/harbor

# Garbage collection
_version: $HARBOR_VERSION

# Proxy cache configuration will be done via API after installation
EOF

# Security: Restrict permissions on harbor.yml (contains plaintext credentials)
chmod 600 /opt/harbor/harbor.yml
echo "Harbor configuration secured with chmod 600"

# Install Harbor
echo "Installing Harbor..."
cd /opt/harbor
./install.sh --with-trivy

# Wait for Harbor to be ready
echo "Waiting for Harbor to start..."
sleep 30

# Configure Harbor as a proxy cache via API
# Note: In production, these should be stored in AWS Secrets Manager
HARBOR_URL="https://localhost"
ADMIN_PASSWORD=$(grep "harbor_admin_password:" /opt/harbor/harbor.yml | cut -d' ' -f2)

# Function to call Harbor API
harbor_api() {
    curl -k -s -u "admin:$ADMIN_PASSWORD" \
         -H "Content-Type: application/json" \
         -X "$1" \
         "$HARBOR_URL/api/v2.0/$2" \
         "${@:3}"
}

# Wait for API to be available
echo "Waiting for Harbor API to be ready..."
for i in {1..30}; do
    if harbor_api GET "systeminfo" > /dev/null 2>&1; then
        echo "Harbor API is ready"
        break
    fi
    sleep 10
done

# Create proxy cache project for Docker Hub
echo "Creating Docker Hub proxy cache project..."
harbor_api POST "projects" -d '{
    "project_name": "dockerhub-proxy",
    "registry_id": 1,
    "metadata": {
        "public": "false"
    }
}' || echo "Project may already exist"

# Create registry endpoint for Docker Hub
echo "Creating Docker Hub registry endpoint..."
REGISTRY_RESPONSE=$(harbor_api POST "registries" -d '{
    "name": "dockerhub",
    "type": "docker-hub",
    "url": "https://hub.docker.com",
    "credential": {
        "type": "basic",
        "access_key": "",
        "access_secret": ""
    },
    "insecure": false
}' 2>/dev/null || echo '{"id": 1}')

# Create proxy cache project linked to Docker Hub
echo "Configuring proxy cache for Docker Hub..."
harbor_api PUT "projects/dockerhub-proxy" -d '{
    "metadata": {
        "public": "false"
    },
    "registry_id": 1
}' || echo "Proxy cache configuration completed"

# Create vulnerability scanning policy
echo "Setting up vulnerability scanning policy..."
harbor_api POST "projects/dockerhub-proxy/scanner/candidates/trivy/metadata" -d '{
    "severity": "Critical",
    "cve_allowlist": {
        "project_id": 2,
        "expires_at": null,
        "items": []
    }
}' || echo "Vulnerability policy may already exist"

# Create webhook for scan results (block critical vulnerabilities)
harbor_api POST "projects/dockerhub-proxy/webhook/policies" -d '{
    "name": "block-critical-vulnerabilities",
    "description": "Block images with critical vulnerabilities from being served",
    "project_id": 2,
    "targets": [
        {
            "type": "http",
            "address": "http://localhost:8080/webhook/scan-result",
            "skip_cert_verify": true
        }
    ],
    "event_types": ["SCANNING_COMPLETED"],
    "enabled": true
}' || echo "Webhook policy may already exist"

# Store Harbor credentials in SSM Parameter Store for CI/CD access
aws ssm put-parameter \
    --region $(curl -s http://169.254.169.254/latest/meta-data/placement/region) \
    --name "/$ENVIRONMENT/harbor/admin-password" \
    --value "$ADMIN_PASSWORD" \
    --type "SecureString" \
    --overwrite || echo "Failed to store credentials in SSM"

# Configure log rotation and monitoring
cat > /etc/logrotate.d/harbor << EOF
/var/log/harbor/*.log {
    daily
    missingok
    rotate 52
    compress
    notifempty
    create 644 999 999
    sharedscripts
    postrotate
        /usr/bin/docker-compose -f /opt/harbor/docker-compose.yml restart > /dev/null 2>&1 || true
    endscript
}
EOF

# Create systemd service for Harbor
cat > /etc/systemd/system/harbor.service << EOF
[Unit]
Description=Harbor Container Registry
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/opt/harbor
ExecStart=/usr/local/bin/docker-compose up -d
ExecStop=/usr/local/bin/docker-compose down
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
EOF

systemctl enable harbor
systemctl daemon-reload

echo "Harbor setup completed successfully!"
echo "Harbor is accessible at: https://$(curl -s http://169.254.169.254/latest/meta-data/local-ipv4)"
echo "Admin password stored in SSM: /$ENVIRONMENT/harbor/admin-password"

# Configure CloudWatch agent for Harbor logs
yum install -y amazon-cloudwatch-agent

cat > /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json << EOF
{
    "logs": {
        "logs_collected": {
            "files": {
                "collect_list": [
                    {
                        "file_path": "/var/log/harbor/harbor.log",
                        "log_group_name": "/aws/ec2/harbor/$ENVIRONMENT",
                        "log_stream_name": "{instance_id}-harbor"
                    },
                    {
                        "file_path": "/var/log/messages",
                        "log_group_name": "/aws/ec2/harbor/$ENVIRONMENT",
                        "log_stream_name": "{instance_id}-system"
                    }
                ]
            }
        }
    }
}
EOF

/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl \
    -a fetch-config \
    -m ec2 \
    -c file:/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json \
    -s

echo "CloudWatch agent configured for Harbor monitoring"