#!/bin/bash
# User data script for EKS nodes with eBPF and BTF optimizations

set -o xtrace

# Bootstrap the EKS node
/etc/eks/bootstrap.sh ${cluster_name} ${bootstrap_arguments}

# Enable BTF (BPF Type Format) if not already available
if [ ! -f /sys/kernel/btf/vmlinux ]; then
    echo "Enabling BTF support..."
    # Install kernel headers and BTF data
    yum update -y
    yum install -y kernel-devel-$(uname -r) kernel-headers-$(uname -r)

    # Create BTF symlink if available in debugfs
    if [ -f /sys/kernel/debug/kernel/btf ]; then
        mkdir -p /sys/kernel/btf
        ln -sf /sys/kernel/debug/kernel/btf /sys/kernel/btf/vmlinux
    fi
fi

# Configure kernel parameters for eBPF optimization
cat >> /etc/sysctl.d/99-ebpf-optimization.conf << EOF
# eBPF and network optimization
net.core.bpf_jit_enable=1
net.core.bpf_jit_harden=0
net.core.bpf_jit_kallsyms=1

# Increase BPF memory limits
kernel.bpf_stats_enabled=1
vm.max_map_count=262144

# Network buffer optimization for high-throughput monitoring
net.core.rmem_default=262144
net.core.rmem_max=16777216
net.core.wmem_default=262144
net.core.wmem_max=16777216
net.core.netdev_max_backlog=5000

# File descriptor limits for intensive monitoring
fs.file-max=2097152
fs.nr_open=1048576
EOF

# Apply sysctl changes
sysctl -p /etc/sysctl.d/99-ebpf-optimization.conf

# Configure ulimits for eBPF programs
cat >> /etc/security/limits.d/99-ebpf.conf << EOF
# Increase limits for eBPF programs and monitoring
*    soft nofile 1048576
*    hard nofile 1048576
*    soft memlock unlimited
*    hard memlock unlimited
EOF

# Install additional tools for debugging and monitoring
yum install -y \
    perf \
    bpftrace \
    strace \
    tcpdump \
    iotop \
    htop

# Create log directory for Tetragon
mkdir -p /var/log/tetragon
chmod 755 /var/log/tetragon

# Configure log rotation for Tetragon logs
cat > /etc/logrotate.d/tetragon << EOF
/var/log/tetragon/*.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    copytruncate
    maxage 7
}
EOF

# Ensure systemd services are optimized
systemctl daemon-reload

# Configure container runtime for security
mkdir -p /etc/containerd/
cat > /etc/containerd/config.toml << EOF
version = 2

[plugins]
  [plugins."io.containerd.grpc.v1.cri"]
    [plugins."io.containerd.grpc.v1.cri".containerd]
      [plugins."io.containerd.grpc.v1.cri".containerd.runtimes]
        [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc]
          runtime_type = "io.containerd.runc.v2"
          [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc.options]
            SystemdCgroup = true
            # Enable seccomp filtering
            SeccompDefault = true
EOF

# Restart containerd with new configuration
systemctl restart containerd

# Set up CloudWatch agent for log forwarding (if needed)
yum install -y amazon-cloudwatch-agent

# Create a marker file to indicate successful setup
touch /var/lib/cloud/scripts/setup-complete

echo "eBPF-optimized EKS node setup completed successfully"