# Real-Time Infrastructure Drift & Runtime Enforcement Lambda
# Processes Tetragon events and automatically isolates compromised pods

import json
import os
import boto3
import base64
import gzip
import logging
from typing import Dict, List, Any
from datetime import datetime
import ipaddress
from kubernetes import client, config
from tetragon_event_schema import (
    TetragonEvent,
    EXAMPLE_PROCESS_EXEC_EVENT, EXAMPLE_FILE_ACCESS_EVENT, EXAMPLE_NETWORK_EVENT
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# AWS clients
cloudwatch = boto3.client('logs')
sns = boto3.client('sns')
secretsmanager = boto3.client('secretsmanager')

# Environment variables
CLUSTER_NAME = os.environ.get('CLUSTER_NAME', 'security-drift-engine')
MONITORED_VPC_CIDRS = os.environ.get('MONITORED_VPC_CIDRS', '10.100.0.0/16,172.31.100.0/24').split(',')
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN')
QUARANTINE_NAMESPACE = os.environ.get('QUARANTINE_NAMESPACE', 'security-quarantine')
EKS_ENDPOINT = os.environ.get('EKS_ENDPOINT')
EKS_CA_SECRET_ARN = os.environ.get('EKS_CA_SECRET_ARN')

class PodQuarantineManager:
    """Manages pod isolation and quarantine operations"""

    def __init__(self):
        self.k8s_core_v1 = None
        self.k8s_networking_v1 = None
        self._init_kubernetes_clients()

    def _init_kubernetes_clients(self):
        """Initialize Kubernetes API clients"""
        try:
            # Load kubeconfig from environment or use in-cluster config
            if EKS_ENDPOINT and EKS_CA_SECRET_ARN:
                # Retrieve EKS CA data from Secrets Manager
                eks_ca_data = self._get_eks_ca_from_secrets_manager()

                # Configure from environment (Lambda environment)
                configuration = client.Configuration()
                configuration.host = EKS_ENDPOINT
                configuration.ssl_ca_cert = self._write_ca_cert(eks_ca_data)
                configuration.api_key_prefix['authorization'] = 'Bearer'

                # Get AWS EKS token
                session = boto3.Session()
                credentials = session.get_credentials()
                token = self._get_eks_token(CLUSTER_NAME, credentials)
                configuration.api_key['authorization'] = token

                self.k8s_core_v1 = client.CoreV1Api(client.ApiClient(configuration))
                self.k8s_networking_v1 = client.NetworkingV1Api(client.ApiClient(configuration))
            else:
                # Use in-cluster config (if running in pod)
                config.load_incluster_config()
                self.k8s_core_v1 = client.CoreV1Api()
                self.k8s_networking_v1 = client.NetworkingV1Api()

            logger.info("Kubernetes clients initialized successfully")

        except Exception as e:
            logger.error(f"Failed to initialize Kubernetes clients: {e}")
            raise

    def _get_eks_ca_from_secrets_manager(self) -> str:
        """Retrieve EKS CA certificate data from AWS Secrets Manager"""
        try:
            response = secretsmanager.get_secret_value(SecretId=EKS_CA_SECRET_ARN)
            secret_data = json.loads(response['SecretString'])
            return secret_data['ca_data']
        except Exception as e:
            logger.error(f"Failed to retrieve EKS CA from Secrets Manager: {e}")
            raise

    def _write_ca_cert(self, eks_ca_data: str) -> str:
        """Write CA certificate to temporary file"""
        ca_cert_path = '/tmp/ca.crt'
        with open(ca_cert_path, 'w') as f:
            f.write(base64.b64decode(eks_ca_data).decode('utf-8'))
        return ca_cert_path

    def _get_eks_token(self, cluster_name: str, credentials) -> str:
        """Generate EKS authentication token"""
        import botocore.auth
        import botocore.awsrequest
        import urllib.parse
        from datetime import datetime, timezone

        # Create STS request for GetCallerIdentity
        sts_client = boto3.client('sts')

        # Generate presigned URL for authentication
        url = sts_client.generate_presigned_url(
            'get_caller_identity',
            Params={'ClusterName': cluster_name},
            ExpiresIn=60,
            HttpMethod='GET'
        )

        # Extract token from URL
        token = base64.b64encode(url.encode()).decode().rstrip('=')
        return f"k8s-aws-v1.{token}"

    def quarantine_pod(self, event: TetragonEvent, is_monitored_region: bool = False) -> bool:
        """Quarantine a compromised pod by applying network policies"""
        try:
            if not event.kubernetes:
                logger.warning(f"No Kubernetes metadata in event {event.process_exec_id}")
                return False

            namespace = event.kubernetes.namespace
            pod_name = event.kubernetes.pod_name

            logger.info(f"Quarantining pod {pod_name} in namespace {namespace}")

            # Create quarantine NetworkPolicy
            quarantine_policy = self._create_quarantine_network_policy(
                namespace, pod_name, is_monitored_region
            )

            # Apply the NetworkPolicy
            try:
                self.k8s_networking_v1.create_namespaced_network_policy(
                    namespace=namespace,
                    body=quarantine_policy
                )
                logger.info(f"Applied quarantine NetworkPolicy for pod {pod_name}")
            except client.rest.ApiException as e:
                if e.status == 409:  # Already exists
                    logger.info(f"Quarantine NetworkPolicy already exists for pod {pod_name}")
                else:
                    raise

            # Label pod for quarantine tracking
            self._label_pod_for_quarantine(namespace, pod_name, event)

            # Create incident record
            self._create_incident_record(event, is_monitored_region)

            return True

        except Exception as e:
            logger.error(f"Failed to quarantine pod: {e}")
            return False

    def _create_quarantine_network_policy(self, namespace: str, pod_name: str,
                                        is_monitored_region: bool) -> Dict[str, Any]:
        """Create NetworkPolicy for pod quarantine"""

        # Base quarantine policy - deny all traffic
        base_policy = {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {
                "name": f"quarantine-{pod_name}",
                "namespace": namespace,
                "labels": {
                    "security.tetragon.io/quarantine": "true",
                    "security.tetragon.io/pod": pod_name,
                    "security.tetragon.io/timestamp": datetime.utcnow().isoformat()
                },
                "annotations": {
                    "security.tetragon.io/reason": "Runtime drift detected by Tetragon",
                    "security.tetragon.io/regional-enforcement": str(is_monitored_region)
                }
            },
            "spec": {
                "podSelector": {
                    "matchLabels": {
                        "security.tetragon.io/quarantined": "true"
                    }
                },
                "policyTypes": ["Ingress", "Egress"]
            }
        }

        if is_monitored_region:
            # Stricter policy for monitored region - no traffic allowed at all
            base_policy["spec"]["ingress"] = []
            base_policy["spec"]["egress"] = []
            base_policy["metadata"]["labels"]["security.tetragon.io/region"] = "monitored"
        else:
            # Standard quarantine - allow only DNS and metadata service
            base_policy["spec"]["egress"] = [
                {
                    "to": [],
                    "ports": [{"protocol": "UDP", "port": 53}],  # DNS
                },
                {
                    "to": [{"ipBlock": {"cidr": "169.254.169.254/32"}}]  # AWS metadata
                }
            ]

        return base_policy

    def _label_pod_for_quarantine(self, namespace: str, pod_name: str, event: TetragonEvent):
        """Add quarantine labels to pod"""
        try:
            # Get current pod
            pod = self.k8s_core_v1.read_namespaced_pod(name=pod_name, namespace=namespace)

            # Add quarantine labels
            if not pod.metadata.labels:
                pod.metadata.labels = {}

            pod.metadata.labels.update({
                "security.tetragon.io/quarantined": "true",
                "security.tetragon.io/quarantine-reason": "runtime-drift",
                "security.tetragon.io/quarantine-timestamp": datetime.utcnow().isoformat(),
                "security.tetragon.io/event-type": event.event_type.name,
                "security.tetragon.io/policy": event.policy_name,
                "security.tetragon.io/severity": event.severity
            })

            # Patch the pod
            self.k8s_core_v1.patch_namespaced_pod(
                name=pod_name,
                namespace=namespace,
                body=pod
            )

            logger.info(f"Added quarantine labels to pod {pod_name}")

        except Exception as e:
            logger.error(f"Failed to label pod {pod_name}: {e}")

    def _create_incident_record(self, event: TetragonEvent, is_monitored_region: bool):
        """Create incident record in CloudWatch"""
        incident_data = {
            "incident_id": f"drift-{event.process_exec_id}",
            "timestamp": event.time.isoformat(),
            "event_type": event.event_type.name,
            "severity": event.severity,
            "node_name": event.node_name,
            "action_taken": "pod_quarantine",
            "regional_enforcement": is_monitored_region,
            "policy_name": event.policy_name,
            "kubernetes": {
                "namespace": event.kubernetes.namespace if event.kubernetes else None,
                "pod_name": event.kubernetes.pod_name if event.kubernetes else None,
                "workload": event.kubernetes.workload_name if event.kubernetes else None
            },
            "process": {
                "binary": event.process.binary,
                "arguments": event.process.arguments,
                "pid": event.process.pid
            }
        }

        if event.file:
            incident_data["file_path"] = event.file.path

        if event.network:
            incident_data["network"] = {
                "src_ip": event.network.src_ip,
                "dst_ip": event.network.dst_ip,
                "dst_port": event.network.dst_port,
                "protocol": event.network.protocol
            }

        # Send to CloudWatch
        try:
            cloudwatch.put_log_events(
                logGroupName='/aws/security/drift-engine/incidents',
                logStreamName=f'incidents-{datetime.utcnow().strftime("%Y-%m-%d")}',
                logEvents=[{
                    'timestamp': int(event.time.timestamp() * 1000),
                    'message': json.dumps(incident_data)
                }]
            )
        except Exception as e:
            logger.error(f"Failed to log incident: {e}")

class EventProcessor:
    """Processes Tetragon events and triggers appropriate responses"""

    def __init__(self):
        self.quarantine_manager = PodQuarantineManager()

    def process_event(self, event: TetragonEvent) -> Dict[str, Any]:
        """Process a single Tetragon event"""
        result = {
            "event_id": event.process_exec_id,
            "timestamp": event.time.isoformat(),
            "event_type": event.event_type.name,
            "severity": event.severity,
            "processed": True,
            "actions_taken": []
        }

        try:
            # Check if this is a high-severity event requiring immediate action
            if event.is_high_severity():
                logger.info(f"Processing high-severity event: {event.process_exec_id}")
                result["high_severity"] = True

                # Check regional context
                is_monitored = False
                if event.node_info:
                    is_monitored = event.node_info.is_monitored_region(MONITORED_VPC_CIDRS)
                    result["monitored_region"] = is_monitored

                # Process based on event type
                if event.is_process_exec_event():
                    actions = self._handle_process_exec_event(event, is_monitored)
                    result["actions_taken"].extend(actions)

                elif event.is_file_access_event():
                    actions = self._handle_file_access_event(event, is_monitored)
                    result["actions_taken"].extend(actions)

                elif event.is_network_event():
                    actions = self._handle_network_event(event, is_monitored)
                    result["actions_taken"].extend(actions)

                # Send alert for high-severity events
                if SNS_TOPIC_ARN:
                    self._send_alert(event, is_monitored)
                    result["actions_taken"].append("alert_sent")

            else:
                # Low/medium severity - just log for monitoring
                result["high_severity"] = False
                self._log_event(event)
                result["actions_taken"].append("logged")

            return result

        except Exception as e:
            logger.error(f"Error processing event {event.process_exec_id}: {e}")
            result["error"] = str(e)
            result["processed"] = False
            return result

    def _handle_process_exec_event(self, event: TetragonEvent, is_monitored: bool) -> List[str]:
        """Handle process execution drift events"""
        actions = []

        # Check for blacklisted processes
        blacklisted_processes = [
            'bash', 'sh', 'curl', 'wget', 'netcat', 'nc', 'nmap',
            'apt', 'yum', 'pip', 'npm', 'ssh', 'strace', 'gdb'
        ]

        process_name = os.path.basename(event.process.binary)
        if any(blocked in process_name.lower() for blocked in blacklisted_processes):
            logger.warning(f"Blacklisted process detected: {process_name}")

            # Quarantine the pod
            if event.kubernetes and self.quarantine_manager.quarantine_pod(event, is_monitored):
                actions.append("pod_quarantined")
                logger.info(f"Pod quarantined for process: {process_name}")

        # Check for suspicious arguments
        if self._has_suspicious_arguments(event.process.arguments):
            logger.warning(f"Suspicious process arguments: {event.process.arguments}")
            actions.append("suspicious_args_detected")

            if event.kubernetes:
                self.quarantine_manager.quarantine_pod(event, is_monitored)
                actions.append("pod_quarantined")

        return actions

    def _handle_file_access_event(self, event: TetragonEvent, is_monitored: bool) -> List[str]:
        """Handle file integrity monitoring events"""
        actions = []

        if not event.file:
            return actions

        # Check for critical file modifications
        critical_paths = [
            '/etc/passwd', '/etc/shadow', '/etc/sudoers', '/etc/ssh/',
            '/bin/', '/sbin/', '/usr/bin/', '/usr/sbin/',
            '/var/lib/kubelet/', '/etc/kubernetes/'
        ]

        if any(event.file.path.startswith(path) for path in critical_paths):
            logger.warning(f"Critical file access detected: {event.file.path}")
            actions.append("critical_file_access")

            # Immediate quarantine for critical file modifications
            if event.kubernetes and self.quarantine_manager.quarantine_pod(event, is_monitored):
                actions.append("pod_quarantined")

        return actions

    def _handle_network_event(self, event: TetragonEvent, is_monitored: bool) -> List[str]:
        """Handle network drift events"""
        actions = []

        if not event.network:
            return actions

        # Check for suspicious network activity
        suspicious_ports = [4444, 5555, 31337, 6666, 12345, 54321]

        if event.network.dst_port in suspicious_ports:
            logger.warning(f"Suspicious network connection to port {event.network.dst_port}")
            actions.append("suspicious_network_connection")

            if event.kubernetes and self.quarantine_manager.quarantine_pod(event, is_monitored):
                actions.append("pod_quarantined")

        # Enhanced enforcement for monitored region
        if is_monitored:
            # Block all external traffic for monitored region
            dst_ip = ipaddress.ip_address(event.network.dst_ip)
            if not dst_ip.is_private and str(dst_ip) != "169.254.169.254":
                logger.warning(f"External connection from monitored region blocked: {event.network.dst_ip}")
                actions.append("regional_enforcement_triggered")

                if event.kubernetes:
                    self.quarantine_manager.quarantine_pod(event, is_monitored)
                    actions.append("pod_quarantined")

        return actions

    def _has_suspicious_arguments(self, arguments: str) -> bool:
        """Check for suspicious process arguments"""
        suspicious_patterns = [
            'bash -i', 'sh -i', '/dev/tcp', 'nc -e', 'curl | bash',
            'wget | sh', 'base64', 'python -c', 'perl -e',
            'sudo su', 'chmod +s', '| bash', '| sh'
        ]

        args_lower = arguments.lower()
        return any(pattern in args_lower for pattern in suspicious_patterns)

    def _send_alert(self, event: TetragonEvent, is_monitored: bool):
        """Send SNS alert for high-severity events"""
        try:
            alert_message = {
                "event_id": event.process_exec_id,
                "timestamp": event.time.isoformat(),
                "severity": "HIGH",
                "event_type": event.event_type.name,
                "node_name": event.node_name,
                "monitored_region": is_monitored,
                "policy": event.policy_name,
                "process": {
                    "binary": event.process.binary,
                    "arguments": event.process.arguments[:200]  # Truncate long arguments
                }
            }

            if event.kubernetes:
                alert_message["kubernetes"] = {
                    "namespace": event.kubernetes.namespace,
                    "pod": event.kubernetes.pod_name,
                    "workload": event.kubernetes.workload_name
                }

            if event.file:
                alert_message["file_path"] = event.file.path

            if event.network:
                alert_message["network"] = {
                    "dst_ip": event.network.dst_ip,
                    "dst_port": event.network.dst_port
                }

            sns.publish(
                TopicArn=SNS_TOPIC_ARN,
                Message=json.dumps(alert_message, indent=2),
                Subject=f"🚨 Runtime Drift Detected - {event.severity.upper()}"
            )

        except Exception as e:
            logger.error(f"Failed to send SNS alert: {e}")

    def _log_event(self, event: TetragonEvent):
        """Log event to appropriate CloudWatch log group"""
        log_group = '/aws/security/drift-engine/events'

        if event.is_process_exec_event():
            log_group = '/aws/security/drift-engine/process-exec'
        elif event.is_file_access_event():
            log_group = '/aws/security/drift-engine/file-access'
        elif event.is_network_event():
            log_group = '/aws/security/drift-engine/network-events'

        try:
            cloudwatch.put_log_events(
                logGroupName=log_group,
                logStreamName=f'events-{datetime.utcnow().strftime("%Y-%m-%d")}',
                logEvents=[{
                    'timestamp': int(event.time.timestamp() * 1000),
                    'message': json.dumps(event.to_cloudwatch_message())
                }]
            )
        except Exception as e:
            logger.error(f"Failed to log event to CloudWatch: {e}")

def lambda_handler(event, context):
    """Main Lambda handler function"""
    logger.info(f"Processing event batch with {len(event.get('Records', []))} records")

    processor = EventProcessor()
    results = []

    try:
        for record in event.get('Records', []):
            # CloudWatch Logs data is compressed and base64 encoded
            compressed_payload = base64.b64decode(record['kinesis']['data'])
            uncompressed_payload = gzip.decompress(compressed_payload)
            log_data = json.loads(uncompressed_payload)

            # Process each log event
            for log_event in log_data.get('logEvents', []):
                try:
                    # Parse Tetragon event
                    tetragon_event = TetragonEvent.from_json(log_event['message'])

                    # Process the event
                    result = processor.process_event(tetragon_event)
                    results.append(result)

                except Exception as e:
                    logger.error(f"Failed to process log event: {e}")
                    results.append({
                        "error": str(e),
                        "processed": False,
                        "log_event": log_event
                    })

        return {
            'statusCode': 200,
            'body': json.dumps({
                'processed_events': len(results),
                'successful': len([r for r in results if r.get('processed', False)]),
                'failed': len([r for r in results if not r.get('processed', True)]),
                'results': results
            })
        }

    except Exception as e:
        logger.error(f"Lambda execution failed: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': str(e),
                'processed_events': 0
            })
        }

# Test function for local development
def test_lambda():
    """Test function with example events"""
    test_events = [
        EXAMPLE_PROCESS_EXEC_EVENT,
        EXAMPLE_FILE_ACCESS_EVENT,
        EXAMPLE_NETWORK_EVENT
    ]

    processor = EventProcessor()

    for i, event_json in enumerate(test_events):
        print(f"\n=== Test Event {i+1} ===")
        try:
            event = TetragonEvent.from_json(event_json)
            result = processor.process_event(event)
            print(f"Result: {json.dumps(result, indent=2)}")
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    test_lambda()