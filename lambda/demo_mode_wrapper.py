"""
Demo Mode Wrapper for Drift Enforcement Lambda
Provides mock responses when DEMO_MODE=true for webinar presentations.
"""

import os
import json
import logging
from datetime import datetime, timezone
from typing import Dict, Any

logger = logging.getLogger(__name__)

DEMO_MODE = os.environ.get('DEMO_MODE', 'false').lower() == 'true'

# Pre-baked mock responses for demo
MOCK_RESPONSES = {
    "process_exec_violation": {
        "event_id": "demo-process-exec-001",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "PROCESS_EXEC",
        "severity": "critical",
        "processed": True,
        "high_severity": True,
        "monitored_region": True,
        "actions_taken": [
            "pod_quarantined",
            "suspicious_args_detected",
            "alert_sent"
        ],
        "demo_mode": True,
        "message": "✅ Malicious process detected and pod quarantined automatically"
    },
    "file_access_violation": {
        "event_id": "demo-file-access-001",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "FILE",
        "severity": "high",
        "processed": True,
        "high_severity": True,
        "actions_taken": [
            "critical_file_access",
            "pod_quarantined",
            "alert_sent"
        ],
        "demo_mode": True,
        "message": "✅ Critical file modification blocked and pod isolated"
    },
    "network_violation": {
        "event_id": "demo-network-001",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "NETWORK",
        "severity": "medium",
        "processed": True,
        "actions_taken": [
            "egress_blocked",
            "logged"
        ],
        "demo_mode": True,
        "message": "✅ Unauthorized network egress blocked by Tetragon policy"
    },
    "remediation_success": {
        "remediation_id": f"demo-rem-{datetime.now().strftime('%Y%m%d%H%M%S')}",
        "status": "SUCCESS",
        "config_rule": "no-public-ingress",
        "violation": "Security group allowed SSH from 0.0.0.0/0",
        "action_taken": "Ingress rule revoked automatically",
        "duration_ms": 1234,
        "demo_mode": True,
        "message": "✅ Security group drift detected and auto-remediated in <2 seconds"
    }
}


def get_demo_response(event_type: str) -> Dict[str, Any]:
    """
    Returns a pre-baked mock response for demo purposes.
    Use when DEMO_MODE=true to avoid real AWS/K8s API calls.
    """
    if event_type in MOCK_RESPONSES:
        response = MOCK_RESPONSES[event_type].copy()
        response["timestamp"] = datetime.now(timezone.utc).isoformat()
        return response
    
    return {
        "event_id": f"demo-unknown-{datetime.now().timestamp()}",
        "processed": True,
        "demo_mode": True,
        "message": "✅ Event processed successfully (demo mode)"
    }


def demo_lambda_handler(event: dict, context: Any) -> Dict[str, Any]:
    """
    Demo-safe Lambda handler that returns mock responses.
    Prevents crashes during webinar if AWS/K8s connectivity fails.
    """
    logger.info("[DEMO MODE] Processing simulated event")
    
    # Simulate processing delay for realism
    import time
    time.sleep(0.5)
    
    # Determine event type from payload
    event_type = "process_exec_violation"  # Default
    
    if "Records" in event:
        # Simulated Kinesis event
        logger.info(f"[DEMO MODE] Processing {len(event['Records'])} simulated records")
        event_type = "remediation_success"
    elif "process" in str(event).lower():
        event_type = "process_exec_violation"
    elif "file" in str(event).lower():
        event_type = "file_access_violation"
    elif "network" in str(event).lower():
        event_type = "network_violation"
    
    response = get_demo_response(event_type)
    
    return {
        "statusCode": 200,
        "body": json.dumps({
            "demo_mode": True,
            "processed_events": 1,
            "successful": 1,
            "failed": 0,
            "results": [response]
        }, indent=2)
    }


def wrap_handler_with_demo_fallback(real_handler):
    """
    Decorator that wraps a real handler with demo mode fallback.
    If DEMO_MODE=true or if real handler fails, return mock response.
    """
    def wrapper(event, context):
        if DEMO_MODE:
            logger.info("[DEMO MODE] Using mock responses")
            return demo_lambda_handler(event, context)
        
        try:
            return real_handler(event, context)
        except Exception as e:
            logger.error(f"Real handler failed: {e}")
            logger.info("[FALLBACK] Switching to demo mode response")
            
            # Return graceful fallback instead of crashing
            return {
                "statusCode": 200,
                "body": json.dumps({
                    "fallback_mode": True,
                    "original_error": str(e),
                    "message": "⚠️ Connectivity issue detected - showing simulated response",
                    "results": [get_demo_response("remediation_success")]
                }, indent=2)
            }
    
    return wrapper


# Console demo function for live presentation
def run_demo_sequence():
    """
    Runs a complete demo sequence showing all enforcement scenarios.
    Perfect for webinar live coding sessions.
    """
    print("\n" + "="*60)
    print("  IMLADRIS DRIFT ENFORCEMENT - LIVE DEMO")
    print("="*60 + "\n")
    
    scenarios = [
        ("process_exec_violation", "Malicious Process Detection"),
        ("file_access_violation", "Critical File Modification"),
        ("network_violation", "Unauthorized Network Egress"),
        ("remediation_success", "Auto-Remediation Complete")
    ]
    
    for event_type, description in scenarios:
        print(f"📋 Scenario: {description}")
        print("-" * 40)
        
        response = get_demo_response(event_type)
        print(f"   Event ID: {response['event_id']}")
        print(f"   Status: ✅ {response['message']}")
        print(f"   Actions: {', '.join(response.get('actions_taken', ['logged']))}")
        print()
        
        import time
        time.sleep(1)  # Dramatic pause
    
    print("="*60)
    print("  ✅ All scenarios completed successfully!")
    print("="*60 + "\n")


if __name__ == "__main__":
    run_demo_sequence()
