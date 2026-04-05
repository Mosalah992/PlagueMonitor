import httpx
from datetime import datetime
from typing import Dict, Any, Optional

class BackendAPIClient:
    def __init__(self, base_url: str = "http://localhost:8000/api/internal"):
        self.base_url = base_url
        self.client = httpx.Client(timeout=5.0)

    def report_agent_state(self, state_dict: Dict[str, Any]):
        try:
            # Ensure datetime is stringified for JSON
            if isinstance(state_dict.get('last_event_at'), datetime):
                state_dict['last_event_at'] = state_dict['last_event_at'].isoformat()
                
            resp = self.client.post(f"{self.base_url}/events/agent_state", json=state_dict)
            resp.raise_for_status()
        except Exception as e:
            print(f"Error reporting agent state: {e}")

    def report_infection_event(self, event_dict: Dict[str, Any]):
        try:
            if isinstance(event_dict.get('timestamp'), datetime):
                 event_dict['timestamp'] = event_dict['timestamp'].isoformat()
                 
            resp = self.client.post(f"{self.base_url}/events/infection", json=event_dict)
            resp.raise_for_status()
        except Exception as e:
            print(f"Error reporting infection event: {e}")

    def publish_snapshot(self, snapshot_dict: Dict[str, Any]):
        try:
            if 'id' in snapshot_dict:
                del snapshot_dict['id'] # Will be auto-assigned implicitly by schema wait schema expects int
            
            # The schema expects id: int, so let's set a dummy one 
            snapshot_dict['id'] = 0 
                
            if isinstance(snapshot_dict.get('timestamp'), datetime):
                 snapshot_dict['timestamp'] = snapshot_dict['timestamp'].isoformat()
                 
            resp = self.client.post(f"{self.base_url}/events/snapshot", json=snapshot_dict)
            resp.raise_for_status()
        except Exception as e:
            print(f"Error reporting snapshot: {e}")
            
    def close(self):
        self.client.close()
