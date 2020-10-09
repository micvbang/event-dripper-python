import requests
import base64


class Client:
    def __init__(self, api_key: str, host: str = None):
        self._api_key = api_key
        self._host = host if host else 'https://api.production.event-dripper.haps.pw'
        self._requests = requests.Session()

    def add_event(self, entity_id: str, event_name: str, data: str):
        payload = {
            'entity_id': entity_id,
            'event_name': event_name,
            'data': base64.b64encode(data.encode('utf8')),  # TODO: verify
        }

        headers = {
            'Authorization': self._api_key
        }

        r = self._requests.post(f'{self._host}/api/event', json=payload, headers=headers)
        r.raise_for_status()
