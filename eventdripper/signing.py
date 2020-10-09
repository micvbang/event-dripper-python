from dataclasses import dataclass
import base64
import hmac
import json
import time
from hashlib import sha256
from typing import ByteString

from eventdripper.notification import Notification, Event
from eventdripper.exceptions import InvalidHeaderError, SignatureExpiredError, InvalidSignatureError, InvalidPayloadFormatError
from eventdripper.rfc3339 import parse_datetime

SigningVersion = 'v1'
SigningToleranceSeconds = 300


def construct_notification(payload: str, header: str, secret: str) -> Notification:
    signed_header = _parse_header(header)

    if SigningToleranceSeconds and signed_header.timestamp < time.time() - SigningToleranceSeconds:
        raise SignatureExpiredError

    expected_signature = _compute_signature(secret, signed_header.timestamp, payload)

    for got_signatures in signed_header.signatures:
        if hmac.compare_digest(expected_signature, got_signatures):
            return _build_notification(payload)

    raise InvalidSignatureError


def _build_notification(payload: str) -> Notification:
    try:
        notification_json = json.loads(payload)

        events = []
        for event in notification_json['events']:
            events.append(Event(
                at=parse_datetime(event['at']),
                name=event['name'],
                data=base64.b64decode(event['data']),
            ))

        return Notification(
            trigger_name=notification_json['trigger_name'],
            entity_id=notification_json['entity_id'],
            events=events,
        )
    except Exception as e:
        raise InvalidPayloadFormatError(e)


def _compute_signature(secret: ByteString, timestamp: int, payload: ByteString):
    mac = hmac.new(
        secret.encode("utf-8"),
        msg=f'{timestamp}.{payload}'.encode("utf-8"),
        digestmod=sha256,
    )
    return mac.hexdigest()


@dataclass
class SignedHeader:
    timestamp: int = int
    signatures: [] = list


def _parse_header(header: str) -> SignedHeader:
    if len(header) == 0:
        raise InvalidHeaderError('empty header')

    signed_header = SignedHeader(timestamp=None, signatures=[])

    pairs = header.split(',')
    for pair in pairs:
        parts = pair.split('=')
        if len(parts) != 2:
            raise InvalidHeaderError('invalid format')

        key, value = parts
        if key == 't':
            try:
                signed_header.timestamp = int(value)
            except ValueError:
                raise InvalidHeaderError('invalid timestamp format')
        elif key == SigningVersion:
            signed_header.signatures.append(value)
        else:
            pass

    if len(signed_header.signatures) == 0 or signed_header.timestamp is None:
        raise InvalidHeaderError('missing fields')

    return signed_header
