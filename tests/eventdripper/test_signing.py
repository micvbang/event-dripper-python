import base64
import json
from unittest import TestCase
from dataclasses import dataclass
from typing import Sequence
from contextlib import contextmanager
import time

from eventdripper.signing import _compute_signature, _parse_header
from eventdripper import construct_notification
from eventdripper import InvalidSignatureError, InvalidHeaderError, SignatureExpiredError
from eventdripper.rfc3339 import parse_datetime
from eventdripper import signing


class TestSigning(TestCase):

    def test_compute_signature(self):
        """ Verifies that compute_signature computes the expected signature.
        Expected signatures have been computed from a reference implementation.
        """

        @dataclass
        class Test:
            secret: str
            timestamp: int
            payload: str
            expected: str

        tests = {
            'simple': Test(
                secret='secret',
                timestamp=421337,
                payload='payload',
                expected='1ddcaadc64a25cc5053ece8965723309bb6d20ba72f8a1b78fc37a83ae027a29'
            ),
            'longer payload': Test(
                secret='top secret',
                timestamp=1602253775,
                payload='wow this payload is larger. not very large, but larger!',
                expected='8b3fbc3bab914fcb8afa437a9412336139b22a9dd8b5ef019ca28bc4597e4a94'
            ),
        }

        for name, test in tests.items():
            got = _compute_signature(test.secret, test.timestamp, test.payload)
            self.assertEqual(test.expected, got, name)

    def test_parse_header(self):
        """ Verifies that parse_header throws exceptions for invalid headers,
        and correctly parses valid headers.
        """

        @dataclass
        class Test:
            header: str
            expected_timestamp: int = int
            expected_signatures: Sequence[str] = list
            expected_raises: Exception = None

        tests = {
            'simple': Test(
                header='t=1,v1=haps',
                expected_timestamp=1,
                expected_signatures=['haps']
            ),
            'multiple signatures': Test(
                header='t=1601036356,v1=FOO,v1=BAR',
                expected_timestamp=1601036356,
                expected_signatures=['FOO', 'BAR']
            ),
            'old signature': Test(
                header='t=42133742,v1=FOO,v0=BAR',
                expected_timestamp=42133742,
                expected_signatures=['FOO']
            ),
            'empty header': Test(
                header='',
                expected_raises=InvalidHeaderError,
            ),
            'no time': Test(
                header='v1=haps',
                expected_raises=InvalidHeaderError,
            ),
            'no signature': Test(
                header='t=123123',
                expected_raises=InvalidHeaderError,
            ),
        }

        for name, test in tests.items():
            with self._maybe_raises(test.expected_raises):
                got = _parse_header(test.header)
                self.assertEqual(test.expected_timestamp, got.timestamp, name)
                self.assertEqual(test.expected_signatures, got.signatures, name)

    def test_construct_notification(self):
        """ Verifies that a payload generated on the fly is verified as expected
        """

        trigger_name = 'trigger name'
        entity_id = 'entity id'

        expected_events = [
            {
                'at': '2020-10-09T13:47:17.321618Z',
                'name': 'event1 name',
                'data': base64.b64encode('event1 data'.encode('utf8')).decode('utf8'),
            },
            {
                'at': '2019-02-25T09:41:12.321618Z',
                'name': 'event2 name',
                'data': base64.b64encode('event2 data'.encode('utf8')).decode('utf8'),
            },
        ]

        payload = json.dumps({
            'entity_id': entity_id,
            'trigger_name': trigger_name,
            'events': expected_events,
        })

        secret = 'top secret'
        timestamp = int(time.time())
        signature = _compute_signature(secret=secret, timestamp=timestamp, payload=payload)
        header = f't={timestamp},v1={signature}'

        got_notification = construct_notification(payload=payload, header=header, secret=secret,)
        self.assertEqual(trigger_name, got_notification.trigger_name)
        self.assertEqual(entity_id, got_notification.entity_id)
        self.assertEqual(len(expected_events), len(got_notification.events))

        for i, expected in enumerate(expected_events):
            got = got_notification.events[i]
            self.assertEqual(parse_datetime(expected['at']), got.at)
            self.assertEqual(expected['name'], got.name)
            self.assertEqual(base64.b64decode(expected['data']), got.data)

    def test_construct_notification_invalid_header_signature(self):
        """ Verifies that a header with an invalid signature raises the
        InvalidSignatureError.
        """

        payload = json.dumps({
            'entity_id': 'entity id',
            'trigger_name': 'trigger name',
            'events': [
                {
                    'at': '2020-10-09T13:47:17.321618Z',
                    'name': 'event1 name',
                    'data': base64.b64encode('event1 data'.encode('utf8')).decode('utf8'),
                },
                {
                    'at': '2019-02-25T09:41:12.321618Z',
                    'name': 'event2 name',
                    'data': base64.b64encode('event2 data'.encode('utf8')).decode('utf8'),
                },
            ],
        })

        secret = 'top secret'
        timestamp = int(time.time())
        header = f't={timestamp},v1=invalid'

        with self.assertRaises(InvalidSignatureError):
            construct_notification(payload=payload, header=header, secret=secret)

    def test_construct_notification_invalid_header_timestamp(self):
        """ Verifies that a header with an incorrect timestamp set raises the
        InvalidSignatureError.
        """

        payload = json.dumps({
            'entity_id': 'entity id',
            'trigger_name': 'trigger name',
            'events': [
                {
                    'at': '2020-10-09T13:47:17.321618Z',
                    'name': 'event1 name',
                    'data': base64.b64encode('event1 data'.encode('utf8')).decode('utf8'),
                },
                {
                    'at': '2019-02-25T09:41:12.321618Z',
                    'name': 'event2 name',
                    'data': base64.b64encode('event2 data'.encode('utf8')).decode('utf8'),
                },
            ],
        })

        secret = 'top secret'
        timestamp = int(time.time())
        signature = _compute_signature(secret=secret, timestamp=timestamp, payload=payload)

        header = f't={timestamp+10},v1={signature}'

        with self.assertRaises(InvalidSignatureError):
            construct_notification(payload=payload, header=header, secret=secret)

    def test_construct_notification_expired_timestamp(self):
        """ Verifies that a header with a expired timestamp raises the
        SignatureExpiredError.
        """

        payload = json.dumps({
            'entity_id': 'entity id',
            'trigger_name': 'trigger name',
            'events': [
                {
                    'at': '2020-10-09T13:47:17.321618Z',
                    'name': 'event1 name',
                    'data': base64.b64encode('event1 data'.encode('utf8')).decode('utf8'),
                },
                {
                    'at': '2019-02-25T09:41:12.321618Z',
                    'name': 'event2 name',
                    'data': base64.b64encode('event2 data'.encode('utf8')).decode('utf8'),
                },
            ],
        })

        secret = 'top secret'
        timestamp = int(133742)
        signature = _compute_signature(secret=secret, timestamp=timestamp, payload=payload)

        header = f't={timestamp},v1={signature}'

        with self.assertRaises(SignatureExpiredError):
            construct_notification(payload=payload, header=header, secret=secret)

    def test_construct_notification_actual_data(self):
        """ Verifies that data coming from a real event-dripper server request
        is verified as expected.

        ... no, the secret is no longer in use :)
        """

        expected_event = {
            'at': parse_datetime('2020-10-09T13:47:17.321618Z'),
            'name': 'trigger_now',
            'data': base64.b64decode('eW91d2luQHZiYW5nLmRr'.encode('utf8')),
        }

        payload = '{"trigger_name":"trigger_now","entity_id":"michael","events":[{"at":"2020-10-09T13:47:17.321618Z","name":"trigger_now","data":"eW91d2luQHZiYW5nLmRr"}]}'

        secret = '6f060e57177008f4bfbc981c5fd1b2abfe22fb64fc6f4e384b5ca7b25d3ecec8'
        header = 't=1602251283,v1=21b9339ced8c9b178f3f9bf7a29a212ec832443e8e2c05fd2dc7ef2fdaa70559'

        got_notification = None
        with self.disable_tolerance():
            got_notification = construct_notification(payload=payload, header=header, secret=secret,)

        self.assertEqual('trigger_now', got_notification.trigger_name)
        self.assertEqual('michael', got_notification.entity_id)
        self.assertEqual(1, len(got_notification.events))

        got = got_notification.events[0]
        self.assertEqual(expected_event['at'], got.at)
        self.assertEqual(expected_event['name'], got.name)
        self.assertEqual(expected_event['data'], got.data)

    @contextmanager
    def disable_tolerance(self):
        cur = signing.SigningToleranceSeconds
        signing.SigningToleranceSeconds = 0
        yield
        signing.SigningToleranceSeconds = cur

    @contextmanager
    def _maybe_raises(self, exception: Exception = None):
        if exception:
            with self.assertRaises(exception):
                yield
        else:
            yield
