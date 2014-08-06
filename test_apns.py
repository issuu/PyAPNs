#!/usr/bin/env python
# coding: utf-8
from binascii import a2b_hex
from random import random
from apns import APNs
from apns import Payload
from apns import PayloadAlert
from apns import DEFAULT_MAX_PAYLOAD_LENGTH
from apns import PayloadTooLargeError

import hashlib
import time
import unittest

TEST_CERTIFICATE = "certificate.pem" # replace with path to test certificate

NUM_MOCK_TOKENS = 10
mock_tokens = []
for i in range(0, NUM_MOCK_TOKENS):
    mock_tokens.append(hashlib.sha256("%.12f" % random()).hexdigest())

def mock_chunks_generator():
    buffer_size = 64
    # Create fake data feed
    data = ''

    for t in mock_tokens:
        token_bin       = a2b_hex(t)
        token_length    = len(token_bin)

        data += APNs.packed_uint_big_endian(int(time.time()))
        data += APNs.packed_ushort_big_endian(token_length)
        data += token_bin

    while data:
        yield data[0:buffer_size]
        data = data[buffer_size:]


class TestAPNs(unittest.TestCase): # pylint: disable=R0904
    """Unit tests for PyAPNs"""

    def setUp(self):
        """docstring for setUp"""
        pass

    def tearDown(self):
        """docstring for tearDown"""
        pass

    def testConfigs(self):
        apns_test = APNs(use_sandbox=True)
        apns_prod = APNs(use_sandbox=False)

        self.assertEqual(apns_test.gateway_server.port, 2195)
        self.assertEqual(apns_test.gateway_server.server,
            'gateway.sandbox.push.apple.com')
        self.assertEqual(apns_test.feedback_server.port, 2196)
        self.assertEqual(apns_test.feedback_server.server,
            'feedback.sandbox.push.apple.com')

        self.assertEqual(apns_prod.gateway_server.port, 2195)
        self.assertEqual(apns_prod.gateway_server.server,
            'gateway.push.apple.com')
        self.assertEqual(apns_prod.feedback_server.port, 2196)
        self.assertEqual(apns_prod.feedback_server.server,
            'feedback.push.apple.com')

    #
    # This test appears to be dead - it invokes a method that no longer exists.
    #
    # def testGatewayServer(self):
    #     pem_file = TEST_CERTIFICATE
    #     apns = APNs(use_sandbox=True, cert_file=pem_file, key_file=pem_file)
    #     gateway_server = apns.gateway_server

    #     self.assertEqual(gateway_server.cert_file, apns.cert_file)
    #     self.assertEqual(gateway_server.key_file, apns.key_file)

    #     token_hex = 'b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c'
    #     payload   = Payload(
    #         alert = "Hello World!",
    #         sound = "default",
    #         badge = 4
    #     )
    #     identifier = 'abcd'
    #     expiry = datetime(2000, 01, 01, 00, 00, 00)
    #     notification = apns.gateway_server.(token_hex, payload, identifier, expiry)

    #     expected_length = (
    #         1                       # leading command byte
    #         + 4                     # Identifier as a 4 bytes buffer
    #         + 4                     # Expiry timestamp as a packed integer
    #         + 2                     # length of token as a packed short
    #         + len(token_hex) / 2    # length of token as binary string
    #         + 2                     # length of payload as a packed short
    #         + len(payload.json())   # length of JSON-formatted payload
    #     )

    #     self.assertEqual(len(notification), expected_length)
    #     self.assertEqual(notification[0], '\x01') # Enhanched format command byte

    def testFeedbackServer(self):
        pem_file = TEST_CERTIFICATE
        apns = APNs(use_sandbox=True, cert_file=pem_file, key_file=pem_file)
        feedback_server = apns.feedback_server

        self.assertEqual(feedback_server.cert_file, apns.cert_file)
        self.assertEqual(feedback_server.key_file, apns.key_file)

        # Overwrite _chunks() to call a mock chunk generator
        feedback_server._chunks = mock_chunks_generator # pylint: disable=W0212

        x = 0
        for (token_hex, _) in feedback_server.items():
            self.assertEqual(token_hex, mock_tokens[x])
            x += 1
        self.assertEqual(x, NUM_MOCK_TOKENS)

    def testPayloadAlert(self):
        pa = PayloadAlert('foo')
        d = pa.dict()
        self.assertEqual(d['body'], 'foo')
        self.assertFalse('action-loc-key' in d)
        self.assertFalse('loc-key' in d)
        self.assertFalse('loc-args' in d)
        self.assertFalse('launch-image' in d)

        pa = PayloadAlert('foo', action_loc_key='bar', loc_key='wibble',
            loc_args=['king','kong'], launch_image='wobble')
        d = pa.dict()
        self.assertEqual(d['body'], 'foo')
        self.assertEqual(d['action-loc-key'], 'bar')
        self.assertEqual(d['loc-key'], 'wibble')
        self.assertEqual(d['loc-args'], ['king','kong'])
        self.assertEqual(d['launch-image'], 'wobble')

    def testPayload(self):
        # Payload with just alert
        p = Payload(alert=PayloadAlert('foo'))
        d = p.dict()
        self.assertTrue('alert' in d['aps'])
        self.assertTrue('sound' not in d['aps'])
        self.assertTrue('badge' not in d['aps'])

        # Payload with just sound
        p = Payload(sound="foo")
        d = p.dict()
        self.assertTrue('sound' in d['aps'])
        self.assertTrue('alert' not in d['aps'])
        self.assertTrue('badge' not in d['aps'])

        # Payload with just badge
        p = Payload(badge=1)
        d = p.dict()
        self.assertTrue('badge' in d['aps'])
        self.assertTrue('alert' not in d['aps'])
        self.assertTrue('sound' not in d['aps'])

        # Payload with just badge removal
        p = Payload(badge=0)
        d = p.dict()
        self.assertTrue('badge' in d['aps'])
        self.assertTrue('alert' not in d['aps'])
        self.assertTrue('sound' not in d['aps'])

        # Test plain string alerts
        alert_str = 'foobar'
        p = Payload(alert=alert_str)
        d = p.dict()
        self.assertEqual(d['aps']['alert'], alert_str)
        self.assertTrue('sound' not in d['aps'])
        self.assertTrue('badge' not in d['aps'])

        # Test custom payload
        alert_str = 'foobar'
        custom_dict = {'foo': 'bar'}
        p = Payload(alert=alert_str, custom=custom_dict)
        d = p.dict()
        self.assertEqual(d, {'foo': 'bar', 'aps': {'alert': 'foobar'}})


    def testPayloadTooLargeError(self):
        # The maximum size of the JSON payload is DEFAULT_MAX_PAYLOAD_LENGTH
        # bytes. First determine how many bytes this allows us in the
        # raw payload (i.e. before JSON serialisation)
        json_overhead_bytes = len(Payload('.').json()) - 1
        max_raw_payload_bytes = DEFAULT_MAX_PAYLOAD_LENGTH - json_overhead_bytes

        # Test ascii characters payload
        Payload('.' * max_raw_payload_bytes)
        self.assertRaises(PayloadTooLargeError, Payload,
            '.' * (max_raw_payload_bytes + 1))

        # Test unicode 2-byte characters payload
        Payload(u'\u0100' * int(max_raw_payload_bytes / 2))
        self.assertRaises(PayloadTooLargeError, Payload,
            u'\u0100' * (int(max_raw_payload_bytes / 2) + 1))

class TestTruncateJSON(unittest.TestCase):

    def assertTruncateListWith(self, truncate_fun, context, content, expected_outputs):
        context_length = len(context[0] + context[1])

        for length in range(len(expected_outputs)):
            expected_output = expected_outputs[length]
            if isinstance(expected_output, type):
                try:
                    truncated = truncate_fun(content, length)
                except Exception as e:
                    self.assertIsInstance(e, expected_output)
                else:
                    self.fail("Expected exception {} but got string {}".format(
                        expected_output, truncated))
            else:
                self.assertLessEqual(len(expected_output), length)
                truncated = truncate_fun(content, length)
                self.assertEquals(truncated,
                                  context[0] + expected_output + context[1])


    def assertTruncateList(self, content, expected_outputs):
        context=('(((', ')))')
        def truncate_fun(content, length):
            truncated = Payload._truncate_json(content, length)
            escaped = Payload._to_json_utf8(truncated)[1:-1]
            return context[0] + escaped + context[1]
        self.assertTruncateListWith(truncate_fun,
                                    context,
                                    content,
                                    expected_outputs)

        def truncate_fun_full_length(content, length):
            return Payload(
                alert=content,
                custom={"hello": "world"},
                max_payload_length=length,
                truncate=True
            ).json()
        context = tuple(truncate_fun_full_length("!", 1000).split("!"))
        self.assertEquals(len(context), 2)
        def truncate_fun(content, length):
            return truncate_fun_full_length(content,
                                            length + len(context[0]) + len(context[1]))
        expected_outputs = [
            (s if s else PayloadTooLargeError)
            for s in expected_outputs
        ]
        self.assertTruncateListWith(truncate_fun,
                                    context,
                                    content,
                                    expected_outputs)


    def test_no_special_chars(self):
        self.assertEquals(Payload._truncate_json("", 100), "")
        self.assertEquals(Payload._truncate_json("big ", 100), "big ")

        self.assertTruncateList("big ", [
            "",
            "b",
            "bi",
            "big",
            "big ",
            "big ",
            "big ",
        ])

    def test_utf8(self):
        self.assertTruncateList('fæ', [
            '',
            'f',
            'f',
            'fæ',
            'fæ',
        ])

        self.assertTruncateList('øgle', [
            '',
            '',
            'ø',
            'øg',
            'øgl',
        ])

        self.assertTruncateList('nøgler', [
            '',
            'n',
            'n',
            'nø',
            'nøg',
        ])

        umbrella = u'\U0001F302'.encode('utf-8') # emoji, four bytes
        self.assertEquals(len(umbrella), 4)

        self.assertTruncateList(umbrella+'B', [
            '',
            '',
            '',
            '',
            umbrella,
            umbrella+'B',
        ])

        self.assertTruncateList('A'+umbrella+'B', [
            '',
            'A',
            'A',
            'A',
            'A',
            'A'+umbrella,
            'A'+umbrella+'B',
        ])

    def test_backslash(self):
        self.assertTruncateList('A\n6789', [
            '',
            'A',
            'A',
            'A\\n',
            'A\\n6',
        ])

        # TODO: test with unicode literals as well


if __name__ == '__main__':
    unittest.main()
