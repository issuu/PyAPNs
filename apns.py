# PyAPNs was developed by Simon Whitaker <simon@goosoftware.co.uk>
# Source available at https://github.com/simonwhitaker/PyAPNs
#
# PyAPNs is distributed under the terms of the MIT license.
#
# Copyright (c) 2011 Goo Software Ltd
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is furnished to do
# so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from binascii import a2b_hex, b2a_hex
from datetime import datetime, timedelta
from time import mktime
from socket import socket, AF_INET, SOCK_STREAM
from struct import pack, unpack
import string
import logging


logger = logging.getLogger('apns')


try:
    from ssl import wrap_socket
    from ssl import SSLError
except ImportError:
    from socket import ssl as wrap_socket

try:
    import json
except ImportError:
    import simplejson as json


DEFAULT_MAX_PAYLOAD_LENGTH = 256


class APNs(object):
    """A class representing an Apple Push Notification service connection"""

    def __init__(self, use_sandbox=False, cert_file=None, key_file=None):
        """
        Set use_sandbox to True to use the sandbox (test) APNs servers.
        Default is False.
        """
        super(APNs, self).__init__()
        self.use_sandbox = use_sandbox
        self.cert_file = cert_file
        self.key_file = key_file
        self._feedback_connection = None
        self._gateway_connection = None

    @staticmethod
    def packed_ushort_big_endian(num):
        """
        Returns an unsigned short in packed big-endian (network) form
        """
        return pack('>H', num)

    @staticmethod
    def unpacked_ushort_big_endian(bytez):
        """
        Returns an unsigned short from a packed big-endian (network) byte
        array
        """
        return unpack('>H', bytez)[0]

    @staticmethod
    def packed_uint_big_endian(num):
        """
        Returns an unsigned int in packed big-endian (network) form
        """
        return pack('>I', num)

    @staticmethod
    def unpacked_uint_big_endian(bytez):
        """
        Returns an unsigned int from a packed big-endian (network) byte array
        """
        return unpack('>I', bytez)[0]

    @property
    def feedback_server(self):
        if not self._feedback_connection:
            self._feedback_connection = FeedbackConnection(
                use_sandbox = self.use_sandbox,
                cert_file = self.cert_file,
                key_file = self.key_file
            )
        return self._feedback_connection

    @property
    def gateway_server(self):
        if not self._gateway_connection:
            self._gateway_connection = GatewayConnection(
                use_sandbox = self.use_sandbox,
                cert_file = self.cert_file,
                key_file = self.key_file
            )
        return self._gateway_connection


class APNsConnection(object):
    """
    A generic connection class for communicating with the APNs
    """
    def __init__(self, cert_file=None, key_file=None):
        super(APNsConnection, self).__init__()
        self.cert_file = cert_file
        self.key_file = key_file
        self.server = None
        self.port = None
        self._socket = None
        self._ssl = None

    def __del__(self):
        self._disconnect()

    def _connect(self):
        # Establish an SSL connection
        logger.info("Connecting")
        self._socket = socket(AF_INET, SOCK_STREAM)
        self._socket.connect((self.server, self.port))
        self._ssl = wrap_socket(self._socket, self.key_file, self.cert_file)

    def _disconnect(self):
        logger.info("Disconnecting")
        if self._socket:
            self._socket.close()
            self._ssl = None  # Make sure we reconnect on next try

    def _connection(self):
        if not self._ssl:
            self._connect()
        return self._ssl

    def read(self, n=None, timeout=0):
        self._connection().settimeout(timeout)
        return self._connection().read(n)

    def write(self, s):
        return self._connection().write(s)


class PayloadAlert(object):
    def __init__(self, body=None, action_loc_key=None, loc_key=None,
                 loc_args=None, launch_image=None):
        super(PayloadAlert, self).__init__()
        self.body = body
        self.action_loc_key = action_loc_key
        self.loc_key = loc_key
        self.loc_args = loc_args
        self.launch_image = launch_image

    def dict(self):
        d = {}
        if self.body:
            d['body'] = self.body
        if self.action_loc_key:
            d['action-loc-key'] = self.action_loc_key
        if self.loc_key:
            d['loc-key'] = self.loc_key
        if self.loc_args:
            d['loc-args'] = self.loc_args
        if self.launch_image:
            d['launch-image'] = self.launch_image
        return d


class PayloadTooLargeError(Exception):
    pass


class Payload(object):
    """A class representing an APNs message payload"""
    def __init__(self, alert=None, badge=None, sound=None, custom=None, category=None,
                 max_payload_length=DEFAULT_MAX_PAYLOAD_LENGTH, truncate=False):
        self.alert = alert
        self.badge = badge
        self.sound = sound
        self.custom = custom
        self.category = category
        try:
            self._check_size(max_payload_length)
        except PayloadTooLargeError as e:
            if truncate:
                self._truncate_alert(max_payload_length)
            else:
                raise e

    def dict(self):
        """Returns the payload as a regular Python dictionary"""
        aps = {}
        if self.alert:
            # Alert can be either a string or a PayloadAlert
            # object
            if isinstance(self.alert, PayloadAlert):
                aps['alert'] = self.alert.dict()
            else:
                aps['alert'] = self.alert
        if self.sound:
            aps['sound'] = self.sound
        if self.badge is not None:
            aps['badge'] = int(self.badge)

        payload = {
            'aps': aps
        }

        if self.category is not None:
            payload['category'] = self.category

        if self.custom:
            payload.update(self.custom)

        return payload

    def json(self):
        return Payload._to_json_utf8(self.dict())

    def _truncate_alert(self, max_payload_length):
        """The json message is too large. Truncate it."""

        # Depending on the type of self.alert (PayloadAlert or string), we
        # access its truncatable contents as either self.alert.body or
        # self.alert.
        if isinstance(self.alert, PayloadAlert):
            body = self.alert.body
            self.alert.body = '!'
        else:
            body = self.alert
            # We replace the body with a 1-char string instead of the empty
            # string since the empty string is a special case in dict()
            self.alert = '!'

        json_with_1char = self.json()
        avail_length = max_payload_length - (len(json_with_1char) - 1)
        if avail_length < 1:
            raise PayloadTooLargeError(
                'The serialized payload is too long'
                ' even if we truncate the alert to one character:'
                ' {length} vs. the maximum of {max}'
                .format(length=len(json_with_1char),
                        max=max_payload_length),
                json_with_1char
            )
        short_body = Payload._truncate_json(body, avail_length)
        if not short_body:
            raise PayloadTooLargeError(
                "Truncating body gave it length 0. Won't send empty alert.")

        if isinstance(self.alert, PayloadAlert):
            self.alert.body = short_body
        else:
            self.alert = short_body

    def _check_size(self, max_payload_length):
        payload = self.json()
        length = len(payload)
        if length > max_payload_length:
            raise PayloadTooLargeError(
                'The serialized payload is too long:'
                ' {length} vs. the maximum of {max}'
                .format(length=length, max=max_payload_length),
                payload
            )

    def __repr__(self):
        attrs = ("alert", "badge", "sound", "custom")
        args = ", ".join(["%s=%r" % (n, getattr(self, n)) for n in attrs])
        return "%s(%s)" % (self.__class__.__name__, args)

    @staticmethod
    def _to_json_utf8(value):
        """
        Produces a compact UTF-8 JSON string of the given Python value.
        """
        text = json.dumps(
            value,
            separators=(',', ':'),
            ensure_ascii=False
        )
        if isinstance(text, unicode):
            return text.encode('utf-8')
        else:
            assert isinstance(text, str)
            return text

    @staticmethod
    def _truncate_json(content, max_length):
        """
        Truncate a UTF-8 string so its JSON representation is at most
        'max_length' bytes.
        """
        assert max_length >= 0

        escaped = Payload._to_json_utf8(content)[1:-1]

        if len(escaped) <= max_length:
            return content

        # Idea borrowed from http://stackoverflow.com/questions/1809531
        escaped = escaped[:max_length] \
            .decode('utf-8', 'ignore') \
            .encode('utf-8')

        # Cut off the last character until it's valid JSON. This should take
        # care of escape sequences.
        while True:
            try:
                return json.loads('"' + escaped + '"').encode('utf-8')
            except ValueError:
                escaped = escaped[:-1]



class FeedbackConnection(APNsConnection):
    """
    A class representing a connection to the APNs Feedback server
    """
    def __init__(self, use_sandbox=False, **kwargs):
        super(FeedbackConnection, self).__init__(**kwargs)
        self.server = (
            'feedback.push.apple.com',
            'feedback.sandbox.push.apple.com')[use_sandbox]
        self.port = 2196

    def _chunks(self):
        buffer_size = 4096
        while 1:
            data = self.read(buffer_size, timeout=0.5)
            yield data
            if not data:
                break

    def items(self):
        """
        A generator that yields (token_hex, fail_time) pairs retrieved from
        the APNs feedback server
        """
        buff = ''
        for chunk in self._chunks():
            buff += chunk

            # Quit if there's no more data to read
            if not buff:
                break

            # Sanity check: after a socket read we should always have at least
            # 6 bytes in the buffer
            if len(buff) < 6:
                break

            while len(buff) > 6:
                token_length = APNs.unpacked_ushort_big_endian(buff[4:6])
                bytes_to_read = 6 + token_length
                if len(buff) >= bytes_to_read:
                    fail_time_unix = APNs.unpacked_uint_big_endian(buff[0:4])
                    fail_time = datetime.utcfromtimestamp(fail_time_unix)
                    token = b2a_hex(buff[6:bytes_to_read])

                    yield (token, fail_time)

                    # Remove data for current token from buffer
                    buff = buff[bytes_to_read:]
                else:
                    # break out of inner while loop - i.e. go and fetch
                    # some more data and append to buffer
                    break


class Notification(object):
    def __init__(self, token_hex, payload, identifier=0, expiry=None):
        assert all(c in string.hexdigits for c in token_hex)
        assert len(token_hex) == 64

        self.token_hex = token_hex
        self.payload = payload
        self.identifier = identifier

        if expiry is None:
            self.expiry = datetime.now() + timedelta(30)
        else:
            self.expiry = expiry

    def get_binary(self):
        """
        Takes a token as a hex string and a payload as a Python dict and sends
        the notification
        """
        identifier_bin = pack('>I', self.identifier)
        expiry_bin = APNs.packed_uint_big_endian(int(mktime(self.expiry.timetuple())))
        token_bin = a2b_hex(self.token_hex)
        token_length_bin = APNs.packed_ushort_big_endian(len(token_bin))
        payload_json = self.payload.json()
        payload_length_bin = APNs.packed_ushort_big_endian(len(payload_json))

        notification = (
            '\x01' + identifier_bin + expiry_bin
            + token_length_bin + token_bin
            + payload_length_bin + payload_json
        )

        return notification

    def __repr__(self):
        return '<%s to %s id:%d>' % (
            repr(self.payload), self.token_hex, self.identifier
        )


class GatewayConnection(APNsConnection):
    """
    A class that represents a connection to the APNs gateway server

    This class will guarantee that well-formed notifications will
    arrive at their destination.

    Read http://redth.info/the-problem-with-apples-push-notification-ser/
    for a detailed description of the problem and the solution,
    implemented below.

    """
    def __init__(self, use_sandbox=False, **kwargs):
        super(GatewayConnection, self).__init__(**kwargs)
        self.server = (
            'gateway.push.apple.com',
            'gateway.sandbox.push.apple.com')[use_sandbox]
        self.port = 2195
        self.next_identifier = 0
        self.failed_notifications = []
        self.in_flight_notifications = []

    def flush(self):
        """
        Check for all notifications if they were correctly sent.

        If this method is not called after your batch of
        notifications there might be notifications that
        did not arrive at their destination.

        If for example a notification somewhere in the middle
        of your batch is corrupted (see the response dictionary
        below for a list of possible problems)
        it is possible that that notification
        AND ALL NOTIFICATIONS AFTER IT will be discarded by Apple.

        """
        if len(self.in_flight_notifications):
            while self._check_for_errors(timeout=1):
                pass

        # If the APN server has no error codes left to tell us we
        # can assume that all in-flight notifications have arrived
        self.in_flight_notifications = []

    def _check_for_errors(self, timeout=0):
        """
        Try to read error codes from the APNS gateway server.

        This tells us which notification failed, which succeeded
        (all notifications sent before the failed notification)
        and which need to be resent (all notifications sent after
        the failed notification)

        Will return a boolean that indicates if it sent out new notifications.

        """
        resent_notifications = False
        try:
            error_response = self.read(6, timeout=timeout)
            if not error_response:
                logger.info("Socket EOF")
                status = 999
                identifier = None
            else:
                logger.info("Got error_response")
                # command = error_response[0]
                status = ord(error_response[1])
                identifier, = unpack('>I', error_response[2:6])

            if status > 0:
                self._disconnect()  # Make sure we're ready for next send.

            in_flight = self.in_flight_notifications

            # Every notification in in_flight will either succeeded,
            # fail or be marked for resending
            # We can start afresh with the list of in flight notifications
            self.in_flight_notifications = []

            needs_resending = []

            # Check for all previously sent notifications
            # if they arrived or not
            for notification in in_flight:
                if identifier and notification.identifier < identifier:
                    # This notification was *before* the problematic
                    # notification. We can assume it was sent successfully
                    # and don't have to do anything with it anymore
                    pass
                elif identifier and notification.identifier == identifier:
                    if status > 0:
                        # This was the notification that tripped up
                        # the APN server. Save it to a list of failed
                        # notifications so that the API user can process
                        # them somehow
                        response = {
                            1: 'Processing error',
                            2: 'Missing device token',
                            3: 'Missing topic',
                            4: 'Missing payload',
                            5: 'Invalid token size',
                            6: 'Invalid topic size',
                            7: 'Invalid payload size',
                            8: 'Invalid token'
                        }.get(status, 'Unknown Error')

                        notification.fail_reason = (status, response)

                        self.failed_notifications.append(notification)
                else:
                    if status > 0:
                        # This notification was sent *after*
                        # the problematic notification We can assume
                        # that it was not sent and needs to be resent.
                        needs_resending.append(notification)
                    else:
                        # Unless, off course, it was not problematic at all
                        # and Apple sends an "Error" that no errors were
                        # encountered (status code 0) In that case we still
                        # don't know the fate of the notification and have
                        # to put it back in-flight
                        self.in_flight_notifications.append(notification)

            for notification in needs_resending:
                self.send(notification)
                resent_notifications = True

        except (SSLError, timeout) as ex:
            # SSL throws SSLError instead of timeout,
            #  see http://bugs.python.org/issue10272
            # Timeouts are OK - don't reconnect
            logger.info("Threw exception: %s", ex)

        return resent_notifications

    def send_notification(self, token_hex, payload, expiry=None):
        self.send(Notification(token_hex, payload, expiry))

    def send(self, notification):
        notification.identifier = self.next_identifier
        self.next_identifier += 1

        try: # Connection might have been closed
            self.write(notification.get_binary())
            self.in_flight_notifications.append(notification)
        except:
            # Prepare to reconnect.
            self._disconnect()
            raise
        else:
            self._check_for_errors()
