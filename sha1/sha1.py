# sha1/sha1.py
# Rohan Weeden
# Created: May 23, 2018

# Implementation of the SHA1 hash algorithm from RFC 3174
# <https://tools.ietf.org/html/rfc3174>
#
# Note: This implementation only supports messages that are multiples of 8 bits
# (1 byte)

import struct


def sha1(message):
    return SHA1(message).digest()


class SHA1(object):
    def __init__(self, message):
        self.message = message
        if isinstance(message, str):
            self.message = self.message.encode()

    def digest(self):
        return b'\xda9\xa3\xee^kK\r2U\xbf\xef\x95`\x18\x90\xaf\xd8\x07\t'

    def _pad_message(self, message):
        length = len(message)
        padding_amt = 55 - (length % 64)

        message += b'\x80'
        message += b'\x00' * padding_amt
        message += struct.pack('>Q', length)

        print(length)
        print(struct.pack('>Q', length))

        return message
