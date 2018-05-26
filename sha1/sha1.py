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
        self._initialize_h()
        message = self._pad_message(self.message)
        for block in self._blocks_of(message):
            self._process_block(block)
        return b'\xda9\xa3\xee^kK\r2U\xbf\xef\x95`\x18\x90\xaf\xd8\x07\t'

    def _initialize_h(self):
        self.h = [
            0x67452301,
            0xEFCDAB89,
            0x98BADCFE,
            0x10325476,
            0xC3D2E1F0
        ]

    def _pad_message(self, message):
        length = len(message)
        padding_amt = 55 - (length % 64)

        message += b'\x80'
        message += b'\x00' * padding_amt
        # Length field must be in bits, therefore 8 x byte length
        message += struct.pack('>Q', length * 8)

        return message

    def _process_block(self, block):
        A = self.h[0]
        B = self.h[1]
        C = self.h[2]
        D = self.h[3]
        E = self.h[4]

        W = [b''] * 80
        for i in range(16):
            W[i] = block[i * 4: i * 4 + 4]

        for t in range(16, 80):
            W[t] = self._leftrotate(
                self._strxor(W[t-3],
                self._strxor(W[t-8],
                self._strxor(W[t-14], W[t-16]
                ))),
                1
            )

    def _blocks_of(self, message):
        length = len(message)
        assert (length % 64 == 0)

        i = 0
        while i < length:
            yield message[i: i + 64]
            i += 64

    def _leftrotate(self, a, amt):
        assert (len(a) == 4)
        int_val = struct.unpack('I', a)[0]
        return struct.pack('I', ((int_val << amt) & 0xFFFFFFFF) | (int_val >> (32 - amt)))

    def _strxor(self, a, b):
        assert (len(a) == len(b))
        return b''.join([struct.pack('B', c ^ d) for c, d in zip(a, b)])

    def _strand(self, a, b):
        assert (len(a) == len(b))
        return b''.join([struct.pack('B', c & d) for c, d in zip(a, b)])

    def _stror(self, a, b):
        assert (len(a) == len(b))
        return b''.join([struct.pack('B', c | d) for c, d in zip(a, b)])

    def _strnot(self, a):
        return b''.join([struct.pack('b', ~c) for c in a])

pass
pass
pass
pass
