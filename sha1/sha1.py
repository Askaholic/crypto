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
    K = [
        0x5A827999,
        0x6ED9EBA1,
        0x8F1BBCDC,
        0xCA62C1D6
    ]

    def __init__(self, message):
        self.message = message
        if isinstance(message, str):
            self.message = self.message.encode()

    def digest(self):
        self._initialize_h()
        self._compute_hash(self.message)

        return self._get_hash()

    def _initialize_h(self):
        self.h = [
            0x67452301,
            0xEFCDAB89,
            0x98BADCFE,
            0x10325476,
            0xC3D2E1F0
        ]

    def _compute_hash(self, message):
        message = self._pad_message(message)
        for block in self._blocks_of(message):
            self._process_block(block)

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
            W[i] = struct.unpack('>I', block[i * 4: i * 4 + 4])[0]

        for t in range(16, 80):
            W[t] = self._leftrotate(W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16], 1)

        for t in range(80):
            temp = 0xFFFFFFFF & (self._leftrotate(A, 5) + self._f(t, B, C, D) + E + W[t] + self._get_K(t))
            E = D
            D = C
            C = self._leftrotate(B, 30)
            B = A
            A = temp

        self._update_hash(A, B, C, D, E)

    def _f(self, t, B, C, D):
        assert t >= 0 and t <= 80

        if t < 20:
            return (B & C) | ((~ B) & D) & 0xFFFFFFFF
        if t < 40:
            return B ^ C ^ D & 0xFFFFFFFF
        if t < 60:
            return (B & C) | (B & D) | (C & D) & 0xFFFFFFFF
        if t < 80:
            return B ^ C ^ D & 0xFFFFFFFF

    def _update_hash(self, A, B, C, D, E):
        self.h[0] = (self.h[0] + A) & 0xFFFFFFFF
        self.h[1] = (self.h[1] + B) & 0xFFFFFFFF
        self.h[2] = (self.h[2] + C) & 0xFFFFFFFF
        self.h[3] = (self.h[3] + D) & 0xFFFFFFFF
        self.h[4] = (self.h[4] + E) & 0xFFFFFFFF

    def _blocks_of(self, message):
        length = len(message)
        assert (length % 64 == 0)

        i = 0
        while i < length:
            yield message[i: i + 64]
            i += 64

    def _leftrotate(self, a, amt):
        return ((a << amt) & 0xFFFFFFFF) | (a >> (32 - amt))

    def _get_K(self, t):
        return SHA1.K[t // 20]

    def _get_hash(self):
        return b''.join([struct.pack('>I', h) for h in self.h])
