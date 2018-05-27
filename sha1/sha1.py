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


def sha1_extend(digest, known_data, extension, secret_length):
    return SHA1Extender(digest, known_data, extension, secret_length).extend()


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
        message = SHA1.pad_message(message)
        for block in SHA1.blocks_of(message):
            self._process_block(block)

    @staticmethod
    def pad_message(message):
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
            W[t] = SHA1.leftrotate(W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16], 1)

        for t in range(80):
            temp = 0xFFFFFFFF & (SHA1.leftrotate(A, 5) + SHA1.f(t, B, C, D) + E + W[t] + SHA1.get_K(t))
            E = D
            D = C
            C = SHA1.leftrotate(B, 30)
            B = A
            A = temp

        self._update_hash(A, B, C, D, E)

    @staticmethod
    def f(t, B, C, D):
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

    @staticmethod
    def blocks_of(message):
        length = len(message)
        assert (length % 64 == 0)

        i = 0
        while i < length:
            yield message[i: i + 64]
            i += 64

    @staticmethod
    def leftrotate(a, amt):
        return ((a << amt) & 0xFFFFFFFF) | (a >> (32 - amt))

    @staticmethod
    def get_K(t):
        return SHA1.K[t // 20]

    def _get_hash(self):
        return b''.join([struct.pack('>I', h) for h in self.h])


class SHA1Extender(object):
    def __init__(self, digest, known_data, extension, secret_length):
        self.digest = digest
        self.known_data = known_data
        self.extension = extension
        self.secret_length = secret_length

    def extend(self):
        extended, num_blocks = self._prepare_new_message()
        new_digest = self._extend_padded_message(extended, num_blocks)

        return (new_digest, extended)

    def _prepare_new_message(self):
        original_length = self.secret_length + len(self.known_data)
        padding, padded_length = self._get_padding_for_message_length(original_length)
        known_padded = self.known_data + padding

        extended_data = known_padded + self.extension
        num_known_blocks = padded_length // 64
        return extended_data, num_known_blocks

    def _get_padding_for_message_length(self, length):
        padded = SHA1.pad_message(b'*' * length)
        return padded[length:], len(padded)

    def _extend_padded_message(self, extended_data, num_known_blocks):
        sha = SHA1(extended_data)
        # Initialize h to the old hash
        sha.h = [struct.unpack('>I', self.digest[i*4: (i*4) + 4])[0] for i in range(5)]

        # The value of the secret and old data doesn't matter because we already
        # have the digest of that data
        new_message = SHA1.pad_message(b'*' * self.secret_length + extended_data)
        for i, block in enumerate(SHA1.blocks_of(new_message)):
            # skip the blocks which are part of the old message
            if i < num_known_blocks:
                continue
            # Process the new blocks into the old digest
            sha._process_block(block)

        return sha._get_hash()
