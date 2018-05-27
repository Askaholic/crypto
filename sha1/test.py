# sha1/test.py
# Rohan Weeden
# Created: May 23, 2018

# Unit tests for sha1 algorithm

import unittest.main
from unittest import TestCase
from sha1 import sha1, SHA1, sha1_extend
from binascii import hexlify
import struct
import os


class SHA1TestCase(TestCase):

    def test_dummy(self):
        self.assertTrue(True)

    def test_empty_string(self):
        h = hexlify(sha1(b''))
        self.assertEqual(h, b'da39a3ee5e6b4b0d3255bfef95601890afd80709')

    def test_1(self):
        h = hexlify(sha1(b'The quick brown fox jumps over the lazy dog'))
        self.assertEqual(h, b'2fd4e1c67a2d28fced849ee1bb76e7391b93eb12')

    def test_2(self):
        h = hexlify(sha1(b'The quick brown fox jumps over the lazy cog'))
        self.assertEqual(h, b'de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3')

    def test_length_extension(self):
        secret = os.urandom(10)
        known_data = b'Don\'t extend me bro!'
        legit_hash = sha1(secret + known_data)

        new_hash, extended_message = sha1_extend(legit_hash, known_data, b' Ha! Get extended bro!', len(secret))
        self.assertEqual(new_hash, sha1(secret + extended_message))

    def test_length_extension_2(self):
        legit_hash = sha1('')

        (new_hash, extended_message) = sha1_extend(legit_hash, b'', b' Ha! Get extended bro!', 0)
        self.assertEqual(new_hash, sha1(b'' + extended_message))


class SHA1InternalsTestCase(TestCase):
    def test_padding_length(self):
        l = 40
        m = b'A' * l
        new_m = SHA1.pad_message(m)
        self.assertEqual(m, new_m[:l])
        self.assertEqual(len(new_m) % 64, 0)

    def test_padding_length_2(self):
        l = 64
        m = b'A' * l
        new_m = SHA1.pad_message(m)
        self.assertEqual(m, new_m[:l])
        self.assertEqual(len(new_m) % 64, 0)

    def test_padding_message_length_field(self):
        l = 40
        m = b'A' * l
        new_m = SHA1.pad_message(m)
        self.assertEqual(m, new_m[:l])
        self.assertEqual(struct.unpack('>Q', new_m[-8:])[0], len(m) * 8)

    def test_padding_message_length_field_2(self):
        l = 0xFFFF
        m = b'A' * l
        new_m = SHA1.pad_message(m)
        self.assertEqual(m, new_m[:l])
        self.assertEqual(struct.unpack('>Q', new_m[-8:])[0], len(m) * 8)

    def test_padding_1(self):
        m = b'abcde'
        new_m = SHA1.pad_message(m)
        correct_padded_message = b'abcde\x80' + b'\x00' * 57 + b'\x28'
        self.assertEqual(m, new_m[:len(m)])
        self.assertEqual(new_m, correct_padded_message)

    def test_blocks_of(self):
        message = b''.join([str(chr((i + 0x30) % 0x7f)).encode() for i in range(64 * 10)])
        block_list = []
        for block in SHA1.blocks_of(message):
            with self.subTest(block=block):
                self.assertEqual(len(block), 64)
            block_list.append(block)

        self.assertEqual(message, b''.join(block_list))

    def test_leftrotate(self):
        self.assertEqual(0xfe0154ab, SHA1.leftrotate(0xff00aa55, 1))

    def test_f_1(self):
        self.assertEqual(0, SHA1.f(11, 0xFFFFFFFF, 0, 0xDEADBEEF))

    def test_f_2(self):
        self.assertEqual(0, SHA1.f(23, 0xBEADF00D, 0x60004EE2, 0xDEADBEEF))

    def test_f_3(self):
        self.assertEqual(0, SHA1.f(53, 0, 0, 0))

    def test_f_4(self):
        self.assertEqual(0, SHA1.f(79, 0xBEADF00D, 0xDEADBEEF, 0x60004EE2))

if __name__ == '__main__':
    unittest.main()
