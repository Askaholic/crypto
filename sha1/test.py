# sha1/test.py
# Rohan Weeden
# Created: May 23, 2018

# Unit tests for sha1 algorithm

import unittest.main
from unittest import TestCase
from sha1 import sha1, SHA1
from binascii import hexlify
import struct


class SHA1TestCase(TestCase):

    def test_dummy(self):
        self.assertTrue(True)

    def test_empty_string(self):
        h = hexlify(sha1(''))
        self.assertEqual(h, b'da39a3ee5e6b4b0d3255bfef95601890afd80709')

    def test_1(self):
        h = hexlify(sha1('The quick brown fox jumps over the lazy dog'))
        self.assertEqual(h, b'2fd4e1c67a2d28fced849ee1bb76e7391b93eb12')

    def test_2(self):
        h = hexlify(sha1('The quick brown fox jumps over the lazy cog'))
        self.assertEqual(h, b'de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3')


class SHA1InternalsTestCase(TestCase):
    def setUp(self):
        self.sha_obj = SHA1(b'')

    def test_padding_length(self):
        l = 40
        m = b'A' * l
        new_m = self.sha_obj._pad_message(m)
        self.assertEqual(m, new_m[:l])
        self.assertEqual(len(new_m) % 64, 0)

    def test_padding_length_2(self):
        l = 64
        m = b'A' * l
        new_m = self.sha_obj._pad_message(m)
        self.assertEqual(m, new_m[:l])
        self.assertEqual(len(new_m) % 64, 0)

    def test_padding_message_length_field(self):
        l = 40
        m = b'A' * l
        new_m = self.sha_obj._pad_message(m)
        self.assertEqual(m, new_m[:l])
        self.assertEqual(struct.unpack('>Q', new_m[-8:])[0], len(m) * 8)

    def test_padding_message_length_field_2(self):
        l = 0xFFFF
        m = b'A' * l
        new_m = self.sha_obj._pad_message(m)
        self.assertEqual(m, new_m[:l])
        self.assertEqual(struct.unpack('>Q', new_m[-8:])[0], len(m) * 8)

    def test_padding_1(self):
        m = b'abcde'
        new_m = self.sha_obj._pad_message(m)
        correct_padded_message = b'abcde\x80' + b'\x00' * 57 + b'\x28'
        self.assertEqual(m, new_m[:len(m)])
        self.assertEqual(new_m, correct_padded_message)

    def test_blocks_of(self):
        message = b''.join([str(chr((i + 0x30) % 0x7f)).encode() for i in range(64 * 10)])
        block_list = []
        for block in self.sha_obj._blocks_of(message):
            with self.subTest(block=block):
                self.assertEqual(len(block), 64)
            block_list.append(block)

        self.assertEqual(message, b''.join(block_list))

    def test_strxor(self):
        a = b'Hell'
        b = b'Worl'
        self.assertEqual(
            struct.pack('I', struct.unpack('I', a)[0] ^ struct.unpack('I', b)[0]),
            self.sha_obj._strxor(a, b)
        )


if __name__ == '__main__':
    unittest.main()
