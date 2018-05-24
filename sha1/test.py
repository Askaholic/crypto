# sha1/test.py
# Rohan Weeden
# Created: May 23, 2018

# Unit tests for sha1 algorithm

import unittest.main
from unittest import TestCase
from sha1 import sha1
from binascii import hexlify


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

if __name__ == '__main__':
    unittest.main()
