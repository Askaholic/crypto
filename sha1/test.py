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

if __name__ == '__main__':
    unittest.main()
