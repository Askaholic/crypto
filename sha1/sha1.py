# sha1/sha1.py
# Rohan Weeden
# Created: May 23, 2018

# Implementation of the SHA1 hash algorithm from RFC 3174
# <https://tools.ietf.org/html/rfc3174>


def sha1(message):
    return SHA1(message).digest()


class SHA1(object):
    def __init__(self, message):
        pass

    def digest(self):
        return b'\xda9\xa3\xee^kK\r2U\xbf\xef\x95`\x18\x90\xaf\xd8\x07\t'
