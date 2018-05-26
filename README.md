# Askaholic Crypto
This project is meant to help me learn how the implementations of common
cryptographic algorithms work (SHA family in particular). These implementations
are likely unpolished, bug ridden and extremely slow... So I would not recommend
using them.

## Checklist
- [x] SHA1
- [ ] SHA256
- [ ] SHA512

- [ ] SHA1 Length extension

# Documentation
My interfaces use Python3 bytes-like objects for both the input parameter and
the return value. This means if you print the return value straight from the
hash function, it will not look like the usual string of hex characters. You can
convert to this format using `binascii.hexlify()`.
```python
from binascii import hexlify
from sha1 import sha1

hexdigest = hexlify(sha1(b'Bears. Beats. Battlestar Galactica.'))
print(hexdigest.decode())
# 06f7ea2480e76595befe7c9676604fff2e52d322
```

## sha1(message)
Implements the SHA1 algorithm from RFC 3174 <https://tools.ietf.org/html/rfc3174>.
Only supports message lengths that are multiples of 8 bits. Located in sha1.py.

Parameters: _message_ = Bytes-like object to digest

Returns: Bytes-like digest
