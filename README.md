# Askaholic Crypto
This project is meant to help me learn how the implementations of common
cryptographic algorithms work (SHA family in particular). These implementations
are likely unpolished, bug ridden and extremely slow... So I would not recommend
using them.

## Checklist
- [x] SHA1
- [ ] SHA256
- [ ] SHA512

- [x] SHA1 length extension

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

| Parameters |                             |
|:----------:| --------------------------- |
| *message*  | Bytes-like object to digest |

**Returns**: Bytes-like digest

________________________________________________________________________________

## sha1_extend(digest, known_data, extension, secret_length)
Performs a length extension attack for the given signed message. For this attack
to work all you need is the digest of the original signed message, the public
(known) part of the message and the length of the secret used to sign the message.

|    Parameters   |                                                            |
|:---------------:| ---------------------------------------------------------- |
|     *digest*    | Bytes-like hash used to sign the message                   |
|   *known_data*  | Bytes-like public part of the message that has been signed |
|   *extension*   | Bytes-like data to append to the known data                |
| *secret_length* | The length of the secret (in bytes)                        |

**Returns**: A tuple containing the new digest and the extended public data. Both
are Bytes-like objects. Note that the extended data contains null byte padding,
and is not simply a concatenation of the known data and the extension.

#### Example
```python
secret = os.urandom(10)
known_data = b'Don\'t extend me bro!'
h1 = sha1(secret + known_data)

h2, ext = sha1_extend(h1, known_data, b'Totally bro', 10)
h2 == sha1(secret + ext)
# True
```
