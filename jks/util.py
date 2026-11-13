# vim: set et ai ts=4 sts=4 sw=4:
from __future__ import print_function
import textwrap
import base64
import struct

from pyasn1.codec.ber import decoder
from pyasn1.error import PyAsn1Error, SubstrateUnderrunError
from pyasn1.type import univ
from pyasn1_modules import rfc5208, rfc3447, rfc5915, rfc2459

b8 = struct.Struct('>Q')
b4 = struct.Struct('>L') # unsigned
b2 = struct.Struct('>H')
b1 = struct.Struct('B') # unsigned

py23basestring = ("".__class__, u"".__class__) # useful for isinstance checks

RSA_ENCRYPTION_OID = (1,2,840,113549,1,1,1)
DSA_OID            = (1,2,840,10040,4,1)       # identifier for DSA public/private keys; see RFC 3279, section 2.2.2 (e.g. in PKCS#8 PrivateKeyInfo or X.509 SubjectPublicKeyInfo)
DSA_WITH_SHA1_OID  = (1,2,840,10040,4,3)       # identifier for the DSA signature algorithm; see RFC 3279, section 2.3.2 (e.g. in X.509 signatures)
RSA_PSS_OID        = (1,2,840,113549,1,1,10)
EC_PUBLIC_KEY_OID  = (1,2,840,10045,2,1)
DH_OID             = (1,2,840,113549,1,3,1)
ED25519_OID        = (1,3,101,112)
ED448_OID          = (1,3,101,113)
X25519_OID         = (1,3,101,110)
X448_OID           = (1,3,101,111)

class KeystoreException(Exception):
    """Superclass for all pyjks exceptions."""
    pass
class KeystoreSignatureException(KeystoreException):
    """Signifies that the supplied password for a keystore integrity check is incorrect."""
    pass
class DuplicateAliasException(KeystoreException):
    """Signifies that duplicate aliases were encountered in a keystore."""
    pass
class NotYetDecryptedException(KeystoreException):
    """
    Signifies that an attribute of a key store entry can not be accessed because the entry has not yet been decrypted.

    By default, the keystore ``load`` and ``loads`` methods automatically try to decrypt all key entries using the store password.
    Any keys for which that attempt fails are returned undecrypted, and will raise this exception when its attributes are accessed.

    To resolve, first call decrypt() with the correct password on the entry object whose attributes you want to access.
    """
    pass
class BadKeystoreFormatException(KeystoreException):
    """Signifies that a structural error was encountered during key store parsing."""
    pass
class BadDataLengthException(KeystoreException):
    """Signifies that given input data was of wrong or unexpected length."""
    pass
class BadPaddingException(KeystoreException):
    """Signifies that bad padding was encountered during decryption."""
    pass
class BadHashCheckException(KeystoreException):
    """Signifies that a hash computation did not match an expected value."""
    pass
class DecryptionFailureException(KeystoreException):
    """Signifies failure to decrypt a value."""
    pass
class UnsupportedKeystoreVersionException(KeystoreException):
    """Signifies an unexpected or unsupported keystore format version."""
    pass
class UnexpectedJavaTypeException(KeystoreException):
    """Signifies that a serialized Java object of unexpected type was encountered."""
    pass
class UnexpectedAlgorithmException(KeystoreException):
    """Signifies that an unexpected cryptographic algorithm was used in a keystore."""
    pass
class UnexpectedKeyEncodingException(KeystoreException):
    """Signifies that a key was stored in an unexpected format or encoding."""
    pass
class UnsupportedKeystoreTypeException(KeystoreException):
    """Signifies that the keystore was an unsupported type."""
    pass
class UnsupportedKeystoreEntryTypeException(KeystoreException):
    """Signifies that the keystore entry was an unsupported type."""
    pass
class UnsupportedKeyFormatException(KeystoreException):
    """Signifies that the key format was an unsupported type."""
    pass


def der_decode_exact(data, asn1Spec=None):
    """
    Decodes exactly one DER value and rejects both malformed input and any
    trailing bytes after the first encoded value.

    This is intentionally stricter than pyasn1's decoder defaults: trusting
    an outer checksum or a successful prefix parse must not make a value
    usable when the remaining bytes hold another object or arbitrary data.

    :raises BadKeystoreFormatException: If the data is truncated, malformed,
      or contains trailing bytes after a complete object.
    """
    try:
        value, rest_of_data = decoder.decode(data, asn1Spec=asn1Spec)
    except PyAsn1Error as e:
        error = BadKeystoreFormatException("Malformed DER data: %s" % str(e))
        error.__cause__ = e
        raise error

    if rest_of_data:
        raise BadKeystoreFormatException("Malformed DER data: found %d trailing byte(s) after a complete object" % len(rest_of_data))
    return value


def decode_pkcs8_private_key_info(data):
    """
    Parse a PKCS#8 PrivateKeyInfo and verify that its required members were
    actually present in the encoding, not just schema placeholders.

    :raises BadKeystoreFormatException: If the structure is truncated or
      otherwise incomplete.
    """
    private_key_info = der_decode_exact(data, rfc5208.PrivateKeyInfo())

    try:
        version = int(private_key_info['version'])
    except (PyAsn1Error, TypeError, ValueError):
        raise BadKeystoreFormatException("Malformed PKCS#8 private key: missing or invalid version")
    if version not in (0, 1):
        raise BadKeystoreFormatException("Malformed PKCS#8 private key: unsupported version %r" % version)

    try:
        algorithm = private_key_info['privateKeyAlgorithm']['algorithm'].asTuple()
        encoded_key = private_key_info['privateKey'].asOctets()
    except (PyAsn1Error, TypeError, ValueError):
        raise BadKeystoreFormatException("Malformed PKCS#8 private key: missing algorithm or key material")

    if not algorithm:
        raise BadKeystoreFormatException("Malformed PKCS#8 private key: empty algorithm identifier")
    if not private_key_info['privateKeyAlgorithm']['algorithm'].isValue or not private_key_info['privateKey'].isValue:
        raise BadKeystoreFormatException("Malformed PKCS#8 private key: incomplete algorithm or key material")
    if not encoded_key:
        raise BadKeystoreFormatException("Malformed PKCS#8 private key: empty private key material")

    validate_private_key_encoding(algorithm, encoded_key)

    return private_key_info, algorithm, encoded_key


def validate_private_key_encoding(algorithm_oid, encoded_key):
    """
    Verify that the private key bytes inside a PKCS#8 PrivateKeyInfo match
    the algorithm identifier and are completely consumable.

    For algorithms with a defined private-key DER structure this checks the
    inner structure using an algorithm-specific ASN.1 schema; unsupported
    algorithm identifiers are rejected rather than treated as usable keys.

    :raises UnexpectedAlgorithmException: If the algorithm is unsupported.
    :raises UnexpectedKeyEncodingException: If the inner key encoding does
      not match the algorithm.
    :raises BadKeystoreFormatException: If the inner key data is malformed
      or followed by trailing bytes.
    """
    if algorithm_oid in (RSA_ENCRYPTION_OID, RSA_PSS_OID):
        # PKCS#1 RSAPrivateKey. A PSS key carries the same RSAPrivateKey
        # structure in PKCS#8.
        _check_der_key_structure(encoded_key, rfc3447.RSAPrivateKey(), "RSA")
        return

    if algorithm_oid == DSA_OID:
        # PKCS#8 stores DSA private keys as an ASN.1 INTEGER (x).
        _check_der_key_structure(encoded_key, univ.Integer(), "DSA")
        return

    if algorithm_oid == EC_PUBLIC_KEY_OID:
        _check_der_key_structure(encoded_key, rfc5915.ECPrivateKey(), "EC")
        return

    if algorithm_oid in (ED25519_OID, ED448_OID, X25519_OID, X448_OID):
        # RFC 8410 stores the raw private key as an OCTET STRING payload;
        # the PKCS#8 layer already gives us those octets, so require the
        # usual sizes and no inner DER object.
        expected_sizes = {ED25519_OID: 32, ED448_OID: 57, X25519_OID: 32, X448_OID: 56}
        if len(encoded_key) != expected_sizes[algorithm_oid]:
            raise BadKeystoreFormatException("Malformed private key: expected %d bytes for algorithm OID %s, found %d" % \
                                             (expected_sizes[algorithm_oid], algorithm_oid, len(encoded_key)))
        return

    if algorithm_oid == DH_OID:
        raise UnexpectedKeyEncodingException("DH private key encoding is not supported")

    raise UnexpectedAlgorithmException("Unsupported private key algorithm OID: %s" % (algorithm_oid,))


def _check_der_key_structure(encoded_key, asn1Spec, algorithm_family):
    """
    Check that inner private key bytes are one complete DER object of the
    expected algorithm-specific schema.

    Truncation and trailing bytes are corruption (BadKeystoreFormatException).
    A complete, differently-tagged object is an unsupported key encoding
    (UnexpectedKeyEncodingException).
    """
    try:
        value, rest_of_data = decoder.decode(encoded_key, asn1Spec=asn1Spec)
    except SubstrateUnderrunError as e:
        raise BadKeystoreFormatException("Malformed %s private key: truncated DER data (%s)" % (algorithm_family, str(e)))
    except PyAsn1Error as e:
        raise UnexpectedKeyEncodingException("Private key material is not a valid %s private key: %s" % (algorithm_family, str(e)))

    if rest_of_data:
        raise BadKeystoreFormatException("Malformed %s private key: found %d trailing byte(s) after a complete key object" % (algorithm_family, len(rest_of_data)))
    return value


def normalize_public_key_algorithm(algorithm_name):
    """
    Map a Java key algorithm name to its canonical family name.

    Returns ``None`` when the name is unknown.
    """
    if not algorithm_name:
        return None
    normalized = str(algorithm_name).upper().replace("-", "").replace("_", "")
    if normalized == "RSA" or normalized.startswith("RSASSA"):
        return "RSA"
    if normalized == "DSA":
        return "DSA"
    if normalized in ("EC", "ECDSA"):
        return "EC"
    if normalized in ("ED25519", "ED448", "EDDSA"):
        return "EDDSA"
    if normalized in ("X25519", "X448", "XDH"):
        return "XDH"
    if normalized in ("DH", "DIFFIEHELLMAN"):
        return "DH"
    if normalized == "AES":
        return "AES"
    if normalized in ("DES", "DESEDE", "TRIPLEDES", "3DES"):
        return "DES"
    return None


def public_key_algorithm_family(algorithm_oid):
    """Return the canonical key family for a public/private key OID."""
    if algorithm_oid in (RSA_ENCRYPTION_OID, RSA_PSS_OID):
        return "RSA"
    if algorithm_oid == DSA_OID:
        return "DSA"
    if algorithm_oid == EC_PUBLIC_KEY_OID:
        return "EC"
    if algorithm_oid in (ED25519_OID, ED448_OID):
        return "EDDSA"
    if algorithm_oid in (X25519_OID, X448_OID):
        return "XDH"
    if algorithm_oid == DH_OID:
        return "DH"
    return None


def validate_public_key_encoding(algorithm_oid, encoded_key):
    """
    Validate an X.509 SubjectPublicKeyInfo and ensure that the algorithm
    identifier is present, supported and consistent with the certificate's
    key material.

    :raises BadKeystoreFormatException: If the SPKI structure is incomplete
      or malformed.
    :raises UnexpectedAlgorithmException: If the algorithm is unsupported.
    :raises UnexpectedKeyEncodingException: If the key encoding does not
      match the algorithm.
    """
    spki = der_decode_exact(encoded_key, rfc2459.SubjectPublicKeyInfo())
    if not spki['algorithm']['algorithm'].isValue or not spki['subjectPublicKey'].isValue:
        raise BadKeystoreFormatException("Malformed X.509 public key: incomplete SubjectPublicKeyInfo")

    found_oid = spki['algorithm']['algorithm'].asTuple()
    if not found_oid:
        raise BadKeystoreFormatException("Malformed X.509 public key: empty algorithm identifier")
    if algorithm_oid is not None and found_oid != algorithm_oid:
        raise UnexpectedAlgorithmException("Public key algorithm OID %s does not match the entry's algorithm OID %s" % (found_oid, algorithm_oid))
    if public_key_algorithm_family(found_oid) is None:
        raise UnexpectedAlgorithmException("Unsupported public key algorithm OID: %s" % (found_oid,))

    public_key = bitstring_to_bytes(spki['subjectPublicKey'])
    if not public_key:
        raise UnexpectedKeyEncodingException("Malformed X.509 public key: empty subject public key")

    return spki, found_oid, public_key

class AbstractKeystore(object):
    """
    Abstract superclass for keystores.
    """
    def __init__(self, store_type, entries):
        self.store_type = store_type  #: A string indicating the type of keystore that was loaded.
        self.entries = dict(entries)  #: A dictionary of all entries in the keystore, mapped by alias.

    @classmethod
    def load(cls, filename, store_password, try_decrypt_keys=True):
        """
        Convenience wrapper function; reads the contents of the given file
        and passes it through to :func:`loads`. See :func:`loads`.
        """
        with open(filename, 'rb') as file:
            input_bytes = file.read()
            ret = cls.loads(input_bytes,
                            store_password,
                            try_decrypt_keys=try_decrypt_keys)
        return ret

    def save(self, filename, store_password):
        """
        Convenience wrapper function; calls the :func:`saves` 
        and saves the content to a file.
        """
        with open(filename, 'wb') as file:
            keystore_bytes = self.saves(store_password)
            file.write(keystore_bytes)

    @classmethod
    def _read_utf(cls, data, pos, kind=None):
        """
        :param kind: Optional; a human-friendly identifier for the kind of UTF-8 data we're loading (e.g. is it a keystore alias? an algorithm identifier? something else?).
                     Used to construct more informative exception messages when a decoding error occurs.
        """
        if pos < 0 or pos + 2 > len(data):
            raise BadKeystoreFormatException("Unexpected end of data while reading %s length" % (kind or "data"))
        size = b2.unpack_from(data, pos)[0]
        pos += 2
        if pos + size > len(data):
            raise BadKeystoreFormatException("Unexpected end of data while reading %s; found %d bytes, expected %d" % \
                                             (kind or "data", len(data) - pos, size))
        try:
            return data[pos:pos+size].decode('utf-8'), pos+size
        except (UnicodeEncodeError, UnicodeDecodeError) as e:
            raise BadKeystoreFormatException(("Failed to read %s, contains bad UTF-8 data: %s" % (kind, str(e))) if kind else \
                                             ("Encountered bad UTF-8 data: %s" % str(e)))

    @classmethod
    def _read_data(cls, data, pos):
        if pos < 0 or pos + 4 > len(data):
            raise BadKeystoreFormatException("Unexpected end of data while reading data length")
        size = b4.unpack_from(data, pos)[0]
        pos += 4
        if pos + size > len(data):
            raise BadKeystoreFormatException("Unexpected end of data while reading data; found %d bytes, expected %d" % \
                                             (len(data) - pos, size))
        return data[pos:pos+size], pos+size

    @classmethod
    def _write_utf(cls, text):
        encoded_text = text.encode('utf-8')
        size = len(encoded_text)
        result = b2.pack(size)
        result += encoded_text
        return result

    @classmethod
    def _write_data(cls, data):
        size = len(data)
        result = b4.pack(size)
        result += data
        return result

class AbstractKeystoreEntry(object):
    """Abstract superclass for keystore entries."""
    def __init__(self, **kwargs):
        super(AbstractKeystoreEntry, self).__init__()
        self.store_type = kwargs.get("store_type")
        self.alias = kwargs.get("alias")
        self.timestamp = kwargs.get("timestamp")

    @classmethod
    def new(cls, alias):
        """
        Helper function to create a new KeyStoreEntry.
        """
        raise NotImplementedError("Abstract method")

    def is_decrypted(self):
        """
        Returns ``True`` if the entry has already been decrypted, ``False`` otherwise.
        """
        raise NotImplementedError("Abstract method")

    def decrypt(self, key_password):
        """
        Decrypts the entry using the given password. Has no effect if the entry has already been decrypted.

        :param str key_password: The password to decrypt the entry with.
        :raises DecryptionFailureException: If the entry could not be decrypted using the given password.
        :raises UnexpectedAlgorithmException: If the entry was encrypted with an unknown or unexpected algorithm
        """
        raise NotImplementedError("Abstract method")

    def encrypt(self, key_password):
        """
        Encrypts the entry using the given password, so that it can be saved.

        :param str key_password: The password to encrypt the entry with.
        """
        raise NotImplementedError("Abstract method")

def as_hex(ba):
    return "".join("{:02x}".format(b) for b in bytearray(ba))

def as_pem(der_bytes, type):
    result = "-----BEGIN %s-----\n" % type
    result += "\n".join(textwrap.wrap(base64.b64encode(der_bytes).decode('ascii'), 64))
    result += "\n-----END %s-----" % type
    return result

def bitstring_to_bytes(bitstr):
    """
    Converts a pyasn1 univ.BitString instance to byte sequence of type 'bytes'.
    The bit string is interpreted big-endian and is left-padded with 0 bits to form a multiple of 8.
    """
    bitlist = list(bitstr)
    bits_missing = (8 - len(bitlist) % 8) % 8
    bitlist = [0]*bits_missing + bitlist # pad with 0 bits to a multiple of 8
    result = bytearray()
    for i in range(0, len(bitlist), 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bitlist[i+j]
        result.append(byte)
    return bytes(result)

def xor_bytearrays(a, b):
    return bytearray([x^y for x,y in zip(a,b)])

def print_pem(der_bytes, type):
    print(as_pem(der_bytes, type))

def pkey_as_pem(pk):
    if pk.algorithm_oid == RSA_ENCRYPTION_OID:
        return as_pem(pk.pkey, "RSA PRIVATE KEY")
    else:
        return as_pem(pk.pkey_pkcs8, "PRIVATE KEY")

def strip_pkcs5_padding(m):
    """
    Drop PKCS5 padding:  8-(||M|| mod 8) octets each with value 8-(||M|| mod 8)
    Note: ideally we would use pycrypto for this, but it doesn't provide padding functionality and the project is virtually dead at this point.
    """
    return strip_pkcs7_padding(m, 8)

def strip_pkcs7_padding(m, block_size):
    """
    Same as PKCS#5 padding, except generalized to block sizes other than 8.
    """
    if len(m) < block_size or len(m) % block_size != 0:
        raise BadPaddingException("Unable to strip padding: invalid message length")

    m = bytearray(m) # py2/3 compatibility: always returns individual indexed elements as ints
    last_byte = m[-1]
    # the <last_byte> bytes of m must all have value <last_byte>, otherwise something's wrong
    if (last_byte <= 0 or last_byte > block_size) or (m[-last_byte:] != bytearray([last_byte])*last_byte):
        raise BadPaddingException("Unable to strip padding: invalid padding found")

    return bytes(m[:-last_byte]) # back to 'str'/'bytes'

def add_pkcs7_padding(m, block_size):
    if block_size <= 0 or block_size > 255:
        raise ValueError("Invalid block size")

    m = bytearray(m)
    num_padding_bytes = block_size - (len(m) % block_size)
    m = m + bytearray([num_padding_bytes]*num_padding_bytes)
    return bytes(m)
