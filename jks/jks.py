# vim: set et ai ts=4 sts=4 sw=4:
"""JKS/JCEKS file format decoder. Use in conjunction with PyOpenSSL
to translate to PEM, or load private key and certs directly into
openssl structs and wrap sockets.

Notes on Python2/3 compatibility:

Whereever possible, we rely on the 'natural' byte string
representation of each Python version, i.e. 'str' in Python2 and
'bytes' in Python3.

Python2.6+ aliases the 'bytes' type to 'str', so we can universally
write bytes(...) or b"" to get each version's natural byte string
representation.

The libraries we interact with are written to expect these natural
types in their respective Py2/Py3 versions, so this works well.

Things get slightly more complicated when we need to manipulate
individual bytes from a byte string. str[x] returns a 'str' in Python2
and an 'int' in Python3. You can't do 'int' operations on a 'str' and
vice-versa, so we need some form of common data type.  We use
bytearray() for this purpose; in both Python2 and Python3, this will
return individual elements as an 'int'.

"""

from __future__ import print_function
import struct
import ctypes
import hashlib
import javaobj
import os
import time
from pyasn1.codec.ber import encoder, decoder
from pyasn1_modules import rfc5208
from pyasn1_modules.rfc2459 import AlgorithmIdentifier
from pyasn1.type import univ, namedtype
from . import rfc2898
from . import sun_crypto
from .util import *

try:
    # javaobj-py3 0.4+ exposes the beans through the v1 subpackage (older
    # versions only have the top-level namespace).
    from javaobj.v1.beans import JavaClass, JavaObject, JavaString, JavaByteArray, JavaEnum
except ImportError:  # pragma: no cover - depends on installed javaobj version
    from javaobj import JavaClass, JavaObject, JavaString, JavaByteArray, JavaEnum

try:
    from StringIO import StringIO as BytesIO  # python 2
except ImportError:
    from io import BytesIO  # python3

__version_info__ = (20, 0, 1, 'dev')
__version__ = ".".join(str(x) for x in __version_info__ if str(x))

MAGIC_NUMBER_JKS = b4.pack(0xFEEDFEED)
MAGIC_NUMBER_JCEKS = b4.pack(0xCECECECE)
SIGNATURE_WHITENING = b"Mighty Aphrodite"


class TrustedCertEntry(AbstractKeystoreEntry):
    """Represents a trusted certificate entry in a JKS or JCEKS keystore."""

    def __init__(self, **kwargs):
        super(TrustedCertEntry, self).__init__(**kwargs)
        self.type = kwargs.get("type")
        """A string indicating the type of certificate. Unless in exotic applications, this is usually ``X.509``."""
        self.cert = kwargs.get("cert")
        """A byte string containing the actual certificate data. In the case of X.509 certificates, this is the DER-encoded
        X.509 representation of the certificate."""

    @classmethod
    def new(cls, alias, cert):
        """
        Helper function to create a new TrustedCertEntry.

        :param str alias: The alias for the Trusted Cert Entry
        :param str certs: The certificate, as a byte string.

        :returns: A loaded :class:`TrustedCertEntry` instance, ready
          to be placed in a keystore.
        """
        timestamp = int(time.time()) * 1000

        tke = cls(timestamp = timestamp,
                               # Alias must be lower case or it will corrupt the keystore for Java Keytool and Keytool Explorer
                               alias = alias.lower(),
                               cert = cert)
        return tke

    def is_decrypted(self):
        """Always returns ``True`` for this entry type."""
        return True

    def decrypt(self, key_password):
        """Does nothing for this entry type; certificates are inherently public data and are not stored in encrypted form."""
        return

    def encrypt(self, key_password):
        """Does nothing for this entry type; certificates are inherently public data and are not stored in encrypted form."""
        return

class PrivateKeyEntry(AbstractKeystoreEntry):
    """Represents a private key entry in a JKS or JCEKS keystore (e.g. an RSA or DSA private key)."""

    def __init__(self, **kwargs):
        super(PrivateKeyEntry, self).__init__(**kwargs)
        self.cert_chain = kwargs.get("cert_chain")
        """
        A list of tuples, representing the certificate chain associated with the private key. Each element of the list of a 2-tuple
        containing the following data:

            - ``[0]``: A string indicating the type of certificate. Unless in exotic applications, this is usually ``X.509``.
            - ``[1]``: A byte string containing the actual certificate data. In the case of X.509 certificates, this is the DER-encoded X.509 representation of the certificate.
        """

        self._encrypted = kwargs.get("encrypted")
        # The ciphertext as stored in (or explicitly prepared for) the
        # keystore. It is retained across decryption so that re-saving an
        # entry that was never explicitly re-encrypted does not silently
        # change its protection password.
        self._saved_encrypted = kwargs.get("encrypted")
        self._pkey = kwargs.get("pkey")
        self._pkey_pkcs8 = kwargs.get("pkey_pkcs8")
        self._algorithm_oid = kwargs.get("algorithm_oid")

    @classmethod
    def new(cls, alias, certs, key, key_format='pkcs8'):
        """
        Helper function to create a new PrivateKeyEntry.

        :param str alias: The alias for the Private Key Entry
        :param list certs: An list of certificates, as byte strings.
          The first one should be the one belonging to the private key,
          the others the chain (in correct order).
        :param str key: A byte string containing the private key in the
          format specified in the key_format parameter (default pkcs8).
        :param str key_format: The format of the provided private key.
          Valid options are pkcs8 or rsa_raw. Defaults to pkcs8.

        :returns: A loaded :class:`PrivateKeyEntry` instance, ready
          to be placed in a keystore.

        :raises UnsupportedKeyFormatException: If the key format is
          unsupported.
        """
        timestamp = int(time.time()) * 1000

        cert_chain = []
        for cert in certs:
            cert_chain.append(('X.509', cert))

        pke = cls(timestamp = timestamp,
                               # Alias must be lower case or it will corrupt the keystore for Java Keytool and Keytool Explorer
                               alias = alias.lower(),
                               cert_chain = cert_chain)

        if key_format == 'pkcs8':
            private_key_info = decoder.decode(key, asn1Spec=rfc5208.PrivateKeyInfo())[0]

            pke._algorithm_oid = private_key_info['privateKeyAlgorithm']['algorithm'].asTuple()
            pke.pkey = private_key_info['privateKey'].asOctets()
            pke.pkey_pkcs8 = key

        elif key_format == 'rsa_raw':
            pke._algorithm_oid = RSA_ENCRYPTION_OID

            # We must encode it to pkcs8
            private_key_info = rfc5208.PrivateKeyInfo()
            private_key_info.setComponentByName('version','v1')
            a = AlgorithmIdentifier()
            a.setComponentByName('algorithm', pke._algorithm_oid)
            a.setComponentByName('parameters', '\x05\x00')
            private_key_info.setComponentByName('privateKeyAlgorithm', a)
            private_key_info.setComponentByName('privateKey', key)

            pke.pkey_pkcs8 = encoder.encode(private_key_info, ifNotEmpty=True)
            pke.pkey = key

        else:
            raise UnsupportedKeyFormatException("Key Format '%s' is not supported" % key_format)

        return pke

    def __getattr__(self, name):
        if not self.is_decrypted():
            raise NotYetDecryptedException("Cannot access attribute '%s'; entry not yet decrypted, call decrypt() with the correct password first" % name)
        return self.__dict__['_' + name]

    def is_decrypted(self):
        return (not self._encrypted)

    def decrypt(self, key_password):
        """
        Decrypts the entry using the given password. Has no effect if the entry has already been decrypted.

        :param str key_password: The password to decrypt the entry with. If the entry was loaded from a JCEKS keystore,
                                 the password must not contain any characters outside of the ASCII character set.
        :raises DecryptionFailureException: If the entry could not be decrypted using the given password.
        :raises UnexpectedAlgorithmException: If the entry was encrypted with an unknown or unexpected algorithm
        :raise ValueError: If the entry was loaded from a JCEKS keystore and the password contains non-ASCII characters.
        """
        if self.is_decrypted():
            return

        encrypted_info = decoder.decode(self._encrypted, asn1Spec=rfc5208.EncryptedPrivateKeyInfo())[0]
        algo_id = encrypted_info['encryptionAlgorithm']['algorithm'].asTuple()
        algo_params = encrypted_info['encryptionAlgorithm']['parameters'].asOctets()
        encrypted_private_key = encrypted_info['encryptedData'].asOctets()

        plaintext = None
        try:
            if algo_id == sun_crypto.SUN_JKS_ALGO_ID:
                plaintext = sun_crypto.jks_pkey_decrypt(encrypted_private_key, key_password)

            elif algo_id == sun_crypto.SUN_JCE_ALGO_ID:
                if self.store_type != "jceks":
                    raise UnexpectedAlgorithmException("Encountered JCEKS private key protection algorithm in JKS keystore")
                # see RFC 2898, section A.3: PBES1 and definitions of AlgorithmIdentifier and PBEParameter
                params = decoder.decode(algo_params, asn1Spec=rfc2898.PBEParameter())[0]
                salt = params['salt'].asOctets()
                iteration_count = int(params['iterationCount'])
                plaintext = sun_crypto.jce_pbe_decrypt(encrypted_private_key, key_password, salt, iteration_count)
            else:
                raise UnexpectedAlgorithmException("Unknown %s private key protection algorithm: %s" % (self.store_type.upper(), algo_id))

        except (BadHashCheckException, BadPaddingException):
            raise DecryptionFailureException("Failed to decrypt data for private key '%s'; wrong password?" % self.alias)

        # at this point, 'plaintext' is a PKCS#8 PrivateKeyInfo (see RFC 5208)
        private_key_info = decoder.decode(plaintext, asn1Spec=rfc5208.PrivateKeyInfo())[0]
        key = private_key_info['privateKey'].asOctets()
        algorithm_oid = private_key_info['privateKeyAlgorithm']['algorithm'].asTuple()

        self._encrypted = None
        self._pkey = key
        self._pkey_pkcs8 = plaintext
        self._algorithm_oid = algorithm_oid

    def encrypt(self, key_password):
        """
        Encrypts the private key, so that it can be saved to a keystore.

        This will make it necessary to decrypt it again if it is going to be used later.
        Has no effect if the entry is already encrypted.

        :param str key_password: The password to encrypt the entry with.
        """
        if not self.is_decrypted():
            return

        encrypted = self._encrypt_pkcs8(key_password, use_jce=(self.store_type == 'jceks'))
        self._encrypted = encrypted
        self._saved_encrypted = encrypted
        self._pkey = None
        self._pkey_pkcs8 = None
        self._algorithm_oid = None

    def _encrypt_pkcs8(self, key_password, use_jce=False):
        """Builds an EncryptedPrivateKeyInfo for the plaintext key, without
        changing the entry itself.

        JCEKS stores protect private keys with PBEWithMD5AndTripleDES;
        JKS stores use the older JavaSoft key protection algorithm.
        """
        if use_jce:
            salt = os.urandom(8)
            encrypted_private_key = sun_crypto.jce_pbe_encrypt(self.pkey_pkcs8, key_password,
                                                               salt, SecretKeyEntry.SEAL_ITERATION_COUNT)
            params = rfc2898.PBEParameter()
            params.setComponentByName('salt', salt)
            params.setComponentByName('iterationCount', SecretKeyEntry.SEAL_ITERATION_COUNT)

            a = AlgorithmIdentifier()
            a.setComponentByName('algorithm', sun_crypto.SUN_JCE_ALGO_ID)
            a.setComponentByName('parameters', encoder.encode(params))
        else:
            encrypted_private_key = sun_crypto.jks_pkey_encrypt(self.pkey_pkcs8, key_password)

            a = AlgorithmIdentifier()
            a.setComponentByName('algorithm', sun_crypto.SUN_JKS_ALGO_ID)
            a.setComponentByName('parameters', '\x05\x00')

        epki = rfc5208.EncryptedPrivateKeyInfo()
        epki.setComponentByName('encryptionAlgorithm', a)
        epki.setComponentByName('encryptedData', encrypted_private_key)
        return encoder.encode(epki)

    def _encrypted_for_save(self, key_password, store_type=None):
        """Returns the encrypted private key bytes to write, without changing
        the entry.

        An entry that was loaded in encrypted form keeps its existing
        ciphertext, so it is never silently re-encrypted with the store
        password (even after the in-memory copy has been decrypted). A
        decrypted entry without prior ciphertext is encrypted for the
        resulting output only.
        """
        if self._saved_encrypted is not None:
            return self._saved_encrypted
        if not self.is_decrypted():
            return self._encrypted
        use_jce = (store_type if store_type is not None else self.store_type) == 'jceks'
        return self._encrypt_pkcs8(key_password, use_jce=use_jce)

    is_decrypted.__doc__ = AbstractKeystoreEntry.is_decrypted.__doc__


class SecretKeyEntry(AbstractKeystoreEntry):
    """Represents a secret (symmetric) key entry in a JCEKS keystore (e.g. an AES or DES key)."""

    # Compatibility identifiers of the serialized Java objects involved in a
    # JCEKS secret key entry. These are fixed by the Java serialization
    # format of the corresponding classes; see the comments in
    # KeyStore._read_secret_key for details.
    SEAL_ALGORITHM = "PBEWithMD5AndTripleDES"
    SEAL_ITERATION_COUNT = 20
    _SEALED_OBJECT_CLASS = "com.sun.crypto.provider.SealedObjectForKeyProtector"
    _SEALED_OBJECT_SUID = -3650226485480866989
    _JAVA_SEALED_OBJECT_CLASS = "javax.crypto.SealedObject"
    _JAVA_SEALED_OBJECT_SUID = 4482838265551344752
    _JAVA_SECRET_KEY_SPEC_CLASS = "javax.crypto.spec.SecretKeySpec"
    _JAVA_SECRET_KEY_SPEC_SUID = 6577238317307289933
    _JAVA_BYTE_ARRAY_CLASS = "[B"
    _JAVA_BYTE_ARRAY_SUID = -5984413125824719648

    def __init__(self, **kwargs):
        super(SecretKeyEntry, self).__init__(**kwargs)
        self._encrypted = kwargs.get("sealed_obj")
        # The exact serialized SealedObject bytes as encountered in (or
        # produced for) the keystore. Kept even after decryption, so that a
        # plain save writes an already-sealed entry back unchanged.
        self._sealed_bytes = kwargs.get("sealed_obj_bytes")
        self._inner_form = kwargs.get("inner_form")
        self._algorithm = kwargs.get("algorithm")
        self._key = kwargs.get("key")
        self._key_size = kwargs.get("key_size")

    @classmethod
    def new(cls, alias, algorithm, key, key_size=None, sealed_obj=None, key_password=None):
        """
        Helper function to create a new SecretKeyEntry.

        The returned entry is in decrypted form, unless a ``sealed_obj`` or
        a ``key_password`` is given. When it is saved to a keystore, its
        key is sealed with the store password (or with the password given
        to a preceding :meth:`encrypt` call).

        :param str alias: The alias for the Secret Key Entry
        :param str algorithm: The key algorithm (e.g. ``AES``, ``DES``,
          ``DESede`` or ``PBKDF2WithHmacSHA1``).
        :param str key: A byte string containing the raw secret key.
        :param int key_size: The key size in bits. Defaults to
          ``len(key) * 8``.
        :param sealed_obj: Optional; an already sealed Java object to use
          for this entry instead of sealing ``key`` on save. When given,
          the entry is returned in encrypted form and ``algorithm`` and
          ``key`` are ignored.
        :param str key_password: Optional; seal the new entry with this
          password immediately (equivalent to a follow-up call to
          :meth:`encrypt`). Must be a plain ASCII string.

        :returns: A loaded :class:`SecretKeyEntry` instance, ready
          to be placed in a keystore.
        """
        timestamp = int(time.time()) * 1000

        if isinstance(algorithm, JavaObject):
            # Also accept the positional order used by the earlier stub
            # signature new(alias, sealed_obj, algorithm, key, key_size).
            sealed_obj, algorithm, key, key_size = algorithm, key, key_size, sealed_obj
        elif isinstance(algorithm, bytes) and isinstance(key, py23basestring):
            # Also accept new(alias, key, algorithm[, key_size]).
            algorithm, key = key, algorithm

        if key_size is None:
            key_size = len(key) * 8

        if not isinstance(key, bytes):
            # bytearray/memoryview are accepted for convenience, but the
            # stored key must be an immutable byte string.
            key = bytes(bytearray(key))

        sk = cls(timestamp = timestamp,
                 # Alias must be lower case or it will corrupt the keystore for Java Keytool and Keytool Explorer
                 alias = alias.lower(),
                 algorithm = algorithm,
                 key = key,
                 key_size = key_size)

        if sealed_obj is not None:
            sk._adopt_sealed_object(sealed_obj)
            sk._algorithm = None
            sk._key = None
            sk._key_size = None
        elif key_password is not None:
            sk.encrypt(key_password)

        return sk

    def _adopt_sealed_object(self, sealed_obj):
        """Uses an existing Java SealedObject as this entry's encrypted form."""
        if not KeyStore._java_is_subclass(sealed_obj, "javax.crypto.SealedObject"):
            raise UnexpectedJavaTypeException("Unexpected sealed object type '%s'; not a subclass of javax.crypto.SealedObject" % sealed_obj.get_class().name)
        # Rebuild rather than re-dump the object: byte[] fields of a parsed
        # object hold plain byte strings, which the Java object marshaller
        # would otherwise write as block data instead of arrays.
        encoded_params = sealed_obj.encodedParams
        encrypted_content = sealed_obj.encryptedContent
        if not isinstance(encoded_params, bytes):
            encoded_params = KeyStore._java_bytestring(encoded_params)
        if not isinstance(encrypted_content, bytes):
            encrypted_content = KeyStore._java_bytestring(encrypted_content)
        top_class = sealed_obj.get_class()
        self._sealed_bytes = self._build_sealed_object(
            encoded_params, encrypted_content,
            str(sealed_obj.sealAlg), str(sealed_obj.paramsAlg),
            top_class.name, top_class.serialVersionUID)
        self._encrypted = sealed_obj

    def __getattr__(self, name):
        if not self.is_decrypted():
            raise NotYetDecryptedException("Cannot access attribute '%s'; entry not yet decrypted, call decrypt() with the correct password first" % name)
        return self.__dict__['_' + name]

    def is_decrypted(self):
        return (not self._encrypted)

    def decrypt(self, key_password):
        """
        Decrypts the entry using the given password. Has no effect if the entry has already been decrypted.

        :param str key_password: The password to decrypt the entry with. Must not contain any characters outside
                                 of the ASCII character set.
        :raises DecryptionFailureException: If the entry could not be decrypted using the given password.
        :raises UnexpectedAlgorithmException: If the entry was encrypted with an unknown or unexpected algorithm
        :raise ValueError: If the password contains non-ASCII characters.
        """
        if self.is_decrypted():
            return

        plaintext = None
        sealed_obj = self._encrypted
        seal_alg = str(sealed_obj.sealAlg)
        params_alg = str(sealed_obj.paramsAlg)
        encoded_params = sealed_obj.encodedParams
        encrypted_content = sealed_obj.encryptedContent
        if not isinstance(encoded_params, bytes):
            encoded_params = KeyStore._java_bytestring(encoded_params)
        if not isinstance(encrypted_content, bytes):
            encrypted_content = KeyStore._java_bytestring(encrypted_content)

        #In python 2.7.x many issues have occured where comparison between 'JavaString' & 'str' have failed.
        #https://github.com/kurtbrose/pyjks/issues/60, https://github.com/kurtbrose/pyjks/issues/47
        #type cast sealed_obj.sealAlg which is of type <class 'javaobj.v1.beans.JavaString'> to <type 'str'>
        #So, that 'String' to 'String' comparison is performed and not 'JavaString' to 'String'
        if seal_alg == "PBEWithMD5AndTripleDES":
            # if the object was sealed with PBEWithMD5AndTripleDES
            # then the parameters should apply to the same algorithm
            # and not be empty or null
            if params_alg != seal_alg:
                raise UnexpectedAlgorithmException("Unexpected parameters algorithm used in SealedObject; should match sealing algorithm '%s' but found '%s'" % (seal_alg, params_alg))
            if encoded_params is None or len(encoded_params) == 0:
                raise UnexpectedJavaTypeException("No parameters found in SealedObject instance for sealing algorithm '%s'; need at least a salt and iteration count to decrypt" % seal_alg)

            params_asn1 = decoder.decode(encoded_params, asn1Spec=rfc2898.PBEParameter())[0]
            salt = params_asn1['salt'].asOctets()
            iteration_count = int(params_asn1['iterationCount'])
            try:
                plaintext = sun_crypto.jce_pbe_decrypt(encrypted_content, key_password, salt, iteration_count)
            except sun_crypto.BadPaddingException:
                raise DecryptionFailureException("Failed to decrypt data for secret key '%s'; bad password?" % self.alias)
        else:
            raise UnexpectedAlgorithmException("Unexpected algorithm used for encrypting SealedObject: sealAlg=%s" % seal_alg)

        # The plaintext here is another serialized Java object; this
        # time it's an object implementing the javax.crypto.SecretKey
        # interface.  When using the default SunJCE provider, these
        # are usually either javax.crypto.spec.SecretKeySpec objects,
        # or some other specialized ones like those found in the
        # com.sun.crypto.provider package (e.g. DESKey and DESedeKey).
        #
        # Additionally, things are further complicated by the fact
        # that some of these specialized SecretKey implementations
        # (i.e. other than SecretKeySpec) implement a writeReplace()
        # method, causing Java's serialization runtime to swap out the
        # object for a completely different one at serialization time.
        # Again for SunJCE, the subsitute object that gets serialized
        # is usually a java.security.KeyRep object.
        obj, dummy = KeyStore._read_java_obj(plaintext, 0)
        clazz = obj.get_class()
        if clazz.name == "javax.crypto.spec.SecretKeySpec":
            algorithm = str(obj.algorithm)
            key = KeyStore._java_bytestring(obj.key)
            key_size = len(key)*8
            inner_form = "SecretKeySpec"

        elif clazz.name == "java.security.KeyRep":
            assert (obj.type.constant == "SECRET"), "Expected value 'SECRET' for KeyRep.type enum value, found '%s'" % obj.type.constant
            key_bytes = KeyStore._java_bytestring(obj.encoded)
            key_encoding = str(obj.format)
            if key_encoding == "RAW":
                pass # ok, no further processing needed
            elif key_encoding == "X.509":
                raise NotImplementedError("X.509 encoding for KeyRep objects not yet implemented")
            elif key_encoding == "PKCS#8":
                raise NotImplementedError("PKCS#8 encoding for KeyRep objects not yet implemented")
            else:
                raise UnexpectedKeyEncodingException("Unexpected key encoding '%s' found in serialized java.security.KeyRep object; expected one of 'RAW', 'X.509', 'PKCS#8'." % key_encoding)

            algorithm = str(obj.algorithm)
            key = key_bytes
            key_size = len(key)*8
            inner_form = "KeyRep"
        else:
            raise UnexpectedJavaTypeException("Unexpected object of type '%s' found inside SealedObject; don't know how to handle it" % clazz.name)

        self._encrypted = None
        self._inner_form = inner_form
        self._algorithm = algorithm
        self._key = key
        self._key_size = key_size

    is_decrypted.__doc__ = AbstractKeystoreEntry.is_decrypted.__doc__

    def encrypt(self, key_password):
        """
        Seals the secret key with the given password, so that the keystore
        can be saved.

        The entry becomes encrypted again, which means that it has to be
        decrypted before its attributes can be accessed. Has no effect if
        the entry is already encrypted.

        :param str key_password: The password to seal the entry with.
          Must be a plain ASCII string (the SunJCE PBE implementation
          rejects anything else).
        :raise ValueError: If the password contains non-ASCII characters.
        """
        if not self.is_decrypted():
            return

        sealed = self._seal(self.algorithm, self.key, key_password,
                            inner_form=self._inner_form)
        sealed_bytes = KeyStore._dump_java_obj(sealed)
        self._encrypted = sealed
        self._sealed_bytes = sealed_bytes
        self._inner_form = None
        self._algorithm = None
        self._key = None
        self._key_size = None

    def _sealed_object_for_save(self, key_password):
        """Returns the serialized SealedObject to write, without changing the
        entry.

        An entry that was loaded (or explicitly sealed) in encrypted form
        keeps its existing serialized form, so it is never silently
        re-encrypted with the store password (even after the in-memory
        copy has been decrypted). A new, never-encrypted entry is sealed
        for the resulting output only.
        """
        if self._sealed_bytes is not None:
            return self._sealed_bytes
        if not self.is_decrypted():
            # An already-sealed entry built directly (rather than loaded)
            # has no recorded byte form yet; derive it from its fields.
            sealed_obj = self._encrypted
            encoded_params = sealed_obj.encodedParams
            encrypted_content = sealed_obj.encryptedContent
            if not isinstance(encoded_params, bytes):
                encoded_params = KeyStore._java_bytestring(encoded_params)
            if not isinstance(encrypted_content, bytes):
                encrypted_content = KeyStore._java_bytestring(encrypted_content)
            top_class = sealed_obj.get_class()
            return KeyStore._build_sealed_object(
                encoded_params, encrypted_content,
                str(sealed_obj.sealAlg), str(sealed_obj.paramsAlg),
                top_class.name, top_class.serialVersionUID)
        sealed = self._seal(self.algorithm, self.key, key_password,
                            inner_form=self._inner_form)
        return KeyStore._dump_java_obj(sealed)

    def _seal(self, algorithm, key, key_password, inner_form=None):
        """Builds a SealedObject instance protecting the given raw key, in the
        same shape that the SunJCE keystore implementation uses.
        """
        # The inner object is the SecretKey implementation's serialized form.
        # Both shapes seen in real keystores are supported:
        #  - javax.crypto.spec.SecretKeySpec, holding the raw key directly;
        #  - java.security.KeyRep with a RAW secret encoding, which is what
        #    SunJCE's specialized DES/DESede key classes serialize to via
        #    writeReplace().
        plaintext = self._secret_key_serialized_form(algorithm, key, inner_form)

        salt = os.urandom(8)
        iteration_count = self.SEAL_ITERATION_COUNT
        params = rfc2898.PBEParameter()
        params.setComponentByName('salt', salt)
        params.setComponentByName('iterationCount', iteration_count)
        encoded_params = encoder.encode(params)

        enc_content = sun_crypto.jce_pbe_encrypt(plaintext, key_password, salt, iteration_count)

        return self._make_sealed_object(encoded_params, enc_content,
                                        self.SEAL_ALGORITHM, self.SEAL_ALGORITHM)

    @classmethod
    def _make_sealed_object(cls, encoded_params, encrypted_content, seal_alg, params_alg,
                            top_class_name=None, top_class_suid=None):
        """Builds a Java SealedObject over already-encrypted parts, using the
        class descriptors that the SunJCE keystore implementation produces."""
        if top_class_name is None:
            top_class_name = cls._SEALED_OBJECT_CLASS
        if top_class_suid is None:
            top_class_suid = cls._SEALED_OBJECT_SUID
        array_cls = cls._java_class(cls._JAVA_BYTE_ARRAY_CLASS, cls._JAVA_BYTE_ARRAY_SUID)
        sealed_super = cls._java_class(cls._JAVA_SEALED_OBJECT_CLASS, cls._JAVA_SEALED_OBJECT_SUID,
            fields=[('encodedParams', '[B'), ('encryptedContent', '[B'),
                    ('paramsAlg', 'Ljava/lang/String;'), ('sealAlg', 'Ljava/lang/String;')])
        sealed_cls = cls._java_class(top_class_name, top_class_suid, superclass=sealed_super)

        sealed_obj = JavaObject()
        sealed_obj.classdesc = sealed_cls
        sealed_obj.encodedParams = JavaByteArray(encoded_params, array_cls)
        sealed_obj.encryptedContent = JavaByteArray(encrypted_content, array_cls)
        # Both strings deliberately carry the same value but are written as
        # separate TC_STRING entries (not as a back reference to one another),
        # matching the serialized objects produced by SunJCE.
        sealed_obj.paramsAlg = _UnreferencedJavaString(params_alg)
        sealed_obj.sealAlg = _UnreferencedJavaString(seal_alg)
        return sealed_obj

    @classmethod
    def _build_sealed_object(cls, encoded_params, encrypted_content, seal_alg, params_alg,
                             top_class_name=None, top_class_suid=None):
        """Builds the serialized byte form of a SealedObject from
        already-encrypted parts."""
        sealed_obj = cls._make_sealed_object(encoded_params, encrypted_content, seal_alg,
                                             params_alg, top_class_name, top_class_suid)
        return KeyStore._dump_java_obj(sealed_obj)

    @classmethod
    def _secret_key_serialized_form(cls, algorithm, key, inner_form=None):
        array_cls = cls._java_class(cls._JAVA_BYTE_ARRAY_CLASS, cls._JAVA_BYTE_ARRAY_SUID)
        if inner_form == "SecretKeySpec":
            use_key_rep = False
        elif inner_form == "KeyRep":
            use_key_rep = True
        else:
            # SunJCE's specialized DES/DESede SecretKey implementations
            # replace themselves with a KeyRep; for all other algorithms the
            # SecretKeySpec form is used.
            use_key_rep = algorithm in ("DES", "DESede")

        if not use_key_rep:
            spec_cls = cls._java_class(cls._JAVA_SECRET_KEY_SPEC_CLASS, cls._JAVA_SECRET_KEY_SPEC_SUID,
                fields=[('algorithm', 'Ljava/lang/String;'), ('key', '[B')])
            spec = JavaObject()
            spec.classdesc = spec_cls
            spec.algorithm = JavaString(algorithm)
            spec.key = JavaByteArray(key, array_cls)
            return KeyStore._dump_java_obj(spec)

        # java.security.KeyRep, with the SECRET type constant. The enum's
        # class descriptor and the java.lang.Enum superclass are emitted
        # with the flags observed in java.security.KeyRep$Type.
        enum_cls = cls._java_class("java.security.KeyRep$Type", 0, flags=0x12,
                                   superclass=cls._java_class("java.lang.Enum", 0, flags=0x12))
        enum_obj = JavaEnum()
        enum_obj.classdesc = enum_cls
        enum_obj.constant = JavaString("SECRET")

        key_rep_cls = cls._java_class("java.security.KeyRep", -4757683898830641853,
            fields=[('algorithm', 'Ljava/lang/String;'), ('encoded', '[B'),
                    ('format', 'Ljava/lang/String;'), ('type', 'Ljava/security/KeyRep$Type;')])
        key_rep = JavaObject()
        key_rep.classdesc = key_rep_cls
        key_rep.algorithm = JavaString(algorithm)
        key_rep.encoded = JavaByteArray(key, array_cls)
        key_rep.format = JavaString("RAW")
        key_rep.type = enum_obj
        return KeyStore._dump_java_obj(key_rep)

    @staticmethod
    def _java_class(name, serial_version_uid, fields=(), superclass=None, flags=2):
        clazz = JavaClass()
        clazz.name = name
        clazz.serialVersionUID = serial_version_uid
        clazz.flags = flags
        clazz.fields_names = [f[0] for f in fields]
        clazz.fields_types = [JavaString(f[1]) for f in fields]
        clazz.superclass = superclass
        return clazz

# --------------------------------------------------------------------------

class _UnreferencedJavaString(JavaString):
    """A Java string that is always written as its own TC_STRING value.

    javaobj's marshaller reuses an earlier TC_STRING entry whenever an equal
    string value is serialized twice. SunJCE's SealedObject instances contain
    two separate string fields that happen to hold the same algorithm name;
    they are written as independent TC_STRING entries rather than as a back
    reference. This subclass keeps the marshaller from collapsing them,
    while still comparing equal to plain strings.
    """

    def __eq__(self, other):
        return self is other

    def __ne__(self, other):
        return self is not other

    __hash__ = object.__hash__

# --------------------------------------------------------------------------

class KeyStore(AbstractKeystore):
    """
    Represents a loaded JKS or JCEKS keystore.
    """

    @classmethod
    def new(cls, store_type, store_entries):
        """
        Helper function to create a new KeyStore.

        :param string store_type: What kind of keystore
          the store should be. Valid options are jks or jceks.
        :param list store_entries: Existing entries that
          should be added to the keystore.

        :returns: A loaded :class:`KeyStore` instance,
          with the specified entries.

        :raises DuplicateAliasException: If some of the
          entries have the same alias.
        :raises UnsupportedKeyStoreTypeException: If the keystore is of
          an unsupported type
        :raises UnsupportedKeyStoreEntryTypeException: If some
          of the keystore entries are unsupported (in this keystore type)
        """
        if store_type not in ['jks', 'jceks']:
            raise UnsupportedKeystoreTypeException("The Keystore Type '%s' is not supported" % store_type)

        entries = {}
        for entry in store_entries:
            if not isinstance(entry, AbstractKeystoreEntry):
                raise UnsupportedKeystoreEntryTypeException("Entries must be a KeyStore Entry")

            if store_type != 'jceks' and isinstance(entry, SecretKeyEntry):
                raise UnsupportedKeystoreEntryTypeException('Secret Key only allowed in JCEKS keystores')

            alias = entry.alias

            if alias in entries:
                raise DuplicateAliasException("Found duplicate alias '%s'" % alias)
            entries[alias] = entry

        # Record the store type on the entries so that a later encrypt()
        # uses the protection scheme belonging to this keystore type.
        for entry in entries.values():
            entry.store_type = store_type

        return cls(store_type, entries)

    @classmethod
    def loads(cls, data, store_password, try_decrypt_keys=True):
        """Loads the given keystore file using the supplied password for
        verifying its integrity, and returns a :class:`KeyStore` instance.

        Note that entries in the store that represent some form of
        cryptographic key material are stored in encrypted form, and
        therefore require decryption before becoming accessible.

        Upon original creation of a key entry in a Java keystore,
        users are presented with the choice to either use the same
        password as the store password, or use a custom one. The most
        common choice is to use the store password for the individual
        key entries as well.

        For ease of use in this typical scenario, this function will
        attempt to decrypt each key entry it encounters with the store
        password:

         - If the key can be successfully decrypted with the store
           password, the entry is returned in its decrypted form, and
           its attributes are immediately accessible.
         - If the key cannot be decrypted with the store password, the
           entry is returned in its encrypted form, and requires a
           manual follow-up decrypt(key_password) call from the user
           before its individual attributes become accessible.

        Setting ``try_decrypt_keys`` to ``False`` disables this automatic
        decryption attempt, and returns all key entries in encrypted
        form.

        You can query whether a returned entry object has already been
        decrypted by calling the :meth:`is_decrypted` method on it.
        Attempting to access attributes of an entry that has not yet
        been decrypted will result in a
        :class:`~jks.util.NotYetDecryptedException`.

        :param bytes data: Byte string representation of the keystore
          to be loaded.
        :param str password: Keystore password string
        :param bool try_decrypt_keys: Whether to automatically try to
          decrypt any encountered key entries using the same password
          as the keystore password.

        :returns: A loaded :class:`KeyStore` instance, if the keystore
          could be successfully parsed and the supplied store password
          is correct.

          If the ``try_decrypt_keys`` parameter was set to ``True``, any
          keys that could be successfully decrypted using the store
          password have already been decrypted; otherwise, no atttempt
          to decrypt any key entries is made.

        :raises BadKeystoreFormatException: If the keystore is malformed
          in some way
        :raises UnsupportedKeystoreVersionException: If the keystore
          contains an unknown format version number
        :raises KeystoreSignatureException: If the keystore signature
          could not be verified using the supplied store password
        :raises DuplicateAliasException: If the keystore contains
          duplicate aliases
        """
        store_type = ""
        magic_number = data[:4]
        if magic_number == MAGIC_NUMBER_JKS:
            store_type = "jks"
        elif magic_number == MAGIC_NUMBER_JCEKS:
            store_type = "jceks"
        else:
            raise BadKeystoreFormatException('Not a JKS or JCEKS keystore'
                                             ' (magic number wrong; expected'
                                             ' FEEDFEED or CECECECE)')

        try:
            version = b4.unpack_from(data, 4)[0]
            if version != 2:
                tmpl = 'Unsupported keystore version; expected v2, found v%r'
                raise UnsupportedKeystoreVersionException(tmpl % version)

            entries = {}

            entry_count = b4.unpack_from(data, 8)[0]
            pos = 12
            for i in range(entry_count):
                tag = b4.unpack_from(data, pos)[0]; pos += 4
                alias, pos = cls._read_utf(data, pos, kind="entry alias")
                timestamp = int(b8.unpack_from(data, pos)[0]); pos += 8 # milliseconds since UNIX epoch

                if tag == 1:
                    entry, pos = cls._read_private_key(data, pos, store_type)
                elif tag == 2:
                    entry, pos = cls._read_trusted_cert(data, pos, store_type)
                elif tag == 3:
                    if store_type != "jceks":
                        raise BadKeystoreFormatException("Unexpected entry tag {0} encountered in JKS keystore; only supported in JCEKS keystores".format(tag))
                    entry, pos = cls._read_secret_key(data, pos, store_type)
                else:
                    raise BadKeystoreFormatException("Unexpected keystore entry tag %d", tag)

                entry.alias = alias
                entry.timestamp = timestamp

                if try_decrypt_keys:
                    try:
                        entry.decrypt(store_password)
                    except DecryptionFailureException:
                        pass # ok, let user call decrypt() manually

                if alias in entries:
                    raise DuplicateAliasException("Found duplicate alias '%s'" % alias)
                entries[alias] = entry

        except struct.error as e:
            raise BadKeystoreFormatException(e)

        # skip integrity check if no password is provided
        if store_password is None:
            return cls(store_type, entries)

        # check keystore integrity (uses UTF-16BE encoding of the password)
        hash_fn = hashlib.sha1
        hash_digest_size = hash_fn().digest_size

        store_password_utf16 = store_password.encode('utf-16be')
        expected_hash = hash_fn(store_password_utf16 + SIGNATURE_WHITENING + data[:pos]).digest()
        found_hash = data[pos:pos+hash_digest_size]

        if len(found_hash) != hash_digest_size:
            tmpl = "Bad signature size; found %d bytes, expected %d bytes"
            raise BadKeystoreFormatException(tmpl % (len(found_hash),
                                                     hash_digest_size))
        if expected_hash != found_hash:
            raise KeystoreSignatureException("Hash mismatch; incorrect keystore password?")

        return cls(store_type, entries)

    @classmethod
    def _write_private_key(cls, alias, item, key_password, store_type):
        private_key_entry = b4.pack(1) # private key
        private_key_entry += cls._write_utf(alias)
        private_key_entry += b8.pack(item.timestamp)
        private_key_entry += cls._write_data(item._encrypted_for_save(key_password, store_type))

        private_key_entry += b4.pack(len(item.cert_chain))
        for cert in item.cert_chain:
            private_key_entry += cls._write_utf(cert[0])
            private_key_entry += cls._write_data(cert[1])

        return private_key_entry

    @classmethod
    def _write_trusted_cert(cls, alias, item):
        trusted_cert = b4.pack(2) # trusted cert
        trusted_cert += cls._write_utf(alias)
        trusted_cert += b8.pack(item.timestamp)
        trusted_cert += cls._write_utf('X.509')
        trusted_cert += cls._write_data(item.cert)
        return trusted_cert

    @classmethod
    def _write_secret_key(cls, alias, item, key_password):
        # Secret keys are written as a bare serialized SealedObject; unlike
        # the other entry types, there is no length prefix.
        secret_key_entry = b4.pack(3) # secret key
        secret_key_entry += cls._write_utf(alias)
        secret_key_entry += b8.pack(item.timestamp)
        secret_key_entry += item._sealed_object_for_save(key_password)
        return secret_key_entry

    def saves(self, store_password):
        """
        Saves the keystore so that it can be read by other applications.

        Saving does not modify any of the entries. Entries that are still
        encrypted (private or secret keys) are written with their existing
        ciphertext, and are therefore not re-encrypted with the supplied
        store password. Entries that have been decrypted are encrypted for
        the output only; they remain decrypted and accessible on the
        in-memory entry.

        The integrity digest is computed over the complete output,
        i.e. the store header and all serialized entries, and is appended
        as the final 20 bytes.

        :param str store_password: Password for the created keystore
          (and for any unencrypted keys)

        :returns: A byte string representation of the keystore.

        :raises UnsupportedKeystoreTypeException: If the keystore
          is of an unsupported type
        :raises UnsupportedKeystoreEntryTypeException: If the keystore
          contains an unsupported entry type
        :raise ValueError: If a secret key password contains non-ASCII
          characters.
        """

        if self.store_type == 'jks':
            keystore = MAGIC_NUMBER_JKS
        elif self.store_type == 'jceks':
            keystore = MAGIC_NUMBER_JCEKS
        else:
            raise UnsupportedKeystoreTypeException("Only JKS and JCEKS keystores are supported")

        entries = list(self.entries.items())

        # Check every entry before serializing anything, so a save either
        # produces a complete store or fails before touching any entry.
        for alias, item in entries:
            if isinstance(item, TrustedCertEntry):
                continue
            if isinstance(item, PrivateKeyEntry):
                continue
            if isinstance(item, SecretKeyEntry):
                if self.store_type != 'jceks':
                    raise UnsupportedKeystoreEntryTypeException('Secret Key only allowed in JCEKS keystores')
                continue
            raise UnsupportedKeystoreEntryTypeException("Unknown entry type in keystore")

        keystore += b4.pack(2) # version 2
        keystore += b4.pack(len(entries))

        for alias, item in entries:
            if isinstance(item, TrustedCertEntry):
                keystore += self._write_trusted_cert(alias, item)
            elif isinstance(item, PrivateKeyEntry):
                keystore += self._write_private_key(alias, item, store_password, self.store_type)
            elif isinstance(item, SecretKeyEntry):
                keystore += self._write_secret_key(alias, item, store_password)

        hash_fn = hashlib.sha1
        store_password_utf16 = store_password.encode('utf-16be')
        hash = hash_fn(store_password_utf16 + SIGNATURE_WHITENING + keystore).digest()
        keystore += hash

        return keystore

    def __init__(self, store_type, entries):
        super(KeyStore, self).__init__(store_type, entries)

    @property
    def certs(self):
        """A subset of the :attr:`entries` dictionary, filtered down to only
        those entries of type :class:`TrustedCertEntry`."""
        return dict([(a, e) for a, e in self.entries.items()
                     if isinstance(e, TrustedCertEntry)])

    @property
    def secret_keys(self):
        """A subset of the :attr:`entries` dictionary, filtered down to only
        those entries of type :class:`SecretKeyEntry`."""
        return dict([(a, e) for a, e in self.entries.items()
                     if isinstance(e, SecretKeyEntry)])

    @property
    def private_keys(self):
        """A subset of the :attr:`entries` dictionary, filtered down to only
        those entries of type :class:`PrivateKeyEntry`."""
        return dict([(a, e) for a, e in self.entries.items()
                     if isinstance(e, PrivateKeyEntry)])

    @classmethod
    def _read_trusted_cert(cls, data, pos, store_type):
        cert_type, pos = cls._read_utf(data, pos, kind="certificate type")
        cert_data, pos = cls._read_data(data, pos)
        entry = TrustedCertEntry(type=cert_type, cert=cert_data, store_type=store_type)
        return entry, pos

    @classmethod
    def _read_private_key(cls, data, pos, store_type):
        ber_data, pos = cls._read_data(data, pos)
        chain_len = b4.unpack_from(data, pos)[0]
        pos += 4

        cert_chain = []
        for j in range(chain_len):
            cert_type, pos = cls._read_utf(data, pos, kind="certificate type")
            cert_data, pos = cls._read_data(data, pos)
            cert_chain.append((cert_type, cert_data))

        entry = PrivateKeyEntry(cert_chain=cert_chain, encrypted=ber_data, store_type=store_type)
        return entry, pos

    @classmethod
    def _read_secret_key(cls, data, pos, store_type):
        # SecretKeys are stored in the key store file through Java's
        # serialization mechanism, i.e. as an actual serialized Java
        # object embedded inside the file. The objects that get stored
        # are not the SecretKey instances themselves though, as that
        # would trivially expose the key without the need for a
        # passphrase to gain access to it.
        #
        # Instead, an object of type javax.crypto.SealedObject is
        # written. The purpose of this class is specifically to
        # securely serialize objects that contain secret values by
        # applying a password-based encryption scheme to the
        # serialized form of the object to be protected. Only the
        # resulting ciphertext is then stored by the serialized form
        # of the SealedObject instance.
        #
        # To decrypt the SealedObject, the correct passphrase must be
        # given to be able to decrypt the underlying object's
        # serialized form.  Once decrypted, one more de-serialization
        # will result in the original object being restored.
        #
        # The default key protector used by the SunJCE provider
        # returns an instance of type SealedObjectForKeyProtector, a
        # (direct) subclass of SealedObject, which uses Java's
        # custom/unpublished PBEWithMD5AndTripleDES algorithm.
        #
        # Class member structure:
        #
        # SealedObjectForKeyProtector:
        #   static final long serialVersionUID = -3650226485480866989L;
        #
        # SealedObject:
        #   static final long serialVersionUID = 4482838265551344752L;
        #   private byte[] encryptedContent;         # The serialized underlying object, in encrypted format.
        #   private String sealAlg;                  # The algorithm that was used to seal this object.
        #   private String paramsAlg;                # The algorithm of the parameters used.
        #   protected byte[] encodedParams;          # The cryptographic parameters used by the sealing Cipher, encoded in the default format.

        sealed_start = pos
        sealed_obj, pos = cls._read_java_obj(data, pos, ignore_remaining_data=True)
        if not cls._java_is_subclass(sealed_obj, "javax.crypto.SealedObject"):
            raise UnexpectedJavaTypeException("Unexpected sealed object type '%s'; not a subclass of javax.crypto.SealedObject" % sealed_obj.get_class().name)

        # Keep the original serialized form: entries that are not explicitly
        # re-encrypted must be written back byte for byte.
        sealed_obj_bytes = data[sealed_start:pos]

        if not isinstance(sealed_obj.encryptedContent, bytes):
            sealed_obj.encryptedContent = cls._java_bytestring(sealed_obj.encryptedContent)
        if not isinstance(sealed_obj.encodedParams, bytes):
            sealed_obj.encodedParams = KeyStore._java_bytestring(sealed_obj.encodedParams)

        entry = SecretKeyEntry(sealed_obj=sealed_obj, sealed_obj_bytes=sealed_obj_bytes, store_type=store_type)
        return entry, pos

    @classmethod
    def _read_java_obj(cls, data, pos, ignore_remaining_data=False):
        data_stream = BytesIO(data[pos:])
        obj = javaobj.load(data_stream, ignore_remaining_data=ignore_remaining_data)
        obj_size = data_stream.tell()

        return obj, pos + obj_size

    @classmethod
    def _dump_java_obj(cls, obj):
        """Serializes a Java object back to its Java serialization form."""
        return javaobj.dumps(obj)

    @classmethod
    def _java_is_subclass(cls, obj, class_name):
        """Given a deserialized JavaObject as returned by the javaobj library,
        determine whether it's a subclass of the given class name.
        """
        clazz = obj.get_class()
        while clazz:
            if clazz.name == class_name:
                return True
            clazz = clazz.superclass
        return False

    @classmethod
    def _java_bytestring(cls, java_byte_list):
        """Convert the value returned by javaobj for a byte[] to a byte
        string.  Java's bytes are signed and numeric (i.e. not chars),
        so javaobj returns Java byte arrays as a list of Python
        integers in the range [-128, 127].

        For ease of use we want to get a byte string representation of
        that, so we reinterpret each integer as an unsigned byte, take
        its new value as another Python int (now remapped to the range
        [0, 255]), and use struct.pack() to create the matching byte
        string.
        """
        args = [ctypes.c_ubyte(sb).value for sb in java_byte_list]
        return struct.pack("%dB" % len(java_byte_list), *args)
