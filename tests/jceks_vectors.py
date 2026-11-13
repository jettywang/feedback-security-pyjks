#!/usr/bin/env python
# vim: set ai et ts=4 sw=4 sts=4:
"""
Deterministic generators for JCEKS SecretKey test inputs.

The JCEKS secret key store entries generated here are built directly from
the Java serialization format (JVM serialization stream spec) instead of
being checked in as opaque binaries. This keeps the anomalous object graphs
in `test_jceks_secret_key.py` reproducible, reviewable and independent of a
working JVM: every class descriptor, field type, reference handle and PBE
parameter below is constructed in plain Python.

The sealed payload is encrypted with pyjks' own PBEWithMD5AndTripleDES
primitives, exactly like SunJCE does when it writes a JCEKS keystore. No JVM
is required to regenerate or review any of these inputs.
"""

from __future__ import print_function
import struct
import hashlib

from pyasn1.codec.ber import encoder
from pyasn1.type import univ

import jks
from jks import rfc2898, sun_crypto, util

# Java serialization stream protocol constants (Object Serialization Spec)
TC_NULL = 0x70
TC_REFERENCE = 0x71
TC_CLASSDESC = 0x72
TC_OBJECT = 0x73
TC_STRING = 0x74
TC_ARRAY = 0x75
TC_ENDBLOCKDATA = 0x78
TC_ENUM = 0x7E
BASE_REFERENCE_IDX = 0x7E0000

SECRET_KEY_PASSWORD = "12345678"
SECRET_KEY_ALIAS = "mykey"
SECRET_KEY_SALT = b"SO_SALTY"
SECRET_KEY_ITERATIONS = 42


class ClassSpec(object):
    """Minimal description of a serialized Java class (name, serialVersionUID,
    flags, declared fields and superclass)."""

    def __init__(self, name, suid, flags=2, fields=(), superclass=None):
        self.name = name
        self.suid = suid
        self.flags = flags
        self.fields = list(fields)
        self.superclass = superclass


class Writer(object):
    """Tiny, deterministic writer for the Java serialization stream format.

    It supports exactly the opcodes needed for JCEKS secret keys: objects,
    class descriptors, String and byte[] fields, enums and back references.
    Handle assignment follows javaobj's stream reading order so the same
    reference topology can be exercised via TC_REFERENCE.
    """

    def __init__(self):
        self.buf = bytearray(b"\xac\xed\x00\x05")
        self.handles = []
        self.class_handles = {}
        self.string_handles = {}

    def _new_handle(self):
        self.handles.append(None)
        return BASE_REFERENCE_IDX + len(self.handles) - 1

    def _set_handle(self, handle, value):
        self.handles[handle - BASE_REFERENCE_IDX] = value

    def utf(self, value):
        encoded = value.encode("utf-8")
        self.buf += struct.pack(">H", len(encoded)) + encoded

    def reference(self, handle):
        self.buf += struct.pack(">BL", TC_REFERENCE, handle)

    def null(self):
        self.buf += struct.pack(">B", TC_NULL)

    def string(self, value, reuse=True):
        if reuse and value in self.string_handles:
            handle = self.string_handles[value]
            self.reference(handle)
            return handle
        handle = self._new_handle()
        self._set_handle(handle, ("string", value))
        if reuse:
            self.string_handles[value] = handle
        self.buf += struct.pack(">B", TC_STRING)
        self.utf(value)
        return handle

    def string_without_reuse(self, value):
        handle = self._new_handle()
        self._set_handle(handle, ("string", value))
        self.buf += struct.pack(">B", TC_STRING)
        self.utf(value)
        return handle

    def class_desc(self, spec):
        key = id(spec)
        if key in self.class_handles:
            handle = self.class_handles[key]
            self.reference(handle)
            return handle

        handle = self._new_handle()
        self.class_handles[key] = handle
        self._set_handle(handle, ("class", spec.name))

        self.buf += struct.pack(">B", TC_CLASSDESC)
        self.utf(spec.name)
        self.buf += struct.pack(">qB", spec.suid, spec.flags)
        self.buf += struct.pack(">H", len(spec.fields))
        for field_name, field_type in spec.fields:
            self.buf += field_type.encode("ascii")[:1]
            self.utf(field_name)
            if field_type[0] in "L[":
                self.string(field_type)
        self.buf += struct.pack(">B", TC_ENDBLOCKDATA)
        if spec.superclass:
            self.class_desc(spec.superclass)
        else:
            self.null()
        return handle

    def begin_object(self, spec):
        self.buf += struct.pack(">B", TC_OBJECT)
        self.class_desc(spec)
        handle = self._new_handle()
        self._set_handle(handle, ("object", spec.name))
        return handle

    def begin_enum(self, spec):
        self.buf += struct.pack(">B", TC_ENUM)
        self.class_desc(spec)
        handle = self._new_handle()
        self._set_handle(handle, ("enum", spec.name))
        return handle

    def bytes_array(self, data, spec=None):
        spec = spec or BYTES_SPEC
        self.buf += struct.pack(">B", TC_ARRAY)
        self.class_desc(spec)
        handle = self._new_handle()
        self._set_handle(handle, ("bytes", bytes(data)))
        self.buf += struct.pack(">i", len(data))
        self.buf += bytes(data)
        return handle

    def enum_constant(self, spec, constant):
        self.buf += struct.pack(">B", TC_ENUM)
        self.class_desc(spec)
        handle = self._new_handle()
        self._set_handle(handle, ("enum", constant))
        self.string_without_reuse(constant)
        return handle

    def done(self):
        return bytes(self.buf)


# Class descriptors copied from the serialized form SunJCE writes into a real
# JCEKS keystore (see tests/keystores/jceks/AES128.jceks and DES.jceks).
BYTES_SPEC = ClassSpec("[B", -5984413125824719648, 2, [])
ENUM_SUPER_SPEC = ClassSpec("java.lang.Enum", 0, 0x12, [])
KEYREP_TYPE_SPEC = ClassSpec("java.security.KeyRep$Type", 0, 0x12, [], superclass=ENUM_SUPER_SPEC)
SECRET_KEY_SPEC_SPEC = ClassSpec(
    "javax.crypto.spec.SecretKeySpec", 6577238317307289933, 2,
    [("algorithm", "Ljava/lang/String;"), ("key", "[B")])
KEY_REP_SPEC = ClassSpec(
    "java.security.KeyRep", -4757683898830641853, 2,
    [("algorithm", "Ljava/lang/String;"), ("encoded", "[B"),
     ("format", "Ljava/lang/String;"), ("type", "Ljava/security/KeyRep$Type;")])
SEALED_OBJECT_SPEC = ClassSpec(
    "javax.crypto.SealedObject", 4482838265551344752, 2,
    [("encodedParams", "[B"), ("encryptedContent", "[B"),
     ("paramsAlg", "Ljava/lang/String;"), ("sealAlg", "Ljava/lang/String;")])


def sealed_object_spec(name=None, superclass=None):
    """Returns the class descriptor SunJCE uses for the key protector object."""
    if name is None:
        return ClassSpec(
            "com.sun.crypto.provider.SealedObjectForKeyProtector",
            -3650226485480866989, 2, [], superclass=SEALED_OBJECT_SPEC)
    return ClassSpec(name, -3650226485480866989, 2, [], superclass=superclass or SEALED_OBJECT_SPEC)


def pbe_parameters(salt=SECRET_KEY_SALT, iterations=SECRET_KEY_ITERATIONS):
    params = rfc2898.PBEParameter()
    params["salt"] = univ.OctetString(salt)
    params["iterationCount"] = iterations
    return encoder.encode(params)


def pbe_encrypt(plaintext, password=SECRET_KEY_PASSWORD,
                salt=SECRET_KEY_SALT, iterations=SECRET_KEY_ITERATIONS):
    key, iv = sun_crypto._jce_pbe_derive_key_and_iv(password, salt, iterations)
    from Cryptodome.Cipher import DES3
    padded = util.add_pkcs7_padding(plaintext, 8)
    return DES3.new(key, DES3.MODE_CBC, IV=iv).encrypt(padded)


def sealed_object(inner, password=SECRET_KEY_PASSWORD):
    """Seals `inner` (an already serialized Java object) in a SunJCE
    SealedObjectForKeyProtector container, serialized as JCEKS stores it."""
    encrypted_content = pbe_encrypt(inner, password)
    writer = Writer()
    writer.begin_object(sealed_object_spec())
    writer.bytes_array(pbe_parameters())
    writer.bytes_array(encrypted_content)
    writer.string("PBEWithMD5AndTripleDES")
    writer.string("PBEWithMD5AndTripleDES")
    return writer.done()


def jceks_store(sealed, password=SECRET_KEY_PASSWORD,
                alias=SECRET_KEY_ALIAS, timestamp=0):
    """Wraps `sealed` in a minimal valid JCEKS container with a v2 store and a
    single secret key entry (entry tag 3), followed by the store integrity hash.
    """
    body = bytearray(b"\xce\xce\xce\xce" + struct.pack(">LL", 2, 1))
    body += struct.pack(">L", 3)
    alias_bytes = alias.encode("utf-8")
    body += struct.pack(">H", len(alias_bytes)) + alias_bytes
    body += struct.pack(">q", timestamp)
    body += sealed
    digest = hashlib.sha1(password.encode("utf-16be") + b"Mighty Aphrodite" + bytes(body)).digest()
    return bytes(body) + digest


def secret_key_spec_object(algorithm="AES", key=b"\x00" * 16,
                           spec=None, algorithm_value=None, key_value=None,
                           field_order="algorithm_first"):
    """Serializes a javax.crypto.spec.SecretKeySpec object.

    `algorithm_value`/`key_value` callbacks receive (writer, handles) so a test
    can deliberately store a reference instead of a value. `handles` contains
    the "object", "algorithm" and "key" handles written so far.
    """
    writer = Writer()
    handles = {}
    handles["object"] = writer.begin_object(spec or SECRET_KEY_SPEC_SPEC)
    if field_order == "key_first":
        if key_value is None:
            handles["key"] = writer.bytes_array(key)
        else:
            key_value(writer, handles)
        if algorithm_value is None:
            handles["algorithm"] = writer.string(algorithm)
        else:
            algorithm_value(writer, handles)
    else:
        if algorithm_value is None:
            handles["algorithm"] = writer.string(algorithm)
        else:
            algorithm_value(writer, handles)
        if key_value is None:
            handles["key"] = writer.bytes_array(key)
        else:
            key_value(writer, handles)
    return writer.done()


def key_rep_object(algorithm="DES", encoded=b"12345678", key_format="RAW",
                   key_type="SECRET", spec=None, algorithm_value=None,
                   encoded_value=None, format_value=None, type_value=None,
                   field_order="algorithm_first"):
    """Serializes a java.security.KeyRep object, the writeReplace() form
    SunJCE uses for specialized SecretKey implementations (DES, DESede).

    As with secret_key_spec_object(), callbacks receive (writer, handles). Use
    field_order="encoded_first" to make the byte[] handle available before the
    algorithm field, which allows constructing a cross-reference graph that
    would otherwise be impossible to express.
    """
    writer = Writer()
    handles = {}
    handles["object"] = writer.begin_object(spec or KEY_REP_SPEC)
    if field_order == "encoded_first":
        if encoded_value is None:
            handles["encoded"] = writer.bytes_array(encoded)
        else:
            encoded_value(writer, handles)
        if algorithm_value is None:
            handles["algorithm"] = writer.string(algorithm)
        else:
            algorithm_value(writer, handles)
    else:
        if algorithm_value is None:
            handles["algorithm"] = writer.string(algorithm)
        else:
            algorithm_value(writer, handles)
        if encoded_value is None:
            handles["encoded"] = writer.bytes_array(encoded)
        else:
            encoded_value(writer, handles)
    if format_value is None:
        writer.string(key_format)
    else:
        format_value(writer, handles)
    if type_value is None:
        writer.enum_constant(KEYREP_TYPE_SPEC, key_type)
    else:
        type_value(writer, handles)
    return writer.done()


def load_entry(inner, password=SECRET_KEY_PASSWORD, try_decrypt_keys=False):
    """Loads the JCEKS store containing `inner` as a single secret key entry."""
    store_bytes = jceks_store(sealed_object(inner, password), password)
    store = jks.KeyStore.loads(store_bytes, password, try_decrypt_keys=try_decrypt_keys)
    return store.entries[SECRET_KEY_ALIAS]
