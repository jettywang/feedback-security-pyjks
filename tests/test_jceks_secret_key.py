#!/usr/bin/env python
# vim: set ai et ts=4 sw=4 sts=4:
"""
Security-focused tests for JCEKS SecretKey entry loading.

These tests pin down the exact conversion path used for JCEKS secret keys:

  KeyStore.loads
    -> KeyStore._read_secret_key          (outer SealedObject structural checks)
    -> KeyStore._read_java_obj            (javaobj deserialization, no Java code)
    -> SecretKeyEntry.decrypt             (PBE decryption, then inner object checks)

The inner plaintext is a serialized Java object. Deserializing it with javaobj
builds Python data structures only; it does not execute Java code (no
readObject/readResolve/writeReplace hooks run). The security question is
therefore whether the resulting object *shape* is restricted to the two
allowed representations: javax.crypto.spec.SecretKeySpec and
java.security.KeyRep with type SECRET and format RAW.

All inputs are generated deterministically in tests/jceks_vectors.py. Each
negative case documents the rejection stage and the expected exception type;
none of the rejections rely on `assert`, so the same expectations must hold
under `python -O` where assertions are stripped.
"""

from __future__ import print_function
import os
import subprocess
import sys
import textwrap
import unittest

import jks
from . import jceks_vectors as vectors


PASSWORD = vectors.SECRET_KEY_PASSWORD
ALIAS = vectors.SECRET_KEY_ALIAS


class SecretKeyVectorTests(unittest.TestCase):
    """Normal-path controls: the two representations SunJCE actually writes."""

    def test_secret_key_spec_accepted(self):
        """Baseline: a SecretKeySpec is the canonical AES secret key form."""
        entry = vectors.load_entry(vectors.secret_key_spec_object(
            algorithm="AES", key=b"\x66\x6e\x02\x21\xcc\x44\xc1\xfc\x4a\xab\xf4\x58\xf9\xdf\xdd\x3c"))
        self.assertFalse(entry.is_decrypted())
        entry.decrypt(PASSWORD)
        self.assertTrue(entry.is_decrypted())
        self.assertEqual(entry.algorithm, "AES")
        self.assertEqual(entry.key_size, 128)
        self.assertEqual(entry.key, b"\x66\x6e\x02\x21\xcc\x44\xc1\xfc\x4a\xab\xf4\x58\xf9\xdf\xdd\x3c")

    def test_key_rep_secret_raw_accepted(self):
        """Baseline: KeyRep(type=SECRET, format=RAW) is the DES/DESede form."""
        entry = vectors.load_entry(vectors.key_rep_object(
            algorithm="DES", encoded=b"\x4c\xf2\xfe\x91\x5d\x08\x2a\x43", key_format="RAW"))
        entry.decrypt(PASSWORD)
        self.assertEqual(entry.algorithm, "DES")
        self.assertEqual(entry.key_size, 64)
        self.assertEqual(entry.key, b"\x4c\xf2\xfe\x91\x5d\x08\x2a\x43")

    def test_real_jceks_samples_still_load(self):
        """The checked-in SunJCE samples must remain accepted unchanged."""
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keystores", "jceks")
        store = jks.KeyStore.load(os.path.join(path, "AES128.jceks"), PASSWORD)
        self.assertEqual(store.entries[ALIAS].algorithm, "AES")
        store = jks.KeyStore.load(os.path.join(path, "DES.jceks"), PASSWORD)
        self.assertEqual(store.entries[ALIAS].algorithm, "DES")
        store = jks.KeyStore.load(os.path.join(path, "DESede.jceks"), PASSWORD)
        self.assertEqual(store.entries[ALIAS].algorithm, "DESede")


class SecretKeyRejectionTests(unittest.TestCase):
    """Each test names the stage at which malformed input must be rejected."""

    def make_outer(self, params_value=None, content_value=None):
        writer = vectors.Writer()
        writer.begin_object(vectors.sealed_object_spec())
        if params_value is None:
            writer.bytes_array(vectors.pbe_parameters())
        else:
            params_value(writer)
        if content_value is None:
            writer.bytes_array(vectors.pbe_encrypt(vectors.secret_key_spec_object()))
        else:
            content_value(writer)
        writer.string("PBEWithMD5AndTripleDES")
        writer.string("PBEWithMD5AndTripleDES")
        return writer.done()

    def assertRejectedAtDecrypt(self, inner, exception_type, stage):
        """Loads an entry (outer checks only), then expects decrypt() to fail."""
        entry = vectors.load_entry(inner, try_decrypt_keys=False)
        self.assertFalse(entry.is_decrypted())
        try:
            entry.decrypt(PASSWORD)
        except exception_type as error:
            message = str(error)
        else:
            self.fail("%s: decrypt() accepted malformed secret key" % stage)
        self.assertFalse(entry.is_decrypted())
        # A rejected entry must not expose partial key material.
        self.assertRaises(jks.NotYetDecryptedException, lambda: entry.algorithm)
        return message

    def test_wrong_class_inheritance_is_rejected(self):
        """Wrong class inheritance: an attacker-named subclass of SecretKeySpec
        (same serialVersionUID, extra fields) is not the allowed exact class.
        Rejection stage: inner object dispatch in SecretKeyEntry.decrypt."""
        subclass = vectors.ClassSpec(
            "evil.SecretKeySpec", 6577238317307289933, 2,
            [], superclass=vectors.SECRET_KEY_SPEC_SPEC)
        inner = vectors.secret_key_spec_object(
            algorithm="AES", key=b"\x11" * 16, spec=subclass)
        self.assertRejectedAtDecrypt(inner, jks.UnexpectedJavaTypeException,
                                     "inner type dispatch")

    def test_secret_key_spec_fake_superclass_is_rejected(self):
        """SecretKeySpec extends java.lang.Object only; an object of the same
        name carrying an explicit superclass descriptor is not the allowed
        exact structure.
        Rejection stage: inner class descriptor validation."""
        fake_parent = vectors.ClassSpec("java.lang.Object", 0, 2, [])
        spec = vectors.ClassSpec(
            "javax.crypto.spec.SecretKeySpec", 6577238317307289933, 2,
            [("algorithm", "Ljava/lang/String;"), ("key", "[B")],
            superclass=fake_parent)
        inner = vectors.secret_key_spec_object(spec=spec)
        self.assertRejectedAtDecrypt(inner, jks.UnexpectedJavaTypeException,
                                     "SecretKeySpec fake superclass")

    def test_key_rep_fake_superclass_is_rejected(self):
        """Same rule for KeyRep: no unexpected superclass state.
        Rejection stage: inner class descriptor validation."""
        fake_parent = vectors.ClassSpec("java.lang.Object", 0, 2, [])
        spec = vectors.ClassSpec(
            "java.security.KeyRep", -4757683898830641853, 2,
            [("algorithm", "Ljava/lang/String;"), ("encoded", "[B"),
             ("format", "Ljava/lang/String;"),
             ("type", "Ljava/security/KeyRep$Type;")],
            superclass=fake_parent)
        inner = vectors.key_rep_object(spec=spec)
        self.assertRejectedAtDecrypt(inner, jks.UnexpectedJavaTypeException,
                                     "KeyRep fake superclass")

    def test_wrong_serial_version_uid_is_rejected(self):
        """A class descriptor with the allowed name but a different
        serialVersionUID is a different serialized class and must not be
        accepted. Rejection stage: inner class descriptor validation."""
        wrong_suid = vectors.ClassSpec(
            "javax.crypto.spec.SecretKeySpec", 1, 2,
            [("algorithm", "Ljava/lang/String;"), ("key", "[B")])
        self.assertRejectedAtDecrypt(
            vectors.secret_key_spec_object(spec=wrong_suid),
            jks.UnexpectedJavaTypeException,
            "SecretKeySpec wrong serialVersionUID")
        wrong_suid = vectors.ClassSpec(
            "java.security.KeyRep", 1, 2,
            [("algorithm", "Ljava/lang/String;"), ("encoded", "[B"),
             ("format", "Ljava/lang/String;"),
             ("type", "Ljava/security/KeyRep$Type;")])
        self.assertRejectedAtDecrypt(
            vectors.key_rep_object(spec=wrong_suid),
            jks.UnexpectedJavaTypeException,
            "KeyRep wrong serialVersionUID")

    def test_key_rep_type_not_secret_is_rejected(self):
        """KeyRep.type != SECRET must be rejected by an explicit check, not a
        bare assert (which vanishes under -O).
        Rejection stage: KeyRep field validation in SecretKeyEntry.decrypt."""
        for constant in ("PRIVATE", "PUBLIC", "SYMMETRIC"):
            inner = vectors.key_rep_object(key_type=constant)
            self.assertRejectedAtDecrypt(inner, jks.UnexpectedJavaTypeException,
                                         "KeyRep.type=%s" % constant)

    def test_key_rep_wrong_enum_type_is_rejected(self):
        """A KeyRep.type field carrying an enum of a different class is not a
        KeyRep$Type even if the constant name says SECRET.
        Rejection stage: KeyRep.type structural validation."""
        evil_enum = vectors.ClassSpec(
            "evil.KeyRep$Type", 0, 0x12, [], superclass=vectors.ENUM_SUPER_SPEC)
        inner = vectors.key_rep_object(
            type_value=lambda writer, handles: writer.enum_constant(evil_enum, "SECRET"))
        self.assertRejectedAtDecrypt(inner, jks.UnexpectedJavaTypeException,
                                     "KeyRep.type enum class")

    def test_key_rep_type_fake_enum_descriptor_is_rejected(self):
        """An object named java.security.KeyRep$Type but serialized without the
        SC_ENUM descriptor flag is not a real enum class.
        Rejection stage: KeyRep.type structural validation."""
        fake_enum = vectors.ClassSpec(
            "java.security.KeyRep$Type", 0, 0x02, [],
            superclass=vectors.ENUM_SUPER_SPEC)
        inner = vectors.key_rep_object(
            type_value=lambda writer, handles: writer.enum_constant(fake_enum, "SECRET"))
        self.assertRejectedAtDecrypt(inner, jks.UnexpectedJavaTypeException,
                                     "KeyRep.type fake enum descriptor")

    def test_key_rep_type_not_an_enum_is_rejected(self):
        """A String placed in the KeyRep.type field must be rejected instead of
        raising a raw AttributeError (or being accepted).
        Rejection stage: KeyRep.type structural validation."""
        inner = vectors.key_rep_object(
            type_value=lambda writer, handles: writer.string("SECRET"))
        self.assertRejectedAtDecrypt(inner, jks.UnexpectedJavaTypeException,
                                     "KeyRep.type is a String")

    def test_key_rep_type_self_reference_is_rejected(self):
        """KeyRep.type referring to the KeyRep object itself is a malformed
        reference graph; javaobj hands back the KeyRep object there.
        Rejection stage: KeyRep.type structural validation."""
        def self_reference(writer, handles):
            writer.reference(handles["object"])
        inner = vectors.key_rep_object(type_value=self_reference)
        self.assertRejectedAtDecrypt(inner, jks.UnexpectedJavaTypeException,
                                     "KeyRep.type self-reference")

    def test_key_rep_missing_raw_bytes_is_rejected(self):
        """Missing RAW bytes: KeyRep.encoded = null or empty byte[] must not
        produce a zero-length secret key.
        Rejection stage: KeyRep field validation / key material check."""
        null_encoded = vectors.key_rep_object(
            encoded_value=lambda writer, handles: writer.null())
        self.assertRejectedAtDecrypt(null_encoded, jks.UnexpectedJavaTypeException,
                                     "KeyRep.encoded=null")
        empty_encoded = vectors.key_rep_object(encoded=b"")
        self.assertRejectedAtDecrypt(empty_encoded, jks.UnexpectedJavaTypeException,
                                     "KeyRep.encoded empty")

    def test_byte_fields_self_reference_is_rejected(self):
        """encoded/key fields referring back to their containing object are not
        byte arrays and must be rejected without iterating arbitrary objects.
        Rejection stage: field validation."""
        def self_reference(writer, handles):
            writer.reference(handles["object"])
        self.assertRejectedAtDecrypt(
            vectors.key_rep_object(encoded_value=self_reference),
            jks.UnexpectedJavaTypeException, "KeyRep.encoded self-reference")
        self.assertRejectedAtDecrypt(
            vectors.secret_key_spec_object(key_value=self_reference),
            jks.UnexpectedJavaTypeException, "SecretKeySpec.key self-reference")

    def test_key_rep_encoded_wrong_type_is_rejected(self):
        """KeyRep.encoded must be a byte[]; a String reference must not be
        interpreted as key bytes.
        Rejection stage: KeyRep field validation."""
        inner = vectors.key_rep_object(
            encoded_value=lambda writer, handles: writer.string("abcdefgh"))
        self.assertRejectedAtDecrypt(inner, jks.UnexpectedJavaTypeException,
                                     "KeyRep.encoded is a String")

    def test_key_rep_unsupported_format_is_rejected(self):
        """paramsAlg/sealAlg conflict is separate; format X.509 and PKCS#8 are
        declared but unimplemented and must not silently produce RAW keys.
        Rejection stage: KeyRep.format validation."""
        for key_format, exception_type in (("X.509", NotImplementedError),
                                           ("PKCS#8", NotImplementedError),
                                           ("PEM", jks.UnexpectedKeyEncodingException),
                                           ("raw", jks.UnexpectedKeyEncodingException)):
            inner = vectors.key_rep_object(key_format=key_format)
            self.assertRejectedAtDecrypt(inner, exception_type,
                                         "KeyRep.format=%s" % key_format)

    def test_key_rep_algorithm_cross_reference_is_rejected(self):
        """Duplicate/cross references: KeyRep.algorithm pointing at the encoded
        byte[] handle must not be used as an algorithm name.
        Rejection stage: KeyRep field validation."""
        def algorithm_references_encoded(writer, handles):
            writer.reference(handles["encoded"])
        inner = vectors.key_rep_object(
            algorithm_value=algorithm_references_encoded, encoded=b"12345678",
            field_order="encoded_first")
        self.assertRejectedAtDecrypt(inner, jks.UnexpectedJavaTypeException,
                                     "KeyRep.algorithm cross-reference")

    def test_secret_key_spec_missing_fields_is_rejected(self):
        """SecretKeySpec with its required fields removed altogether must not
        raise a raw AttributeError that bypasses the intended error contract.
        Rejection stage: SecretKeySpec field validation."""
        stripped = vectors.ClassSpec(
            "javax.crypto.spec.SecretKeySpec", 6577238317307289933, 2, [])
        inner = vectors.secret_key_spec_object(spec=stripped)
        self.assertRejectedAtDecrypt(inner, jks.UnexpectedJavaTypeException,
                                     "SecretKeySpec missing fields")

    def test_declared_field_types_are_enforced(self):
        """The class descriptor's declared types are checked too: a field
        declared as byte[] where a String is expected (or vice versa) must be
        rejected even if the value happens to deserialize successfully.
        Rejection stage: declared-type validation."""
        key_rep_spec = vectors.ClassSpec(
            "java.security.KeyRep", -4757683898830641853, 2,
            [("algorithm", "Ljava/lang/String;"), ("encoded", "[B"),
             ("format", "[B"), ("type", "Ljava/security/KeyRep$Type;")])
        writer = vectors.Writer()
        writer.begin_object(key_rep_spec)
        writer.string("DES")
        writer.bytes_array(b"12345678")
        writer.bytes_array(b"RAW")
        writer.enum_constant(vectors.KEYREP_TYPE_SPEC, "SECRET")
        self.assertRejectedAtDecrypt(writer.done(), jks.UnexpectedJavaTypeException,
                                     "KeyRep.format declared byte[]")

        sks_spec = vectors.ClassSpec(
            "javax.crypto.spec.SecretKeySpec", 6577238317307289933, 2,
            [("algorithm", "[B"), ("key", "[B")])
        writer = vectors.Writer()
        writer.begin_object(sks_spec)
        writer.bytes_array(b"AES")
        writer.bytes_array(b"\x00" * 16)
        self.assertRejectedAtDecrypt(writer.done(), jks.UnexpectedJavaTypeException,
                                     "SecretKeySpec.algorithm declared byte[]")

    def test_secret_key_spec_empty_material_is_rejected(self):
        """Empty algorithm name or empty key bytes are not usable key metadata.
        Rejection stage: key material check after field validation."""
        self.assertRejectedAtDecrypt(
            vectors.secret_key_spec_object(algorithm="AES", key=b""),
            jks.UnexpectedJavaTypeException, "SecretKeySpec empty key")
        self.assertRejectedAtDecrypt(
            vectors.secret_key_spec_object(algorithm="", key=b"\x00" * 16),
            jks.UnexpectedJavaTypeException, "SecretKeySpec empty algorithm")

    def test_secret_key_spec_cross_reference_is_rejected(self):
        """Duplicate/cross references: pointing the algorithm String field at a
        byte[] handle must not turn raw bytes into an algorithm name.
        Rejection stage: SecretKeySpec field validation."""
        def algorithm_references_key(writer, handles):
            writer.reference(handles["key"])
        inner = vectors.secret_key_spec_object(
            algorithm_value=algorithm_references_key, key=b"\x22" * 16,
            field_order="key_first")
        self.assertRejectedAtDecrypt(inner, jks.UnexpectedJavaTypeException,
                                     "SecretKeySpec algorithm cross-reference")

    def test_secret_key_spec_algorithm_points_at_object_is_rejected(self):
        """A self-referential algorithm field (object handle) must be rejected
        rather than exposing a JavaObject as the algorithm.
        Rejection stage: SecretKeySpec field validation."""
        def algorithm_references_self(writer, handles):
            writer.reference(handles["object"])
        inner = vectors.secret_key_spec_object(
            algorithm_value=algorithm_references_self, key=b"\x00" * 16)
        self.assertRejectedAtDecrypt(inner, jks.UnexpectedJavaTypeException,
                                     "SecretKeySpec algorithm self-reference")

    def test_params_alg_conflict_is_rejected(self):
        """paramsAlg must match sealAlg; a mismatching pair must be rejected
        before any decryption is attempted.
        Rejection stage: outer SealedObject parameter validation."""
        writer = vectors.Writer()
        writer.begin_object(vectors.sealed_object_spec())
        writer.bytes_array(vectors.pbe_parameters())
        writer.bytes_array(vectors.pbe_encrypt(vectors.secret_key_spec_object()))
        writer.string("PBEWithMD5AndDES")
        writer.string("PBEWithMD5AndTripleDES")
        entry = jks.KeyStore.loads(vectors.jceks_store(writer.done()), PASSWORD,
                                   try_decrypt_keys=False).entries[ALIAS]
        self.assertRaises(jks.UnexpectedAlgorithmException, entry.decrypt, PASSWORD)
        self.assertFalse(entry.is_decrypted())

    def test_unknown_seal_alg_is_rejected(self):
        """sealAlg outside the one implemented algorithm must be rejected rather
        than attempted.
        Rejection stage: outer SealedObject parameter validation."""
        writer = vectors.Writer()
        writer.begin_object(vectors.sealed_object_spec())
        writer.bytes_array(vectors.pbe_parameters())
        writer.bytes_array(vectors.pbe_encrypt(vectors.secret_key_spec_object()))
        writer.string("PBEWithMD5AndDES")
        writer.string("PBEWithMD5AndDES")
        entry = jks.KeyStore.loads(vectors.jceks_store(writer.done()), PASSWORD,
                                   try_decrypt_keys=False).entries[ALIAS]
        self.assertRaises(jks.UnexpectedAlgorithmException, entry.decrypt, PASSWORD)

    def test_outer_field_type_confusion_is_rejected(self):
        """encryptedContent/encodedParams declared or populated as a String is
        not a byte[]; this must not reach struct.unpack/deserialization.
        Rejection stage: outer SealedObject field validation at load time."""
        for field in ("encodedParams", "encryptedContent"):
            sealed = self.make_outer(
                params_value=(lambda writer: writer.string("ABCDEFGH")) if field == "encodedParams" else None,
                content_value=(lambda writer: writer.string("abcdefgh")) if field == "encryptedContent" else None)
            self.assertRaises(jks.UnexpectedJavaTypeException,
                              jks.KeyStore.loads, vectors.jceks_store(sealed), PASSWORD, False)

    def test_outer_empty_encrypted_content_is_rejected(self):
        """An empty encryptedContent cannot decrypt to a valid serialized key;
        reject it rather than calling strip_pkcs5_padding on empty bytes.
        Rejection stage: outer SealedObject structural validation."""
        sealed = self.make_outer(content_value=lambda writer: writer.bytes_array(b""))
        entry = jks.KeyStore.loads(vectors.jceks_store(sealed), PASSWORD,
                                   try_decrypt_keys=False).entries[ALIAS]
        self.assertRaises(jks.UnexpectedJavaTypeException, entry.decrypt, PASSWORD)

    def test_outer_non_block_aligned_content_is_rejected(self):
        """A ciphertext whose length is not a multiple of the 8-byte DES block
        size cannot be valid; reject it before calling the cipher.
        Rejection stage: outer SealedObject structural validation."""
        sealed = self.make_outer(content_value=lambda writer: writer.bytes_array(b"1234567"))
        entry = jks.KeyStore.loads(vectors.jceks_store(sealed), PASSWORD,
                                   try_decrypt_keys=False).entries[ALIAS]
        self.assertRaises(jks.UnexpectedJavaTypeException, entry.decrypt, PASSWORD)

    def test_outer_encoded_params_null_is_rejected(self):
        """A null encodedParams must raise a keystore exception at decrypt time.
        Rejection stage: outer SealedObject parameter validation."""
        sealed = self.make_outer(params_value=lambda writer: writer.null())
        entry = jks.KeyStore.loads(vectors.jceks_store(sealed), PASSWORD,
                                   try_decrypt_keys=False).entries[ALIAS]
        self.assertRaises(jks.UnexpectedJavaTypeException, entry.decrypt, PASSWORD)

    def test_outer_encrypted_content_null_is_rejected(self):
        """A null encryptedContent must raise a keystore exception at decrypt
        time instead of a TypeError from the cipher layer.
        Rejection stage: outer SealedObject structural validation."""
        sealed = self.make_outer(content_value=lambda writer: writer.null())
        entry = jks.KeyStore.loads(vectors.jceks_store(sealed), PASSWORD,
                                   try_decrypt_keys=False).entries[ALIAS]
        self.assertRaises(jks.UnexpectedJavaTypeException, entry.decrypt, PASSWORD)

    def test_outer_malformed_pbe_parameters_is_rejected(self):
        """encodedParams that are not a DER PBEParameter with an 8-byte salt
        must raise a keystore exception, not an ASN.1 ValueError.
        Rejection stage: outer SealedObject parameter validation."""
        sealed = self.make_outer(params_value=lambda writer: writer.bytes_array(b"\x30\x00"))
        entry = jks.KeyStore.loads(vectors.jceks_store(sealed), PASSWORD,
                                   try_decrypt_keys=False).entries[ALIAS]
        self.assertRaises(jks.UnexpectedJavaTypeException, entry.decrypt, PASSWORD)


class OptimizedModeTests(unittest.TestCase):
    """Run the rejection checks under `python -O` to prove they do not rely on
    assert statements. The child process re-runs the same generated vectors and
    reports a compact pass/fail line per case.

    One additional check proves that a bare assert really is stripped under -O,
    so the optimized-mode run is not passing vacuously.
    """

    def test_alternate_outer_protector_subclass_is_supported(self):
        """Outer type dispatch is intentionally by inheritance: JCE providers
        may use their own SealedObject subclass name. This is the one place
        where an attacker-chosen class name is not the acceptance criterion,
        because the inner plaintext is still fully validated.
        Control (accept) case."""
        outer_spec = vectors.ClassSpec(
            "com.example.MyKeyProtector", 123, 2, [],
            superclass=vectors.SEALED_OBJECT_SPEC)
        writer = vectors.Writer()
        writer.begin_object(outer_spec)
        writer.bytes_array(vectors.pbe_parameters())
        writer.bytes_array(vectors.pbe_encrypt(vectors.secret_key_spec_object()))
        writer.string("PBEWithMD5AndTripleDES")
        writer.string("PBEWithMD5AndTripleDES")
        entry = jks.KeyStore.loads(vectors.jceks_store(writer.done()), PASSWORD,
                                   try_decrypt_keys=False).entries[ALIAS]
        entry.decrypt(PASSWORD)
        self.assertEqual(entry.algorithm, "AES")

    def test_assertions_are_really_stripped_under_optimized_mode(self):
        """Harness sanity check: `python -O` skips a bare `assert False`, which
        is exactly why the production rejections must not use assert."""
        script = "assert False, 'must be stripped'\nprint('stripped')\n"
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        environment = dict(os.environ)
        environment["PYTHONPATH"] = repo_root
        process = subprocess.Popen(
            [sys.executable, "-O", "-c", script],
            cwd=repo_root, env=environment,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        self.assertEqual(process.returncode, 0,
                         "assert was not stripped under -O; optimized-mode "
                         "test would be meaningless:\n%s" % stderr.decode("utf-8", "replace"))
        self.assertIn(b"stripped", stdout)

    def test_rejections_hold_with_assertions_stripped(self):
        script = textwrap.dedent('''
            from tests import jceks_vectors as v
            import jks

            failures = []
            vector = v.secret_key_spec_object()
            entry = v.load_entry(vector)
            entry.decrypt(v.SECRET_KEY_PASSWORD)
            if entry.key != b"\\x00" * 16:
                failures.append("SecretKeySpec control")

            def cross_algorithm(writer, handles):
                writer.reference(handles["key"])

            def cross_self(writer, handles):
                writer.reference(handles["object"])

            def encoded_string(writer, handles):
                writer.string("abcdefgh")

            def type_string(writer, handles):
                writer.string("SECRET")

            evil_enum = v.ClassSpec("evil.KeyRep$Type", 0, 0x12, [],
                                    superclass=v.ENUM_SUPER_SPEC)

            def type_evil_enum(writer, handles):
                writer.enum_constant(evil_enum, "SECRET")

            subclass = v.ClassSpec("evil.SecretKeySpec", 6577238317307289933, 2,
                                   [], superclass=v.SECRET_KEY_SPEC_SPEC)
            stripped_sks = v.ClassSpec("javax.crypto.spec.SecretKeySpec",
                                       6577238317307289933, 2, [])
            stripped_keyrep = v.ClassSpec("java.security.KeyRep",
                                          -4757683898830641853, 2, [])

            for name, inner, expected in [
                ("keyrep-private", v.key_rep_object(key_type="PRIVATE"), jks.UnexpectedJavaTypeException),
                ("keyrep-public", v.key_rep_object(key_type="PUBLIC"), jks.UnexpectedJavaTypeException),
                ("keyrep-empty", v.key_rep_object(encoded=b""), jks.UnexpectedJavaTypeException),
                ("keyrep-null", v.key_rep_object(
                    encoded_value=lambda writer, handles: writer.null()),
                 jks.UnexpectedJavaTypeException),
                ("keyrep-type-string", v.key_rep_object(type_value=type_string),
                 jks.UnexpectedJavaTypeException),
                ("keyrep-type-self-ref", v.key_rep_object(type_value=cross_self),
                 jks.UnexpectedJavaTypeException),
                ("keyrep-type-evil-enum", v.key_rep_object(type_value=type_evil_enum),
                 jks.UnexpectedJavaTypeException),
                ("keyrep-encoded-string", v.key_rep_object(encoded_value=encoded_string),
                 jks.UnexpectedJavaTypeException),
                ("keyrep-missing-fields", v.key_rep_object(spec=stripped_keyrep),
                 jks.UnexpectedJavaTypeException),
                ("sks-empty-key", v.secret_key_spec_object(key=b""), jks.UnexpectedJavaTypeException),
                ("sks-empty-alg", v.secret_key_spec_object(algorithm=""), jks.UnexpectedJavaTypeException),
                ("sks-missing-fields", v.secret_key_spec_object(spec=stripped_sks),
                 jks.UnexpectedJavaTypeException),
                ("sks-algorithm-cross-ref", v.secret_key_spec_object(
                    algorithm_value=cross_algorithm, key=b"\\x22" * 16,
                    field_order="key_first"), jks.UnexpectedJavaTypeException),
                ("sks-algorithm-self-ref", v.secret_key_spec_object(
                    algorithm_value=cross_self), jks.UnexpectedJavaTypeException),
                ("sks-subclass", v.secret_key_spec_object(spec=subclass),
                 jks.UnexpectedJavaTypeException),
            ]:
                entry = v.load_entry(inner)
                try:
                    entry.decrypt(v.SECRET_KEY_PASSWORD)
                except expected:
                    pass
                except Exception as error:
                    failures.append("%s raised %s instead of %s" % (name, type(error).__name__, expected.__name__))
                else:
                    failures.append("%s was accepted" % name)

            if failures:
                print("FAIL: " + "; ".join(failures))
                raise SystemExit(1)
            print("OK")
        ''')
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        environment = dict(os.environ)
        environment["PYTHONPATH"] = repo_root
        process = subprocess.Popen(
            [sys.executable, "-O", "-c", script],
            cwd=repo_root, env=environment,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        self.assertEqual(process.returncode, 0,
                         "optimized-mode checks failed:\n%s\n%s" %
                         (stdout.decode("utf-8", "replace"), stderr.decode("utf-8", "replace")))


if __name__ == "__main__":
    unittest.main()
