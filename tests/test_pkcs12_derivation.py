# vim: set ai et ts=4 sts=4 sw=4:
"""
Cross-check PyJKS' PKCS#12 KDF (RFC 7292, Appendix B) against an independent,
deliberately short reference implementation.

The reference in :mod:`tests.pkcs12_reference` does not import :mod:`jks`
and never calls the library's ``_adjust`` or ``derive_key``.  All inputs here
are either public test fixtures shipped with PyJKS or synthetic parameters
constructed inside the tests.
"""

from __future__ import print_function

import contextlib
import hashlib
import hmac
import os
import struct
import unittest

import jks
from jks import bks
from jks import rfc7292
from tests import pkcs12_reference as ref

CUR_PATH = os.path.dirname(os.path.abspath(__file__))
KS_PATH = os.path.join(CUR_PATH, "keystores")

MAC = rfc7292.PURPOSE_MAC_MATERIAL
KEY = rfc7292.PURPOSE_KEY_MATERIAL
IV = rfc7292.PURPOSE_IV_MATERIAL


def _u32(data, offset):
    return struct.unpack(">I", data[offset:offset + 4])[0]


def _bks_header(data):
    """Return (version, salt, iterations, entries_offset) for a BKS store."""
    version = _u32(data, 0)
    salt_len = _u32(data, 4)
    salt = data[8:8 + salt_len]
    offset = 8 + salt_len
    iterations = _u32(data, offset)
    return version, salt, iterations, offset + 4


def _uber_header(data):
    """Return (salt, iterations, ciphertext_offset) for an UBER store."""
    salt_len = _u32(data, 4)
    salt = data[8:8 + salt_len]
    offset = 8 + salt_len
    iterations = _u32(data, offset)
    return salt, iterations, offset + 4


def _sealed_pbe(data):
    """Return (salt, iterations, ciphertext) for a BKS sealed-entry blob."""
    salt_len = _u32(data, 0)
    salt = data[4:4 + salt_len]
    offset = 4 + salt_len
    iterations = _u32(data, offset)
    return salt, iterations, data[offset + 4:]


def _twofish_cbc_decrypt(ciphertext, key, iv):
    """Minimal independent CBC decryptor; PKCS#7 padding is stripped."""
    from twofish import Twofish

    cipher = Twofish(key)
    plaintext = bytearray()
    previous = bytearray(iv)
    for offset in range(0, len(ciphertext), 16):
        block = ciphertext[offset:offset + 16]
        decrypted = cipher.decrypt(block)
        plaintext.extend(bytearray(x ^ y for x, y in zip(bytearray(decrypted), previous)))
        previous = bytearray(block)

    padding = plaintext[-1]
    if padding < 1 or padding > 16 or plaintext[-padding:] != bytearray([padding]) * padding:
        raise ValueError("bad PKCS#7 padding")
    return bytes(plaintext[:-padding])


def _drop_first_carry_adjust(a, a_offset, b):
    """A deliberately buggy ``_adjust``: the least-significant carry is lost."""
    x = (b[-1] & 0xFF) + (a[a_offset + len(b) - 1] & 0xFF) + 1
    a[a_offset + len(b) - 1] = x & 0xFF
    carry = x >> 8
    if carry:
        carry = 0

    for i in range(len(b) - 2, -1, -1):
        x = (b[i] & 0xFF) + (a[a_offset + i] & 0xFF) + carry
        a[a_offset + i] = x & 0xFF
        carry = x >> 8


@contextlib.contextmanager
def _broken_carry():
    """Temporarily install a carry-dropping ``_adjust`` in the library."""
    original = rfc7292._adjust
    rfc7292._adjust = _drop_first_carry_adjust
    try:
        yield
    finally:
        rfc7292._adjust = original


def _broken_reference_blocks(purpose, password, salt, iterations, count):
    """Reference derivation with a carry bug, used only to prove sensitivity."""
    block_size = hashlib.sha1().block_size
    D = bytes(bytearray([purpose]) * block_size)
    I = ref.repeat_to_block(salt, block_size) + ref.repeat_to_block(ref.password_bytes(password), block_size)
    blocks = []

    for unused in range(count):
        A = hashlib.sha1(D + I).digest()
        for unused_iteration in range(iterations - 1):
            A = hashlib.sha1(A).digest()
        blocks.append(A)

        B = ref.repeat_to_block(A, block_size)
        next_I = bytearray()
        for offset in range(0, len(I), block_size):
            block = bytearray(I[offset:offset + block_size])
            carry = 1
            dropped = False
            for i in range(block_size - 1, -1, -1):
                total = block[i] + B[i] + carry
                block[i] = total & 0xFF
                carry = total >> 8
                if carry and not dropped:
                    carry = 0
                    dropped = True
            next_I.extend(block)
        I = bytes(next_I)

    return blocks


class Pkcs12ReferenceVectorTests(unittest.TestCase):
    """The reference itself, plus differential checks of the library against it."""

    def test_d_s_p_expansion_rules(self):
        result = ref.derive_blocks(hashlib.sha1, KEY, "A", b"\x01\x02", 1, 1)

        # D is the purpose byte repeated to the hash block size (64 for SHA-1).
        self.assertEqual(result["D"], b"\x01" * 64)

        # S and P are repeated to a positive multiple of v.  A two-byte salt
        # becomes a 64-byte block, and "A" becomes UTF-16BE 0041 + 0000.
        self.assertEqual(result["S"], b"\x01\x02" * 32)
        self.assertEqual(result["P"], (b"\x00A\x00\x00" * 16))
        self.assertEqual(result["I0"], result["S"] + result["P"])

    def test_empty_salt_expands_to_nothing(self):
        result = ref.derive_blocks(hashlib.sha1, MAC, "password", b"", 1, 3)
        self.assertEqual(result["S"], b"")
        self.assertEqual(result["I0"], result["P"])
        self.assertGreater(len(result["P"]), 0)

    def test_empty_password_expands_to_nothing(self):
        result = ref.derive_blocks(hashlib.sha1, MAC, "", b"\x01\x02", 1, 3)
        self.assertEqual(ref.password_bytes(""), b"")
        self.assertEqual(result["P"], b"")
        self.assertEqual(result["I0"], result["S"])

    def test_empty_salt_and_empty_password(self):
        for purpose in (KEY, IV, MAC):
            result = ref.derive_blocks(hashlib.sha1, purpose, "", b"", 1, 3)
            self.assertEqual(result["S"], b"")
            self.assertEqual(result["P"], b"")
            self.assertEqual(result["I0"], b"")
            self.assertEqual(result["carry_chains"], [[], [], []])
            # With I empty every round hashes only D, so all blocks are equal.
            self.assertEqual(result["blocks"][0], result["blocks"][1])
            self.assertEqual(result["blocks"][1], result["blocks"][2])

    def test_supplementary_plane_password_uses_surrogate_pairs(self):
        password = u"\U0001F600\U0001F4A9"
        # U+1F600 -> D83D DE00, U+1F4A9 -> D83D DCA9, then the terminator.
        expected_password_bytes = b"\xd8\x3d\xde\x00\xd8\x3d\xdc\xa9\x00\x00"
        self.assertEqual(ref.password_bytes(password), expected_password_bytes)

        result = ref.derive_blocks(hashlib.sha1, KEY, password, b"\x01\x02\x03\x04\x05\x06\x07\x08", 1, 1)
        self.assertEqual(result["P"], ref.repeat_to_block(expected_password_bytes, 64))
        self.assertEqual(
            result["blocks"][0],
            b"\x64\x81\xb1\xec\x27\x2f\xe6\x82\x39\x0d\xb0\x33\xa4\xa2\x18\xcd\x33\x1b\xf3\x19",
        )
        # The library must encode the same UTF-16BE code units, not UTF-8.
        self.assertEqual(
            rfc7292.derive_key(hashlib.sha1, KEY, password, b"\x01\x02\x03\x04\x05\x06\x07\x08", 1, 20),
            result["blocks"][0],
        )

    def test_reference_matches_public_bouncycastle_vectors(self):
        # These vectors are emitted by tests/java/.../BksKeystoreGeneratorTest.java,
        # i.e. by BouncyCastle's PKCS12ParametersGenerator.  They pin the reference
        # implementation to an external source rather than to PyJKS itself.
        salt = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        cases = [
            (MAC, "", salt, 1000, 16, b"\xe7\x76\x85\x01\x6a\x53\x62\x1e\x9a\x2a\x8a\x0f\x80\x00\x2e\x70"),
            (MAC, "", salt, 1000, 17, b"\xe7\x76\x85\x01\x6a\x53\x62\x1e\x9a\x2a\x8a\x0f\x80\x00\x2e\x70\xfe"),
            (KEY, "", b"\xbf\x0a\xaa\x4f\x84\xb4\x4e\x41\x16\x0a\x11\xb7\xed\x98\x58\xa0\x95\x3b\x4b\xf8", 2010, 2, b"\x1b\xee"),
            (MAC, "password", salt, 1000, 16, b"\x21\x2b\xab\x71\x42\x2d\x31\xa5\xd3\x93\x4c\x20\xe5\xe7\x7e\xb7"),
            (MAC, "password", salt, 1000, 17, b"\x21\x2b\xab\x71\x42\x2d\x31\xa5\xd3\x93\x4c\x20\xe5\xe7\x7e\xb7\xed"),
            (KEY, "password", salt, 1000, 17, b"\xe8\x0b\xdd\x02\x01\x55\x31\x7f\x30\xb8\x54\xcb\x9f\x78\x11\x81\x76"),
            (IV, "password", salt, 1000, 17, b"\x27\x68\x91\x7c\xf9\xf4\x33\xb0\xa6\x4a\x9f\xcc\xbc\x80\x5f\xd6\x48"),
        ]
        for purpose, password, salt, iterations, size, expected in cases:
            self.assertEqual(ref.derive_key(hashlib.sha1, purpose, password, salt, iterations, size), expected)

        fancy = u"ლ(ಠ益ಠლ)"
        expected = (
            b"\x5e\x3d\xab\x11\xd7\x55\x2c\xaf\x58\x2f\x61\xbd\x95\xdd\x03\xa7\x83\xa4\xf0\x2a\xeb\xdc\x86\x5c\xdb\x1e\xae\x2c\x8f\x91\x82\xa5"
            b"\x84\xbf\xab\x23\x75\x1c\x83\x96\x34\xcf\x0e\xc1\x6c\x84\xd7\x15\xd1\x7c\x10\x3d\x8b\xa8\xef\x1f\x63\xb4\x71\xdf\x15\x4f\xc2\x86"
            b"\xf9\x5c\xba\x37\xad\xd3\xe2\xb2\xaa\xb3\x37\x60\x42\x3d\x69\x29\xd1\x96\x47\x32\x6c\x41\x57\xfa\x0e\x20\x87\xd6\xa7\x40\xae\x0f"
            b"\xe8\x17\xd8\x8e\xda\x12\x53\xac\x7e\x19\x99\xc6\x26\x20\xed\x5d\xcd\x44\xe4\xed\x05\xb9\xdc\x39\x6a\x91\x1b\x00\xbb\x39\x3e\xd8"
            b"\x9b"
        )
        self.assertEqual(ref.derive_key(hashlib.sha1, KEY, fancy, salt, 1000, 129), expected)

    def test_library_matches_reference_block_by_block(self):
        # "multiple blocks" is the point: derive two or three full SHA-1 blocks
        # and compare every boundary, not only the truncated final key.
        cases = [
            ("", b"", 1, 60),
            ("", b"\x01\x02\x03\x04\x05\x06\x07\x08", 2, 60),
            ("password", b"", 3, 60),
            ("password", b"\x01\x02\x03\x04\x05\x06\x07\x08", 7, 60),
            (u"\U0001F600\U0001F4A9", b"\x01\x02\x03\x04\x05\x06\x07\x08", 3, 60),
            (u"a\U0001F600ლ", b"\xff", 4, 60),
            ("x" * 33, b"\x00" * 65, 2, 60),
        ]
        for password, salt, iterations, size in cases:
            for purpose in (KEY, IV, MAC):
                expected = ref.derive_blocks(hashlib.sha1, purpose, password, salt, iterations, (size + 19) // 20)
                for count in (1, 2, 3):
                    prefix = b"".join(expected["blocks"][:count])
                    actual = rfc7292.derive_key(hashlib.sha1, purpose, password, salt, iterations, len(prefix))
                    self.assertEqual(actual, prefix,
                                     "purpose=%d salt=%d password=%d iterations=%d blocks=%d" %
                                     (purpose, len(salt), len(password), iterations, count))

    def test_reference_matches_library_over_many_input_shapes(self):
        salt_lengths = [0, 1, 2, 7, 8, 9, 19, 20, 21, 63, 64, 65, 127, 128, 129]
        password_lengths = [0, 1, 2, 3, 31, 32, 33, 64, 65]
        sizes = [0, 1, 19, 20, 21, 39, 40, 41, 64, 80, 81, 129]
        for salt_len in salt_lengths:
            salt = bytes(bytearray(((i * 37 + 11) & 0xFF) for i in range(salt_len)))
            for password_len in password_lengths:
                password = "A" * password_len
                for purpose in (KEY, IV, MAC):
                    for size in sizes:
                        self.assertEqual(
                            rfc7292.derive_key(hashlib.sha1, purpose, password, salt, 3, size),
                            ref.derive_key(hashlib.sha1, purpose, password, salt, 3, size),
                            "salt=%d password=%d purpose=%d size=%d" %
                            (salt_len, password_len, purpose, size),
                        )


class Pkcs12CarryTests(unittest.TestCase):
    """I-block carry propagation, including deliberately long carry chains."""

    def test_carry_chain_through_a_full_i_block(self):
        # An all-0xff salt block forces the +1 to propagate through all 64
        # bytes of I, which is the longest carry chain SHA-1's block size allows.
        salt = b"\xff" * 64
        expected = {
            KEY: [b"\x7b\x60\x10\xff\x5f\x05\x6b\x6d\x22\xf3\xef\xc3\xc0\xf5\x47\x26\xe7\xd9\xc8\x72",
                  b"\x76\xe0\x49\xc0\x22\x85\xb1\x80\x1c\xb6\x18\x16\x64\xb2\x1d\xf1\x26\x7a\xa6\x2d"],
            IV: [b"\x27\x68\xa1\xd0\x2f\xcf\x53\x58\xd4\x84\x39\x2b\x66\x37\xca\x4c\x1b\xd9\x8b\x47",
                 b"\xd6\x53\xae\x3a\xe9\xb3\x7d\x03\xac\x86\x28\x19\xd7\x95\xb0\xdc\xe7\x59\x89\xe3"],
            MAC: [b"\x79\xa9\xf0\x2b\xc9\xbf\x03\x7a\x58\xa1\xf6\x94\xa4\xfc\x24\x53\xd2\x5c\x2c\x48",
                  b"\xf5\x38\xff\xe9\x9d\x22\x9e\x20\xd9\xea\x26\x54\xdb\xc5\xc4\x61\x0e\xbf\x4a\xa3"],
        }
        for purpose in (KEY, IV, MAC):
            result = ref.derive_blocks(hashlib.sha1, purpose, "", salt, 2, 2)
            self.assertEqual(result["blocks"], expected[purpose])
            self.assertEqual(result["carry_chains"][0], [64])
            self.assertIn(result["carry_chains"][1][0], (1, 2))
            for size in (1, 20, 40):
                self.assertEqual(rfc7292.derive_key(hashlib.sha1, purpose, "", salt, 2, size),
                                 b"".join(expected[purpose])[:size])

    def test_consecutive_carry_across_two_i_blocks(self):
        # 128 bytes of salt produce two all-0xff I-blocks; both carry fully in
        # the first round.  This is the cross-block carry case explicitly.
        result = ref.derive_blocks(hashlib.sha1, KEY, "", b"\xff" * 128, 2, 2)
        self.assertEqual(len(result["I0"]), 128)
        self.assertEqual(result["carry_chains"][0], [64, 64])
        self.assertEqual(result["carry_chains"][1], [0, 0])
        self.assertEqual(result["blocks"][0],
                         b"\x30\x6f\x52\x68\xb7\x41\x7a\x96\xc1\xee\x57\x22\x16\xac\xd0\x4e\xa5\x1d\xfd\x5e")
        self.assertEqual(result["blocks"][1],
                         b"\x67\x33\x39\x0c\x46\x18\x2c\xa1\xde\x1a\xc2\x5e\xdf\xc1\xdd\x4f\xa6\xa7\x71\xb0")

    def test_broken_carry_changes_the_next_block(self):
        # This is the mutation self-check: if the +1 carry is dropped, the
        # first A block stays intact (it is hashed before I is adjusted) while
        # every later block changes.  Both the BKS MAC intermediate-block check
        # and the UBER decryption sample below must notice this.
        salt = b"\xff" * 64
        for purpose in (KEY, IV, MAC):
            good = ref.derive_blocks(hashlib.sha1, purpose, "", salt, 2, 2)["blocks"]
            broken = _broken_reference_blocks(purpose, "", salt, 2, 2)
            self.assertEqual(good[0], broken[0])
            self.assertNotEqual(good[1], broken[1])

    def test_mutating_library_adjust_breaks_carry_vectors(self):
        # Patch only the library; the reference is unaffected.  The derived
        # vector must change, proving the assertions above are carry-sensitive.
        salt = b"\xff" * 64
        with _broken_carry():
            for purpose in (KEY, IV, MAC):
                mutated = rfc7292.derive_key(hashlib.sha1, purpose, "", salt, 2, 40)
                expected = b"".join(ref.derive_blocks(hashlib.sha1, purpose, "", salt, 2, 2)["blocks"])
                self.assertNotEqual(mutated, expected)
                self.assertEqual(mutated[:20], expected[:20])
                self.assertNotEqual(mutated[20:40], expected[20:40])


class KeystoreDerivationChecks(object):
    """Shared assertions, so the mutation tests can run the exact same checks."""

    def assert_bks_mac_derivation(self, filename, password):
        with open(os.path.join(KS_PATH, filename), "rb") as f:
            data = f.read()

        version, salt, iterations, entries_offset = _bks_header(data)
        store_body = data[entries_offset:-20]
        stored_mac = data[-20:]
        mac_key_size = 2 if version == 1 else 20

        expected = ref.derive_blocks(hashlib.sha1, MAC, password, salt, iterations, 2)
        self.assertEqual(expected["D"], b"\x03" * 64)
        self.assertEqual(expected["S"], ref.repeat_to_block(salt, 64))
        self.assertEqual(expected["P"], ref.repeat_to_block(ref.password_bytes(password), 64))
        # At least one fixture's I-block must carry in the round that produces
        # the second block; otherwise the cross-block path is untested.
        self.assertTrue(any(chain > 0 for chain in expected["carry_chains"][0]) or
                        any(chain > 0 for chain in expected["carry_chains"][1]))

        # Compare the intermediate blocks, not just the truncated MAC key.
        block1 = rfc7292.derive_key(hashlib.sha1, MAC, password, salt, iterations, 20)
        block1_and_2 = rfc7292.derive_key(hashlib.sha1, MAC, password, salt, iterations, 40)
        self.assertEqual(block1, expected["blocks"][0])
        self.assertEqual(block1_and_2[:20], expected["blocks"][0])
        self.assertEqual(block1_and_2[20:40], expected["blocks"][1])
        self.assertEqual(block1_and_2[:mac_key_size], block1[:mac_key_size])

        # Final result: the stored HMAC over the entry blob.
        self.assertEqual(hmac.new(block1_and_2[:mac_key_size], store_body, hashlib.sha1).digest(), stored_mac)

        # The real loader must accept the store with that password.
        store = bks.BksKeyStore.load(os.path.join(KS_PATH, filename), password, try_decrypt_keys=False)
        self.assertEqual(store.version, version)

    def assert_uber_decryption(self, filename, password):
        with open(os.path.join(KS_PATH, filename), "rb") as f:
            data = f.read()

        salt, iterations, ciphertext_offset = _uber_header(data)
        ciphertext = data[ciphertext_offset:]

        key_blocks = ref.derive_blocks(hashlib.sha1, KEY, password, salt, iterations, 2)
        iv_block = ref.derive_blocks(hashlib.sha1, IV, password, salt, iterations, 1)

        # Key and IV intermediate blocks from the library must line up exactly.
        self.assertEqual(rfc7292.derive_key(hashlib.sha1, KEY, password, salt, iterations, 20),
                         key_blocks["blocks"][0])
        self.assertEqual(rfc7292.derive_key(hashlib.sha1, KEY, password, salt, iterations, 32),
                         (key_blocks["blocks"][0] + key_blocks["blocks"][1])[:32])
        self.assertEqual(rfc7292.derive_key(hashlib.sha1, IV, password, salt, iterations, 16),
                         iv_block["blocks"][0][:16])

        key = (key_blocks["blocks"][0] + key_blocks["blocks"][1])[:32]
        iv = iv_block["blocks"][0][:16]

        # Final result: decrypt the whole store and check its embedded SHA-1.
        plaintext = _twofish_cbc_decrypt(ciphertext, key, iv)
        self.assertEqual(hashlib.sha1(plaintext[:-20]).digest(), plaintext[-20:])
        self.assertEqual(plaintext, rfc7292.decrypt_PBEWithSHAAndTwofishCBC(ciphertext, password, salt, iterations))

        # The real UBER loader must unpack the same entry blob.
        store = bks.UberKeyStore.load(os.path.join(KS_PATH, filename), password, try_decrypt_keys=False)
        self.assertEqual(store.version, 1)


class Pkcs12KeystoreIntegrationTests(KeystoreDerivationChecks, unittest.TestCase):
    """Feed derived vectors into real BKS and UBER code paths."""

    def test_bks_v1_mac_from_public_fixture(self):
        self.assert_bks_mac_derivation("bks/christmas.bksv1", "12345678")

    def test_bks_v2_mac_from_public_fixture(self):
        self.assert_bks_mac_derivation("bks/christmas.bksv2", "12345678")

    def test_bks_v2_mac_with_custom_entry_passwords(self):
        self.assert_bks_mac_derivation("bks/custom_entry_passwords.bksv2", "store_password")

    def test_bks_v2_mac_with_empty_password(self):
        # Synthetic store: empty store password, carry-heavy salt, MAC purpose.
        # (The entry blob is just the end-of-list marker; no keys are present.)
        password = ""
        salt = b"\xff" * 64
        iterations = 2
        store_body = b"\x00"
        expected = ref.derive_blocks(hashlib.sha1, MAC, password, salt, iterations, 2)
        self.assertEqual(expected["carry_chains"][0], [64])
        mac_key = expected["blocks"][0][:20]
        store = (struct.pack(">I", 2) + struct.pack(">I", len(salt)) + salt +
                 struct.pack(">I", iterations) + store_body +
                 hmac.new(mac_key, store_body, hashlib.sha1).digest())

        loaded = bks.BksKeyStore.loads(store, password)
        self.assertEqual(loaded.version, 2)
        self.assertEqual(rfc7292.derive_key(hashlib.sha1, MAC, password, salt, iterations, 40),
                         expected["blocks"][0] + expected["blocks"][1])

    def test_uber_decryption_from_public_fixture(self):
        self.assert_uber_decryption("uber/christmas.uber", "12345678")

    def test_uber_decryption_with_custom_entry_passwords(self):
        self.assert_uber_decryption("uber/custom_entry_passwords.uber", "store_password")

    def test_uber_decryption_with_empty_password(self):
        self.assert_uber_decryption("uber/empty.uber", "")

    def test_bks_sealed_entry_uses_derived_key_and_iv(self):
        # A BKS sealed key uses the same KDF with KEY and IV purposes, but the
        # key block is 24 bytes (3DES), so the second block is used in full.
        filename = "bks/custom_entry_passwords.bksv2"
        store = bks.BksKeyStore.load(os.path.join(KS_PATH, filename), "store_password", try_decrypt_keys=False)
        entry = store.entries["sealed_private_key"]
        salt, iterations, ciphertext = _sealed_pbe(entry._encrypted)

        iv_block = ref.derive_blocks(hashlib.sha1, IV, "private_password", salt, iterations, 1)
        key_blocks = ref.derive_blocks(hashlib.sha1, KEY, "private_password", salt, iterations, 2)
        self.assertEqual(rfc7292.derive_key(hashlib.sha1, IV, "private_password", salt, iterations, 8),
                         iv_block["blocks"][0][:8])
        self.assertEqual(rfc7292.derive_key(hashlib.sha1, KEY, "private_password", salt, iterations, 24),
                         (key_blocks["blocks"][0] + key_blocks["blocks"][1])[:24])

        from Cryptodome.Cipher import DES3
        from jks.util import strip_pkcs7_padding
        key = (key_blocks["blocks"][0] + key_blocks["blocks"][1])[:24]
        iv = iv_block["blocks"][0][:8]
        plaintext = strip_pkcs7_padding(DES3.new(key, DES3.MODE_CBC, IV=iv).decrypt(ciphertext), 8)
        self.assertEqual(plaintext, rfc7292.decrypt_PBEWithSHAAnd3KeyTripleDESCBC(
            ciphertext, "private_password", salt, iterations))

        entry.decrypt("private_password")
        self.assertTrue(entry.is_decrypted())
        self.assertEqual(entry.type, bks.KEY_TYPE_PRIVATE)


class Pkcs12CarryMutationIntegrationTests(KeystoreDerivationChecks, unittest.TestCase):
    """Temporarily break one carry and prove the integration assertions fail."""

    def test_dropped_carry_breaks_bks_mac_intermediate_block(self):
        # The BKS v2 MAC key is the first 20-byte block only.  Mutating a carry
        # therefore leaves the final HMAC intact, but the intermediate-block
        # comparison in assert_bks_mac_derivation must still fail.  This is
        # exactly why the test checks blocks, not just the resulting MAC.
        filename = "bks/custom_entry_passwords.bksv2"
        password = "store_password"

        with _broken_carry():
            self.assertRaises(AssertionError, self.assert_bks_mac_derivation, filename, password)

        # Sanity check the reasoning above with the same fixture parameters:
        # the HMAC key (block 1) is unaffected, so a MAC-only assertion would
        # silently pass and miss the broken carry.
        with open(os.path.join(KS_PATH, filename), "rb") as f:
            data = f.read()
        version, salt, iterations, entries_offset = _bks_header(data)
        expected = ref.derive_blocks(hashlib.sha1, MAC, password, salt, iterations, 2)
        with _broken_carry():
            mutated_block1 = rfc7292.derive_key(hashlib.sha1, MAC, password, salt, iterations, 20)
            mutated_block2 = rfc7292.derive_key(hashlib.sha1, MAC, password, salt, iterations, 40)[20:40]
        self.assertEqual(mutated_block1, expected["blocks"][0])
        self.assertNotEqual(mutated_block2, expected["blocks"][1])
        store_body = data[entries_offset:-20]
        self.assertEqual(
            hmac.new(mutated_block1, store_body, hashlib.sha1).digest(),
            hmac.new(expected["blocks"][0], store_body, hashlib.sha1).digest(),
        )

    def test_dropped_carry_breaks_uber_decryption(self):
        # UBER uses a 32-byte Twofish key: block 1 plus 12 bytes of block 2.
        # The mutated carry changes block 2, so both the intermediate-block
        # comparison and the real decryption must fail.
        filename = "uber/custom_entry_passwords.uber"
        password = "store_password"

        with open(os.path.join(KS_PATH, filename), "rb") as f:
            store_bytes = f.read()

        with _broken_carry():
            self.assertRaises(AssertionError, self.assert_uber_decryption, filename, password)
            self.assertRaises(jks.util.DecryptionFailureException,
                              bks.UberKeyStore.loads, store_bytes, password)

    def test_dropped_carry_breaks_sealed_entry_decryption(self):
        filename = os.path.join(KS_PATH, "bks/custom_entry_passwords.bksv2")
        with _broken_carry():
            store = bks.BksKeyStore.load(filename, "store_password", try_decrypt_keys=False)
            self.assertRaises(jks.util.DecryptionFailureException,
                              store.entries["sealed_private_key"].decrypt, "private_password")
        store = bks.BksKeyStore.load(filename, "store_password", try_decrypt_keys=False)
        store.entries["sealed_private_key"].decrypt("private_password")
        self.assertTrue(store.entries["sealed_private_key"].is_decrypted())


if __name__ == "__main__":
    unittest.main()
