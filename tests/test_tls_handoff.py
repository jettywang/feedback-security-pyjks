#!/usr/bin/env python
# vim: set ai et ts=4 sw=4 sts=4:
"""Tests for the JKS -> TLS hand-off checks.

These use the repository's public fixtures only. No new certificates are
generated: the Corda root/intermediate pair comes from
``tests/keystores/jks/truststore.jks`` and the same-key trio from
``tests/keystores/jks/RSA2048_3certs.jks``.
"""

from __future__ import print_function

import datetime
import os
import unittest

import jks
import jks.tls as tls

CUR_PATH = os.path.dirname(os.path.abspath(__file__))
KS_PATH = os.path.join(CUR_PATH, "keystores")
REFERENCE = datetime.datetime(2017, 1, 1, tzinfo=tls.UTC)


def load_fixtures():
    entry = jks.KeyStore.load(os.path.join(KS_PATH, "jks", "RSA2048_3certs.jks"),
                              "12345678").private_keys["mykey"]
    trust = jks.KeyStore.load(os.path.join(KS_PATH, "jks", "truststore.jks"), None)
    return entry, trust


class PublicKeyExperiments(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.entry, cls.trust = load_fixtures()
        cls.root = cls.trust.entries["cordarootca"].cert
        cls.intermediate = cls.trust.entries["cordaintermediateca"].cert

    # -- matched ---------------------------------------------------------

    def test_matched_key_and_link(self):
        for _, der in self.entry.cert_chain:
            self.assertTrue(tls.leaf_matches_private_key(self.entry.pkey_pkcs8, der))
        self.assertEqual(
            tls.verify_certificate_signature(self.intermediate, self.root)[0], tls.PASS)
        self.assertEqual(
            tls.verify_certificate_signature(self.root, self.intermediate)[0], tls.FAIL)

    # -- mismatched ------------------------------------------------------

    def test_wrong_private_key_does_not_match(self):
        other = jks.KeyStore.load(os.path.join(KS_PATH, "jks", "RSA1024.jks"),
                                  "12345678").private_keys["mykey"]
        other_cert = other.cert_chain[0][1]
        self.assertFalse(tls.leaf_matches_private_key(self.entry.pkey_pkcs8, other_cert))
        # sanity: the foreign key matches its own certificate
        self.assertTrue(tls.leaf_matches_private_key(other.pkey_pkcs8, other_cert))
        # a mismatched private key and leaf are rejected before chain work
        with self.assertRaises(tls.ChainVerificationError):
            tls.prepare_identity(other, leaf_hint=self.entry.cert_chain[0][1], now=REFERENCE)

    def test_same_key_different_name_is_not_an_issuer(self):
        leaf = self.entry.cert_chain[1][1]          # CN=RSA2048, O=2
        same_key_other_name = self.entry.cert_chain[0][1]  # CN=RSA2048, O=1
        # The signature alone passes, because both are self-signed with one key.
        self.assertEqual(
            tls.verify_certificate_signature(leaf, same_key_other_name)[0], tls.PASS)
        # The chain engine requires the name gate too, so it does not accept it.
        result = tls.verify_certificate_chain(leaf, [(0, same_key_other_name)], now=REFERENCE)
        self.assertEqual(len(result.issuer_ders), 0)
        self.assertEqual(result.checks.get("chain_links").status, tls.PASS)
        self.assertIn("self-signed", result.checks.get("chain_links").detail)

    def test_cross_family_is_a_failure_not_unverified(self):
        status, detail = tls.verify_certificate_signature(
            self.entry.cert_chain[0][1], self.intermediate)
        self.assertEqual(status, tls.FAIL)
        self.assertIn("RSA", detail)

    # -- unordered / reversed -------------------------------------------

    def test_unordered_chain_is_order_independent(self):
        forward = tls.verify_certificate_chain(
            self.intermediate, [(0, self.root)], trusted_roots=[self.root], now=REFERENCE)
        reverse = tls.verify_certificate_chain(
            self.intermediate, [(0, self.root)][::-1], trusted_roots=[self.root], now=REFERENCE)
        self.assertTrue(forward.ok)
        self.assertTrue(reverse.ok)
        self.assertEqual(forward.issuer_ders, reverse.issuer_ders)

    def test_reverse_direction_does_not_link(self):
        result = tls.verify_certificate_chain(
            self.root, [(0, self.intermediate)], trusted_roots=[self.root], now=REFERENCE)
        self.assertEqual(result.issuer_ders, [])
        # The root is a supplied anchor but there is no end-entity chain
        # above it; that is reported as unusable, not as a bad link.
        self.assertFalse(result.ok)
        self.assertEqual(result.checks.get("chain_links").status, tls.FAIL)

    def test_partial_chain_with_supplied_anchor(self):
        result = tls.verify_certificate_chain(
            self.intermediate, [], trusted_roots=[self.root], now=REFERENCE)
        self.assertTrue(result.ok)
        self.assertEqual(result.termination, "anchor")
        self.assertEqual(result.checks.get("trust_root").status, tls.PASS)

    # -- leaf ambiguity --------------------------------------------------

    def test_same_key_certificates_are_ambiguous(self):
        with self.assertRaises(tls.ChainVerificationError) as caught:
            tls.prepare_identity(self.entry, now=REFERENCE)
        self.assertIn("ambiguous", str(caught.exception))

    def test_leaf_hint_resolves_ambiguity(self):
        identity = tls.prepare_identity(
            self.entry, leaf_hint=self.entry.cert_chain[1][1], now=REFERENCE)
        self.assertEqual(identity.leaf_der, self.entry.cert_chain[1][1])

    def test_hint_that_does_not_match_is_rejected(self):
        other = jks.KeyStore.load(os.path.join(KS_PATH, "jks", "RSA1024.jks"),
                                  "12345678").private_keys["mykey"]
        with self.assertRaises(tls.ChainVerificationError):
            tls.prepare_identity(self.entry, leaf_hint=other.cert_chain[0][1], now=REFERENCE)

    # -- trust / unverified ---------------------------------------------

    def test_no_trust_claim_without_roots(self):
        result = tls.verify_certificate_chain(
            self.intermediate, [(0, self.root)], now=REFERENCE)
        self.assertFalse(result.chain_is_trusted)
        self.assertEqual(result.checks.get("trust_root").status, tls.UNVERIFIED)
        self.assertIn("trust_root", result.summary()["unverified"])

    def test_wrong_anchor_fails(self):
        result = tls.verify_certificate_chain(
            self.intermediate, [(0, self.root)],
            trusted_roots=[self.intermediate], now=REFERENCE)
        self.assertEqual(result.checks.get("trust_root").status, tls.FAIL)

    def test_expiry_is_reported_separately_from_links(self):
        result = tls.verify_certificate_chain(
            self.intermediate, [(0, self.root)], trusted_roots=[self.root],
            now=datetime.datetime(2026, 11, 13, tzinfo=tls.UTC))
        self.assertEqual(result.checks.get("chain_links").status, tls.PASS)
        self.assertEqual(result.checks.get("trust_root").status, tls.PASS)
        self.assertEqual(result.checks.get("validity_window").status, tls.FAIL)

    def test_unverified_checks_block_ok(self):
        result = tls.verify_certificate_chain(
            self.intermediate, [(0, self.root)], now=REFERENCE)
        self.assertFalse(result.ok)
        self.assertIn("trust_root", result.summary()["unverified"])

    def test_duplicate_candidate_bytes_are_not_ambiguous(self):
        result = tls.verify_certificate_chain(
            self.intermediate, [(0, self.root), (1, self.root)],
            trusted_roots=[self.root], now=REFERENCE)
        self.assertTrue(result.ok)
        self.assertEqual(result.checks.get("chain_links").status, tls.PASS)

    def test_unrelated_pool_member_is_ignored(self):
        unrelated = self.entry.cert_chain[0][1]
        result = tls.verify_certificate_chain(
            self.intermediate, [(0, unrelated), (1, self.root)],
            trusted_roots=[self.root], now=REFERENCE)
        self.assertTrue(result.ok)
        self.assertEqual(len(result.issuer_ders), 1)
        self.assertIn("[0]", result.checks.get("unused_candidates").detail)

    def test_anchor_as_leaf_is_not_a_serving_chain(self):
        result = tls.verify_certificate_chain(
            self.root, [], trusted_roots=[self.root], now=REFERENCE)
        self.assertFalse(result.ok)
        self.assertEqual(result.checks.get("chain_links").status, tls.FAIL)

    def test_undecrypted_entry_is_rejected(self):
        store = jks.KeyStore.load(os.path.join(KS_PATH, "jks", "RSA2048_3certs.jks"),
                                  "12345678", try_decrypt_keys=False)
        with self.assertRaises(tls.ChainVerificationError):
            tls.prepare_identity(store.private_keys["mykey"])


if __name__ == "__main__":
    unittest.main()
