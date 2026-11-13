#!/usr/bin/env python
# vim: set et ai ts=4 sts=4 sw=4:
"""Reproducible public-key experiments on the repository's own fixtures.

Run from the repository root::

    python tools/tls_handoff_experiment.py

This script uses only public certificate material for chain logic and
never prints private key material. The fixtures are the ones checked in
under ``tests/keystores``:

* ``jks/RSA2048_3certs.jks`` -- one keypair, three self-signed certificates
  with the same key but subjects ``O=1``, ``O=2``, ``O=3``. Serves as
  "same key, different name" and "same-subject-looking family" material.
* ``jks/truststore.jks`` -- a real two-level Corda hierarchy
  (root -> intermediate), both ECDSA/secp256k1, both expired in 2026.
  Serves as matched, mismatched, and unordered-chain material.

The three required inputs are built explicitly:

1. matched: leaf's key equals the private key, and its issuer's key
   verifies the leaf's signature.
2. mismatched: a certificate from another keypair (a different key) is
   tried against the private key; a certificate from a different key
   family is tried as an issuer; and a same-key/different-name
   certificate is rejected as an issuer by the name gate.
3. unordered/reversed: the same CA pair supplied in the reverse order;
   links must still be proven by name gate + signature, never position.
"""

from __future__ import print_function

import datetime
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

import jks
import jks.tls as tls

KEYSTORE = os.path.join(REPO, "tests", "keystores", "jks", "RSA2048_3certs.jks")
TRUSTSTORE = os.path.join(REPO, "tests", "keystores", "jks", "truststore.jks")
STORE_PASSWORD = "12345678"
REFERENCE = datetime.datetime(2017, 1, 1, tzinfo=tls.UTC)


def rule(title):
    print("\n" + "=" * 72)
    print(title)
    print("=" * 72)


def show(result):
    print("ok=%s  chain_is_trusted=%s  termination=%s"
          % (result.ok, result.chain_is_trusted, getattr(result, "termination", None)))
    for check in result.checks:
        print("  %-26s %-11s %s" % (check.name, check.status, check.detail))


def load():
    ks = jks.KeyStore.load(KEYSTORE, STORE_PASSWORD)
    entry = ks.private_keys["mykey"]
    trust = jks.KeyStore.load(TRUSTSTORE, None)
    root = trust.entries["cordarootca"].cert
    intermediate = trust.entries["cordaintermediateca"].cert
    return entry, root, intermediate


def experiment_same_key_leaf_selection(entry):
    """Three certs carry the same key. Position cannot choose the leaf."""
    rule("1. Same-key certificates: key match is ambiguous, position must not decide")
    print("cert_chain subjects: O=1 at index 0, O=2 at index 1, O=3 at index 2")
    print("each certificate's SPKI equals the private key's public key:",
          [tls.leaf_matches_private_key(entry.pkey_pkcs8, der) for _, der in entry.cert_chain])

    try:
        tls.prepare_identity(entry)
        print("UNEXPECTED: no ambiguity reported")
    except tls.ChainVerificationError as exc:
        print("prepare_identity() rejects without a hint:", exc)

    for index in (0, 1, 2):
        identity = tls.prepare_identity(entry, leaf_hint=entry.cert_chain[index][1],
                                        now=REFERENCE)
        print("\nwith leaf_hint=index %d:" % index)
        show(identity)
        print("  PEM chain length (bytes):", len(identity.to_pem()[1]))


def experiment_mismatch(entry, intermediate):
    """A different key must not match, in either direction."""
    rule("2. Mismatches: wrong key, and same key under a different name")
    other = jks.KeyStore.load(
        os.path.join(REPO, "tests", "keystores", "jks", "RSA1024.jks"), "12345678")
    wrong_key_cert = other.private_keys["mykey"].cert_chain[0][1]

    print("leaf_matches_private_key(real key, other keystore cert):",
          tls.leaf_matches_private_key(entry.pkey_pkcs8, wrong_key_cert))

    same_key_other_name = entry.cert_chain[0][1]
    print("same-key/different-name cert verifies under the leaf's own key:",
          tls.verify_certificate_signature(same_key_other_name, same_key_other_name)[0],
          "(self-signature, not an issuer proof)")

    leaf = entry.cert_chain[1][1]
    print("issuer link to the same-key, different-subject (O=1) certificate:",
          tls.verify_certificate_signature(leaf, same_key_other_name)[0],
          "-- signature-only; the name gate in the chain engine rejects it as an issuer")
    result = tls.verify_certificate_chain(
        leaf, [(0, same_key_other_name)], now=REFERENCE)
    show(result)

    print("\nCross-family mismatch: RSA leaf signature checked with the EC intermediate's key:")
    print(" ", tls.verify_certificate_signature(entry.cert_chain[0][1], intermediate))


def experiment_order(root, intermediate):
    """The CA pair in both orders; prove links by signature, not position."""
    rule("3. Unordered and reversed chains: signature proof, not position")
    for title, leaf, candidates in [
        ("natural order: leaf=intermediate, candidate=root",
         intermediate, [(1, root)]),
        ("reversed input list: leaf=intermediate, candidate=root but pool listed reverse",
         intermediate, [(1, root)][::-1]),
        ("leaf=root, candidate=intermediate (wrong direction)",
         root, [(1, intermediate)]),
        ("leaf alone, root supplied only as anchor (partial chain)",
         intermediate, []),
    ]:
        print("\n-- %s" % title)
        show(tls.verify_certificate_chain(
            leaf, candidates, trusted_roots=[root], now=REFERENCE))

    rule("4. Expired fixtures: validity is reported separately from link proof")
    show(tls.verify_certificate_chain(intermediate, [(1, root)],
                                      trusted_roots=[root], now=datetime.datetime.now(tls.UTC)))
    print("\nAt the real current time the links still verify; the validity check fails.")
    print("That separation is deliberate: a decoder must not turn an expired")
    print("certificate into a chain-integrity failure, nor an expired chain into identity.")


def experiment_trust(intermediate, root):
    rule("5. Trust is never inferred from the keystore")
    no_roots = tls.verify_certificate_chain(intermediate, [(1, root)], now=REFERENCE)
    print("without trusted_roots: trust_root =",
          no_roots.checks.get("trust_root").status,
          "| chain_is_trusted =", no_roots.chain_is_trusted)
    wrong_anchor = tls.verify_certificate_chain(
        intermediate, [(1, root)], trusted_roots=[intermediate], now=REFERENCE)
    print("with the wrong anchor (intermediate itself): trust_root =",
          wrong_anchor.checks.get("trust_root").status)
    right_anchor = tls.verify_certificate_chain(
        intermediate, [(1, root)], trusted_roots=[root], now=REFERENCE)
    print("with the root as anchor: trust_root =",
          right_anchor.checks.get("trust_root").status)


def main():
    entry, root, intermediate = load()
    experiment_same_key_leaf_selection(entry)
    experiment_mismatch(entry, intermediate)
    experiment_order(root, intermediate)
    experiment_trust(intermediate, root)
    print("\nAll experiments used certificate bytes only except the explicit")
    print("leaf_matches_private_key() calls, which compare public-key bytes derived")
    print("once from the decrypted PKCS#8 key.")


if __name__ == "__main__":
    main()
