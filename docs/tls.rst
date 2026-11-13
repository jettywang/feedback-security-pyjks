TLS hand-off checks
===================

PyJKS is a keystore decoder, not a certificate validator. This page
separates what PyJKS actually guarantees from what a TLS stack (or an
X.509 verifier such as OpenSSL) must check before a private key entry is
used as a server or client identity. The executable form of this page is
``jks/tls.py``; a runnable demonstration is
``tools/tls_handoff_experiment.py``.

What PyJKS guarantees
---------------------

``KeyStore.load`` / ``KeyStore.loads`` compute and compare the JKS/JCEKS
integrity hash over the file bytes, but only when a store password is
passed. With ``store_password=None`` the hash is skipped; the loader
cannot later tell you it was skipped.

``PrivateKeyEntry.decrypt`` checks the key-protection hash
(``sun_crypto.jks_pkey_decrypt`` raises ``BadHashCheckException`` on a
mismatch, which PyJKS maps to ``DecryptionFailureException``). A
successful decrypt therefore proves that the password is correct for
that entry. It does not prove that the key signs anything, that the
entry's certificates belong to it, or that any certificate is valid for
TLS.

``PrivateKeyEntry.cert_chain`` is a list of ``(type, der_bytes)`` tuples.
PyJKS makes no ordering guarantee beyond what is in the file, does not
parse the DER, and does not associate index 0 with the key. The
``KeyStore.certs`` property returns only ``TrustedCertEntry`` objects;
it is not the chain of a private key and its contents are not
automatically trusted.

What PyJKS does not do
----------------------

PyJKS does not:

* parse X.509 fields (subject, issuer, validity, extensions);
* verify any signature, including a certificate's own signature;
* match a certificate's public key to the private key;
* canonicalise or compare names;
* build a chain in any order;
* apply ``basicConstraints``, ``pathLenConstraint``, ``keyUsage`` or
  ``extendedKeyUsage``;
* evaluate revocation, name constraints, or policy; or
* decide trust, including whether a chain that ends in a root is a
  trusted chain.

Those checks belong to an X.509 verifier. Do not reimplement them by
re-parsing the private key: match the leaf once, then work with
certificates and public keys only.

``jks.tls`` boundary
--------------------

``jks.tls`` is a thin gate between the two layers. It needs no new
dependency: it uses PyJKS's existing ``pyasn1`` packages, with pure
Python arithmetic for RSA PKCS#1 v1.5 and ECDSA over secp256k1 and
NIST P-256.

It performs, for the entry's own material:

===========================  ==============================================
Check                        Owner / meaning
===========================  ==============================================
``store_integrity``          Reported ``UNVERIFIED``. PyJKS already did
                             it (or skipped it when no password was
                             given); the entry cannot prove which.
``private_key_decrypted``    ``PASS`` only after PyJKS's key hash. Proves
                             the password, not identity.
``certificates_parse``       DER parsing of every ``cert_chain`` member.
``leaf_matches_private_key`` Public-key equality. Never name or position.
                             The key is parsed once into public-key bytes.
``leaf_selection``           Only present when several certificates share
                             the key; resolved by ``leaf_hint`` or by a
                             unique completing chain, never by index 0.
``chain_links``              Each link requires *both* issuer-name
                             equality and a verified signature. Scans the
                             whole pool, so order is irrelevant.
``issuer_is_ca[n]``          ``basicConstraints`` on non-anchor issuers.
``path_length_constraints``  ``pathLenConstraint`` along the proven path.
``chain_terminates``         Self-signed top or supplied anchor.
``validity_window``          Reported against ``now``; ``UNVERIFIED``
                             when no reference time is supplied.
``trust_root``               ``PASS`` only against caller-supplied roots;
                             ``UNVERIFIED`` when none are supplied.
``leaf_eku`` / ``key_usage`` Explicitly ``UNVERIFIED``; for the TLS stack.
===========================  ==============================================

Every other result is ``UNVERIFIED`` with a reason. ``Checks.ok`` is true
only when every result is ``PASS`` (or informational); a single
``UNVERIFIED`` makes it false. ``ChainResult.chain_is_trusted`` is always
``False``.

Why names and positions are not evidence
----------------------------------------

* A subject name is not unique. A renewal can carry the same subject with
  a new key; a cross-sign carries the same subject and key under two
  different issuers; a compromised or misissued certificate can reuse a
  name. Distinguish them by SubjectPublicKeyInfo bytes and by signature
  verification.
* Position in ``cert_chain`` is file order. It is not a leaf marker and is
  not reliably leaf-first, issuer-next. Treat the list as an unordered
  pool.
* Signature verification alone is not enough to accept an issuer, because
  a certificate can self-sign under the same key while carrying a
  different subject (the repository's own three-certificate fixture does
  this). ``jks.tls`` therefore requires the issuer name gate as well.
* When multiple candidates pass both checks (cross-signing or a dirty
  pool), ``jks.tls`` reports ambiguity and refuses to choose by list
  order.

Repository fixtures and the three experiments
---------------------------------------------

``tests/keystores/jks/RSA2048_3certs.jks`` holds one keypair and three
self-signed certificates with subjects ``O=1``, ``O=2``, ``O=3``, all
bearing the same public key. This is a deliberately harsh case: the key
match cannot identify the leaf, so ``prepare_identity`` raises until the
caller supplies ``leaf_hint``.

``tests/keystores/jks/truststore.jks`` holds a Corda root and
intermediate (ECDSA/secp256k1). The intermediate's signature verifies
under the root; the reverse does not. Both are expired as of 2026-09-07,
which the experiment uses to show that link proof and validity are
reported separately.

Run::

    python tools/tls_handoff_experiment.py

The script builds the three required inputs from those fixtures:

1. **Matched** -- the leaf's public key equals the private key's, and the
   intermediate's issuer link verifies under the root.
2. **Mismatched** -- an RSA key from another fixture does not match the
   leaf; a same-key/different-name certificate is rejected as an issuer
   despite a passing signature; an RSA leaf against an EC issuer is a
   definite ``FAIL`` (algorithm mismatch), not ``UNVERIFIED``.
3. **Unordered/reversed** -- the CA pair submitted in reverse order still
   produces the same proven links; submitting the root as leaf with the
   intermediate as a candidate does not link; the intermediate alone with
   the root supplied as an anchor forms a valid partial chain.

The script uses public certificate bytes for all chain logic. The only
private-key access is the one derived-public-key comparison.

A TLS hand-off
--------------

::

    import jks
    import jks.tls

    store = jks.KeyStore.load("server.jks", store_password)
    entry = store.private_keys["server"]
    if not entry.is_decrypted():
        entry.decrypt(key_password)

    identity = jks.tls.prepare_identity(
        entry,
        trusted_roots=[root_der],      # explicit; no system store consulted
        now=datetime.datetime.now(jks.tls.UTC),
        leaf_hint=leaf_der,            # only needed for same-key material
    )

    # identity.ok is false while any UNVERIFIED check remains.
    for check in identity.checks:
        if check.status != jks.tls.PASS:
            print(check.name, check.status, check.detail)

    # Feed bytes to the TLS stack only after its own policy checks.
    private_key_pem, certificate_chain_pem = identity.to_pem()
    # identity.chain_is_trusted is always False; the hand-off must not
    # treat a supplied chain as a trust decision.

Do not build an ``SSLContext`` inside this module, and do not use a
``cert_chain`` merely because it loads. A chain is candidate material
until an anchor from the caller -- not from the keystore, not from the
system store -- terminates it.
