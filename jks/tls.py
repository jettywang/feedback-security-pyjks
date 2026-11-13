# vim: set et ai ts=4 sts=4 sw=4:
"""Checks that stage a PyJKS private key entry for a TLS hand-off.

PyJKS is a keystore *decoder*. ``KeyStore.load``/``loads`` checks the
JKS/JCEKS integrity hash when given the store password; ``decrypt``
checks the key-protection hash for the key password; the entry then
exposes DER bytes. PyJKS does not parse X.509 semantics and does not
verify signatures, names, dates, CA constraints, extended key usage, or
trust. It also never associates ``cert_chain[0]`` with the private key.

Those missing checks are what this module covers. It is explicit about
the boundary:

* It verifies *local* facts: the leaf certificate owns the private key,
  and each certificate in a chain was signed by the next one.
* It reports as ``UNVERIFIED`` anything it cannot prove, including
  store integrity (already PyJKS's job), trust roots, validity when no
  reference time is supplied, and EKU/keyUsage enforcement. It never
  upgrades "not disproven" to "verified".
* It never creates a TLS context and never sets ``chain_is_trusted``.

Nothing is decided from a subject/issuer name, an alias, or
``cert_chain`` position. Name equality is used only as a *gate* on an
issuer link (RFC 5280 requires the issuer name to equal the issuer's
subject), and that gate is applied to DER-encoded names without any
name-canonicalization library. Same-subject certificates (renewals,
cross-signs, duplicate key material) are separated by
SubjectPublicKeyInfo bytes and signature verification. ``cert_chain`` is
treated as an unordered pool of issuer candidates.

The X.509 layer uses only PyJKS's existing ``pyasn1``/``pyasn1_modules``
dependencies. RSA PKCS#1 v1.5 and ECDSA over secp256k1 / NIST P-256
canonical signatures are checked in pure Python; other algorithms yield
``UNVERIFIED`` rather than a guess.
"""

import binascii
import hashlib
from datetime import datetime, timedelta, tzinfo

from pyasn1.codec.der import decoder, encoder
from pyasn1.type import univ, namedtype
from pyasn1_modules import rfc5280, rfc5208, rfc8017

from .util import RSA_ENCRYPTION_OID, NotYetDecryptedException, as_pem

PASS = "pass"
FAIL = "fail"
UNVERIFIED = "unverified"
INFO = "info"


class _UTC(tzinfo):
    """Minimal UTC tzinfo, so this module runs on Python 2.6+."""

    def utcoffset(self, dt):
        return timedelta(0)

    def tzname(self, dt):
        return "UTC"

    def dst(self, dt):
        return timedelta(0)


UTC = _UTC()


def _int_from_bytes(value):
    if hasattr(int, "from_bytes"):
        return int.from_bytes(value, "big")
    return int(value.encode("hex"), 16)


def _int_to_bytes(value, size):
    if hasattr(int, "to_bytes"):
        return value.to_bytes(size, "big")
    return ("%0*x" % (size * 2, value)).encode("ascii").decode("hex")

_EC_PUBLIC_KEY = (1, 2, 840, 10045, 2, 1)
_SECP256K1 = (1, 3, 132, 0, 10)
_NIST_P256 = (1, 2, 840, 10045, 3, 1, 7)

_SHA1_RSA = (1, 2, 840, 113549, 1, 1, 5)
_SHA256_RSA = (1, 2, 840, 113549, 1, 1, 11)
_SHA384_RSA = (1, 2, 840, 113549, 1, 1, 12)
_SHA512_RSA = (1, 2, 840, 113549, 1, 1, 13)
_ECDSA_SHA256 = (1, 2, 840, 10045, 4, 3, 2)
_ECDSA_SHA384 = (1, 2, 840, 10045, 4, 3, 3)
_ECDSA_SHA512 = (1, 2, 840, 10045, 4, 3, 4)

_BASIC_CONSTRAINTS = (2, 5, 29, 19)

_RSA_SIG_ALGS = {_SHA1_RSA: "sha1", _SHA256_RSA: "sha256",
                 _SHA384_RSA: "sha384", _SHA512_RSA: "sha512"}
_ECDSA_SIG_ALGS = {_ECDSA_SHA256: "sha256", _ECDSA_SHA384: "sha384",
                   _ECDSA_SHA512: "sha512"}

_RSA_DIGEST_INFO_PREFIX = {
    "sha1": binascii.unhexlify("3021300906052b0e03021a05000414"),
    "sha256": binascii.unhexlify("3031300d060960864801650304020105000420"),
    "sha384": binascii.unhexlify("3041300d060960864801650304020205000430"),
    "sha512": binascii.unhexlify("3051300d060960864801650304020305000440"),
}

_EC_CURVES = {
    _SECP256K1: {
        "p": 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
        "a": 0,
        "n": 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
        "gx": 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
        "gy": 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
    },
    _NIST_P256: {
        "p": 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
        "a": 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC,
        "n": 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
        "gx": 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
        "gy": 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
    },
}


class Check(object):
    """One named result: ``PASS``, ``FAIL``, or ``UNVERIFIED``."""

    def __init__(self, name, status, detail=""):
        assert status in (PASS, FAIL, UNVERIFIED, INFO)
        self.name = name
        self.status = status
        self.detail = detail

    def __repr__(self):
        return "Check(%r, %r, %r)" % (self.name, self.status, self.detail)


class Checks(object):
    """Ordered results and a compact summary.

    ``ok`` requires every result to be ``PASS``. A single ``UNVERIFIED``
    makes it false: callers must opt in knowingly, they cannot read
    "not disproven" as "verified".
    """

    def __init__(self):
        self.results = []

    def add(self, name, status, detail=""):
        self.results.append(Check(name, status, detail))
        return self.results[-1]

    def ok(self):
        return bool(self.results) and all(r.status in (PASS, INFO) for r in self.results)

    def failed(self):
        return [r for r in self.results if r.status == FAIL]

    def unverified(self):
        return [r for r in self.results if r.status == UNVERIFIED]

    def get(self, name):
        for result in self.results:
            if result.name == name:
                return result
        return None

    def __iter__(self):
        return iter(self.results)

    def __len__(self):
        return len(self.results)

    def summary(self):
        return {
            "ok": self.ok(),
            "failed": [r.name for r in self.failed()],
            "unverified": [r.name for r in self.unverified()],
            "passed": [r.name for r in self.results if r.status == PASS],
            "info": [r.name for r in self.results if r.status == INFO],
        }


class ChainVerificationError(Exception):
    """The entry cannot be used as TLS identity (not decrypted,
    malformed, or leaf cannot be unambiguously matched)."""


class ChainResult(object):
    """A locally proven chain plus the checks that remain outstanding."""

    def __init__(self, leaf_der, issuers, checks, termination):
        self.leaf_der = leaf_der
        self.issuer_ders = list(issuers)
        self.checks = checks
        self.termination = termination  # "self-signed", "anchor", or None
        self.chain_is_trusted = False

    @property
    def ok(self):
        return self.checks.ok()

    def certificate_ders(self):
        """Leaf first, then issuers in proven upward order."""
        return [self.leaf_der] + self.issuer_ders

    def summary(self):
        return self.checks.summary()


class Identity(ChainResult):
    """ChainResult for a private key entry, plus hand-off byte material."""

    def __init__(self, alias, private_key_der, leaf_der, issuers, checks, termination):
        ChainResult.__init__(self, leaf_der, issuers, checks, termination)
        self.alias = alias
        self.private_key_der = private_key_der

    def to_pem(self):
        """``(private_key_pem, certificate_chain_pem)`` for a TLS library
        that accepts PEM. The key is always PKCS#8. This does not make the
        chain trusted."""
        key_pem = as_pem(self.private_key_der, "PRIVATE KEY")
        chain_pem = "".join(as_pem(der, "CERTIFICATE") for der in self.certificate_ders())
        return key_pem, chain_pem


def _oid(value):
    return tuple(int(part) for part in value.asTuple())


def _parse_cert(der):
    return decoder.decode(der, asn1Spec=rfc5280.Certificate())[0]


def _encode_cert(cert):
    return encoder.encode(cert)


def _tbs_der(cert):
    return encoder.encode(cert["tbsCertificate"])


def _subject_der(cert):
    return encoder.encode(cert["tbsCertificate"]["subject"])


def _issuer_der(cert):
    return encoder.encode(cert["tbsCertificate"]["issuer"])


def _spki_der(cert):
    return encoder.encode(cert["tbsCertificate"]["subjectPublicKeyInfo"])


def _spki_id(cert):
    return hashlib.sha256(_spki_der(cert)).hexdigest()[:16]


def _rsa_public_from_spki(spki):
    key = decoder.decode(spki["subjectPublicKey"].asOctets(), asn1Spec=rfc8017.RSAPublicKey())[0]
    return int(key["modulus"]), int(key["publicExponent"])


def _rsa_private_public(pkey_pkcs8):
    info = decoder.decode(pkey_pkcs8, asn1Spec=rfc5208.PrivateKeyInfo())[0]
    key = decoder.decode(info["privateKey"].asOctets(), asn1Spec=rfc8017.RSAPrivateKey())[0]
    return int(key["modulus"]), int(key["publicExponent"])


def _rsa_public_der(modulus, exponent):
    key = rfc8017.RSAPublicKey()
    key.setComponentByName("modulus", modulus)
    key.setComponentByName("publicExponent", exponent)
    return encoder.encode(key)


def _curve_oid(algorithm):
    parameters = algorithm["parameters"]
    if not parameters.hasValue():
        raise ValueError("EC SubjectPublicKeyInfo has no curve parameters")
    try:
        decoded = decoder.decode(parameters.asOctets())[0]
        return _oid(decoded)
    except Exception as exc:
        raise ValueError("cannot decode EC curve parameters: %s" % exc)


def _ec_public_from_spki(spki):
    curve = _curve_oid(spki["algorithm"])
    if curve not in _EC_CURVES:
        raise ValueError("unsupported EC curve %r" % (curve,))
    raw = spki["subjectPublicKey"].asOctets()
    if len(raw) != 65 or raw[0] != 4:
        raise ValueError("expected an uncompressed EC point")
    return curve, (_int_from_bytes(raw[1:33]), _int_from_bytes(raw[33:65]))


def _ec_public_der(curve, point):
    return b"\x04" + _int_to_bytes(point[0], 32) + _int_to_bytes(point[1], 32)


def _public_key_from_cert_der(cert_der):
    cert = _parse_cert(cert_der)
    spki = cert["tbsCertificate"]["subjectPublicKeyInfo"]
    alg = _oid(spki["algorithm"]["algorithm"])
    if alg == RSA_ENCRYPTION_OID:
        return alg, _rsa_public_der(*_rsa_public_from_spki(spki))
    if alg == _EC_PUBLIC_KEY:
        return alg, _ec_public_der(*_ec_public_from_spki(spki))
    raise ValueError("unsupported certificate key algorithm %r" % (alg,))


def public_key_der_from_private_key(pkey_pkcs8):
    """Public-key DER derived from a decrypted PKCS#8 private key.

    This is the only read of the private key used for matching. All chain
    work below takes public keys, so the private key is parsed once and
    is never re-parsed to verify links.
    """
    info = decoder.decode(pkey_pkcs8, asn1Spec=rfc5208.PrivateKeyInfo())[0]
    alg = _oid(info["privateKeyAlgorithm"]["algorithm"])
    if alg == RSA_ENCRYPTION_OID:
        return _rsa_public_der(*_rsa_private_public(pkey_pkcs8))
    if alg == _EC_PUBLIC_KEY:
        raise ValueError("EC public-key extraction from a private key is not implemented; "
                         "use a crypto library for the leaf match")
    raise ValueError("unsupported private key algorithm %r" % (alg,))


def public_key_der_from_certificate(cert_der):
    """Public-key DER from a DER certificate."""
    return _public_key_from_cert_der(cert_der)[1]


def leaf_matches_private_key(pkey_pkcs8, cert_der):
    """True when the certificate's public key equals the private key's.

    Compares canonical public-key bytes; subject name and chain position
    are irrelevant. Returns False on unsupported algorithms rather than
    raising, so a mismatch is reportable.
    """
    try:
        key_alg = _oid(decoder.decode(pkey_pkcs8, asn1Spec=rfc5208.PrivateKeyInfo())[0]
                       ["privateKeyAlgorithm"]["algorithm"])
        cert_alg, cert_key = _public_key_from_cert_der(cert_der)
        if key_alg != cert_alg:
            return False
        return public_key_der_from_private_key(pkey_pkcs8) == cert_key
    except Exception:
        return False


def _digest(name, data):
    return hashlib.new(name, data).digest()


def _rsa_pkcs1_v15_verify(signature, tbs_der, digest_name, modulus, exponent):
    size = (modulus.bit_length() + 7) // 8
    if len(signature) != size:
        return False
    value = _int_from_bytes(signature)
    if value >= modulus:
        return False
    recovered = _int_to_bytes(pow(value, exponent, modulus), size)
    expected = _RSA_DIGEST_INFO_PREFIX[digest_name] + _digest(digest_name, tbs_der)
    gap = size - len(expected) - 3
    return (gap >= 8
            and recovered[0] == 0
            and recovered[1] == 1
            and recovered[2:2 + gap] == b"\xff" * gap
            and recovered[2 + gap] == 0
            and recovered[3 + gap:] == expected)


class _EcdsaSignature(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("r", univ.Integer()),
        namedtype.NamedType("s", univ.Integer()),
    )


def _ec_add(p1, p2, p, a):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    (x1, y1), (x2, y2) = p1, p2
    if x1 == x2 and (y1 + y2) % p == 0:
        return None
    if p1 == p2:
        if y1 == 0:
            return None
        slope = (3 * x1 * x1 + a) * pow(2 * y1, p - 2, p) % p
    else:
        slope = (y2 - y1) * pow(x2 - x1, p - 2, p) % p
    x3 = (slope * slope - x1 - x2) % p
    return x3, (slope * (x1 - x3) - y1) % p


def _ec_multiply(k, point, p, a):
    result = None
    addend = point
    while k:
        if k & 1:
            result = _ec_add(result, addend, p, a)
        addend = _ec_add(addend, addend, p, a)
        k >>= 1
    return result


def _ecdsa_verify(signature, tbs_der, digest_name, curve_oid, point):
    curve = _EC_CURVES[curve_oid]
    p, a, n = curve["p"], curve["a"], curve["n"]
    parsed = decoder.decode(signature, asn1Spec=_EcdsaSignature())[0]
    r, s = int(parsed["r"]), int(parsed["s"])
    if not (1 <= r < n and 1 <= s < n):
        return False
    e = _int_from_bytes(_digest(digest_name, tbs_der))
    w = pow(s, n - 2, n)
    base = curve["gx"], curve["gy"]
    candidate = _ec_add(_ec_multiply(e * w % n, base, p, a),
                        _ec_multiply(r * w % n, point, p, a), p, a)
    return candidate is not None and candidate[0] % n == r


def verify_certificate_signature(subject_der, issuer_der):
    """Prove that ``subject_der`` was signed by the key in ``issuer_der``.

    Reads the signature over the subject's TBSCertificate and the issuer's
    public key. Subject/issuer names are deliberately not read here, so
    this answers only "did this key sign that content".

    Returns ``(status, detail)``: ``PASS``, ``FAIL``, or ``UNVERIFIED``
    for algorithms outside the supported set.
    """
    try:
        subject = _parse_cert(subject_der)
        issuer = _parse_cert(issuer_der)
    except Exception as exc:
        return FAIL, "certificate parse failed: %s" % exc
    sig_alg = _oid(subject["signatureAlgorithm"]["algorithm"])
    tbs = _tbs_der(subject)
    signature = subject["signature"].asOctets()
    spki = issuer["tbsCertificate"]["subjectPublicKeyInfo"]
    key_alg = _oid(spki["algorithm"]["algorithm"])
    try:
        if key_alg == RSA_ENCRYPTION_OID:
            if sig_alg in _ECDSA_SIG_ALGS:
                return FAIL, "signature algorithm is ECDSA but the issuer key is RSA"
            if sig_alg not in _RSA_SIG_ALGS:
                return UNVERIFIED, "RSA issuer, unsupported signature algorithm %r" % (sig_alg,)
            ok = _rsa_pkcs1_v15_verify(signature, tbs, _RSA_SIG_ALGS[sig_alg],
                                       *_rsa_public_from_spki(spki))
        elif key_alg == _EC_PUBLIC_KEY:
            if sig_alg in _RSA_SIG_ALGS:
                return FAIL, "signature algorithm is RSA but the issuer key is EC"
            if sig_alg not in _ECDSA_SIG_ALGS:
                return UNVERIFIED, "EC issuer, unsupported signature algorithm %r" % (sig_alg,)
            ok = _ecdsa_verify(signature, tbs, _ECDSA_SIG_ALGS[sig_alg],
                               *_ec_public_from_spki(spki))
        else:
            return UNVERIFIED, "issuer key algorithm %r is not supported" % (key_alg,)
    except Exception as exc:
        return UNVERIFIED, "signature check unavailable: %s" % exc
    return (PASS, "signature verifies with issuer public key") if ok else \
           (FAIL, "signature does not verify with issuer public key")


def _is_ca(cert):
    """``(is_ca, path_len_or_None)`` from basicConstraints, or ``(None, None)``."""
    for ext in cert["tbsCertificate"]["extensions"]:
        if _oid(ext["extnID"]) != _BASIC_CONSTRAINTS:
            continue
        try:
            value = decoder.decode(ext["extnValue"].asOctets(),
                                   asn1Spec=rfc5280.BasicConstraints())[0]
        except Exception:
            return None, None
        path_len = int(value["pathLenConstraint"]) if value["pathLenConstraint"].hasValue() else None
        return bool(value["cA"]), path_len
    return None, None


def _time_value(time_value):
    chosen = time_value["utcTime"] if time_value["utcTime"].hasValue() else time_value["generalTime"]
    return chosen.asDateTime


def _validity(cert):
    validity = cert["tbsCertificate"]["validity"]
    return _time_value(validity["notBefore"]), _time_value(validity["notAfter"])


def _utc(value):
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _self_signed(cert):
    """Name gate + self-signature. Both must hold."""
    if _issuer_der(cert) != _subject_der(cert):
        return False
    return verify_certificate_signature(_encode_cert(cert), _encode_cert(cert))[0] == PASS


def _issuer_candidates(subject_der, pool):
    """Certificates in ``pool`` that may issue ``subject_der``.

    An issuer link requires *both*: canonical issuer name equals the
    candidate's subject name (RFC 5280 identity), and the candidate's key
    verifies the subject's signature. Signature-only matches (same key,
    different name) are reported separately and are not accepted as
    issuers. Name is a necessary gate, never sufficient proof.
    """
    subject = _parse_cert(subject_der)
    subject_issuer_name = _issuer_der(subject)
    accepted = []
    signature_only = []
    unverified = []
    for index, candidate_der in pool:
        candidate = _parse_cert(candidate_der)
        signature_status, signature_detail = verify_certificate_signature(
            _encode_cert(subject), candidate_der)
        if signature_status == UNVERIFIED:
            unverified.append((index, signature_detail))
            continue
        if signature_status != PASS:
            continue
        if _subject_der(candidate) != subject_issuer_name:
            signature_only.append(index)
            continue
        accepted.append((index, candidate_der))
    return accepted, signature_only, unverified


def _reaches_anchor(start_der, pool, roots_der, max_depth=4):
    """Whether a signature-verified path from ``start_der`` reaches a
    supplied anchor (including ``start_der`` itself). Used only to
    disambiguate multiple issuers when the caller has supplied anchors."""
    if start_der in roots_der:
        return True
    frontier = [start_der]
    seen = set([start_der])
    for _ in range(max_depth):
        next_frontier = []
        for der in frontier:
            accepted, _, _ = _issuer_candidates(der, pool)
            for _, issuer_der in accepted:
                if issuer_der in roots_der:
                    return True
                if issuer_der not in seen:
                    seen.add(issuer_der)
                    next_frontier.append(issuer_der)
        frontier = next_frontier
        if not frontier:
            break
    return False


def verify_certificate_chain(leaf_der, candidate_ders, trusted_roots=None, now=None,
                             max_depth=8):
    """Build and check a signature-proven chain above ``leaf_der``.

    ``candidate_ders`` is an unordered pool (normally the rest of
    ``cert_chain``). The pool is scanned in full; nothing depends on list
    order. The returned :class:`ChainResult` carries:

    * ``chain_links``: every accepted link is name- and signature-gated.
    * ``chain_terminates``: self-signed top, a supplied anchor, or
      ``UNVERIFIED`` (unknown anchors) / ``FAIL`` (anchors supplied but
      unreachable). For a cross-signed cycle the links pass while
      termination is ``UNVERIFIED`` unless an anchor resolves it.
    * ``issuer_is_ca[n]`` / ``path_length_constraints`` on proven links.
    * ``validity_window`` (``UNVERIFIED`` without ``now``).
    * ``trust_root``: ``UNVERIFIED`` unless ``trusted_roots`` is given;
      trust is never inferred from the chain or the keystore.
    * ``unused_candidates``: material in the pool not used by the path.
    """
    checks = Checks()
    try:
        leaf = _parse_cert(leaf_der)
    except Exception as exc:
        checks.add("certificates_parse", FAIL, "leaf: %s" % exc)
        return ChainResult(leaf_der, [], checks, None)

    pool = []
    malformed = []
    seen = set()
    for index, der in candidate_ders:
        try:
            parsed_candidate = _parse_cert(der)
        except Exception as exc:
            malformed.append("%d: %s" % (index, exc))
            continue
        if der in seen:
            continue
        seen.add(der)
        pool.append((index, der, parsed_candidate))
    if malformed:
        checks.add("certificates_parse", FAIL, "; ".join(malformed))
        return ChainResult(leaf_der, [], checks, None)
    checks.add("certificates_parse", PASS, "leaf plus %d candidate certificate(s)" % len(pool))

    roots_der = [_encode_cert(_parse_cert(root)) for root in trusted_roots] if trusted_roots else None

    path = []            # (index, der) issuers, leaf's issuer first
    used_der = set([_encode_cert(leaf)])
    termination = None
    termination_detail = ""
    status = None
    detail = ""
    current_der = leaf_der
    current = leaf
    remaining = [(i, d, c) for i, d, c in pool]

    for _ in range(max_depth + 1):
        candidate_pool = [(i, d) for i, d, _ in remaining]
        if roots_der is not None:
            pool_bytes = set(d for _, d in candidate_pool)
            for root_index, root_der in enumerate(roots_der):
                if root_der not in pool_bytes and root_der != current_der:
                    pool_bytes.add(root_der)
                    candidate_pool.append(("anchor[%d]" % root_index, root_der))
        accepted, signature_only, unverified = _issuer_candidates(current_der, candidate_pool)
        if len(accepted) > 1:
            # Multiple issuers can happen with cross-signing (same subject
            # and key, different signatures) or when the pool is dirty.
            if roots_der is not None:
                reaching = [a for a in accepted
                            if _reaches_anchor(a[1], [(i, d) for i, d, _ in remaining], roots_der)]
                if len(reaching) == 1:
                    accepted = reaching
                elif reaching:
                    checks.add("chain_links", FAIL,
                               "%d issuers reach a supplied anchor; refusing to pick by order"
                               % len(reaching))
                    return ChainResult(leaf_der, [d for _, d in path], checks, None)
                else:
                    checks.add("chain_links", FAIL,
                               "%d issuers verify but none reaches a supplied anchor" % len(accepted))
                    return ChainResult(leaf_der, [d for _, d in path], checks, None)
            else:
                checks.add("chain_links", UNVERIFIED,
                           "%d issuer candidates verify (cross-signed or duplicate material); "
                           "supply trusted roots or select the intended issuer" % len(accepted))
                return ChainResult(leaf_der, [d for _, d in path], checks, None)
        if len(accepted) == 1:
            index, issuer_der = accepted[0]
            if issuer_der in used_der:
                # Cross-signed loop: every link verifies, but the walk
                # returns to a certificate already on the path. That is a
                # legitimate cross-signed arrangement, not a broken link,
                # but it cannot be called complete without an anchor.
                checks.add("chain_links", PASS,
                           "%d link(s) proven; path revisits an earlier certificate "
                           "(cross-signed loop)" % (len(path) + 1))
                checks.add("chain_terminates", UNVERIFIED if roots_der is None else FAIL,
                           "cross-signed loop has no self-signed top or supplied anchor"
                           if roots_der is None else
                           "cross-signed loop does not include a supplied anchor")
                checks.add("trust_root", UNVERIFIED if roots_der is None else FAIL,
                           "loop cannot be anchored" if roots_der is None else
                           "loop cannot be anchored in supplied roots")
                return ChainResult(leaf_der, [d for _, d in path], checks, None)
            path.append((index, issuer_der))
            used_der.add(issuer_der)
            remaining = [(i, d, c) for i, d, c in remaining if d != issuer_der or i != index]
            issuer_cert = _parse_cert(issuer_der)
            if _self_signed(issuer_cert):
                termination = "self-signed"
                termination_detail = "topmost certificate is self-signed; it is an anchor only if supplied as one"
                status = PASS
                detail = "self-signed top"
                break
            if roots_der is not None and issuer_der in roots_der:
                termination = "anchor"
                termination_detail = "issuer is a supplied trust anchor"
                status = PASS
                detail = "supplied anchor"
                break
            current_der = issuer_der
            current = issuer_cert
            continue

        # No issuer above this node. If it is self-signed, that is a
        # locally complete one-certificate chain. Otherwise report the
        # dead end; whether it is "fatal" depends on anchors the caller
        # may hold out of band.
        if _self_signed(current):
            if roots_der is not None and current_der in roots_der:
                checks.add("chain_links", FAIL,
                           "certificate is a supplied anchor but no certificate links it to a leaf; "
                           "a trust anchor is not a serving chain")
                checks.add("trust_root", UNVERIFIED,
                           "the leaf itself is an anchor; TLS servers normally need an end-entity certificate")
                return ChainResult(leaf_der, [], checks, None)
            termination = "self-signed"
            termination_detail = "leaf is self-signed" if not path else "topmost is self-signed"
            status = PASS
            detail = "self-signed"
            break
        note = ""
        if signature_only:
            note = ("; certificate(s) %s verify under the same key but their subject name "
                    "does not match the issuer name, so they are not accepted as issuers"
                    % signature_only)
        if unverified:
            status = UNVERIFIED
            detail = "%s%s" % (unverified[0][1], note)
        elif roots_der is None:
            status = UNVERIFIED
            detail = "no issuer in the pool; top is not self-signed and no anchors were supplied" + note
        else:
            status = FAIL
            detail = "no issuer in the pool reaches a supplied anchor" + note
        break

    if status is None:
        status = FAIL
        detail = "issuer path exceeded %d links" % max_depth

    if status == PASS:
        checks.add("chain_links", PASS,
                   "%d link(s) proven by name gate + signature%s"
                   % (len(path), ("; " + termination_detail) if termination_detail else ""))
    elif status == UNVERIFIED:
        checks.add("chain_links", UNVERIFIED, detail)
        return ChainResult(leaf_der, [d for _, d in path], checks, None)
    else:
        checks.add("chain_links", FAIL, detail)
        return ChainResult(leaf_der, [d for _, d in path], checks, None)

    # CA constraints. The topmost issuer is an anchor only if supplied;
    # a self-signed top still needs CA=true to have issued anything.
    issuers = [(_parse_cert(der), index) for index, der in path]
    violations = []
    for position, (issuer, index) in enumerate(issuers):
        is_top = position == len(issuers) - 1
        is_anchor = roots_der is not None and path[position][1] in roots_der
        if is_top and is_anchor:
            checks.add("issuer_is_ca[%d]" % position, INFO,
                       "certificate index %s is a caller-supplied trust anchor; "
                       "basicConstraints is not enforced on anchors" % index)
            continue
        is_ca, path_len = _is_ca(issuer)
        if is_ca is None:
            checks.add("issuer_is_ca[%d]" % position, FAIL,
                       "certificate index %s has no basicConstraints extension" % (index,))
        elif not is_ca:
            checks.add("issuer_is_ca[%d]" % position, FAIL,
                       "certificate index %s has CA=false" % (index,))
        else:
            checks.add("issuer_is_ca[%d]" % position, PASS,
                       "certificate index %s has CA=true" % (index,))
        # position 0 issues the leaf, so 0 CA certificates sit below it.
        if is_ca and path_len is not None and position > path_len:
            violations.append("certificate index %d allows %d CA(s) below, path has %d"
                              % (index, path_len, position))
    if violations:
        checks.add("path_length_constraints", FAIL, "; ".join(violations))
    else:
        checks.add("path_length_constraints", PASS,
                   "pathLenConstraint holds on proven links")

    # Validity is reported, never silently assumed. The TLS stack owns
    # its clock and policy.
    if now is None:
        checks.add("validity_window", UNVERIFIED,
                   "no reference time supplied; TLS library must enforce validity")
    else:
        reference = _utc(now)
        outside = []
        for der in [leaf_der] + [d for _, d in path]:
            try:
                not_before, not_after = _validity(_parse_cert(der))
                if not (_utc(not_before) <= reference <= _utc(not_after)):
                    outside.append(_spki_id(_parse_cert(der)))
            except Exception as exc:
                outside.append("unparsed: %s" % exc)
        if outside:
            checks.add("validity_window", FAIL,
                       "certificate(s) outside validity at reference time: %s" % outside)
        else:
            checks.add("validity_window", PASS,
                       "all path certificates are within validity at the reference time")

    if roots_der is None:
        checks.add("chain_terminates", PASS if termination == "self-signed" else UNVERIFIED,
                   termination_detail if termination == "self-signed" else
                   "top is not self-signed and no anchors were supplied; completeness beyond this point is unknown")
        checks.add("trust_root", UNVERIFIED,
                   "no trusted roots supplied; cert_chain is a candidate chain, not a trust decision")
    else:
        if termination == "self-signed" and path and path[-1][1] in roots_der:
            termination = "anchor"
        if termination == "anchor":
            checks.add("chain_terminates", PASS, termination_detail)
            checks.add("trust_root", PASS, "topmost proven certificate is a supplied trust anchor")
        elif termination == "self-signed":
            checks.add("chain_terminates", PASS, "self-signed top; not necessarily a caller anchor")
            checks.add("trust_root", FAIL,
                       "self-signed top is not among the supplied trust anchors")
        else:
            checks.add("chain_terminates", FAIL, "proven path does not reach a supplied anchor")
            checks.add("trust_root", FAIL, "no supplied trust anchor terminates the path")

    checks.add("unused_candidates", INFO,
               "candidate certificate(s) not used by the path: %s"
               % [i for i, _, _ in remaining])

    return ChainResult(leaf_der, [d for _, d in path], checks, termination)


def _select_leaf(entry, parsed):
    """Find the certificate that owns ``entry.pkey_pkcs8``.

    Selection uses the public key only. If several certificates carry the
    same key, each is tried as a leaf; the entry is usable only if exactly
    one completes a chain (or if the caller supplied an explicit hint).
    """
    info = decoder.decode(entry.pkey_pkcs8, asn1Spec=rfc5208.PrivateKeyInfo())[0]
    key_alg = _oid(info["privateKeyAlgorithm"]["algorithm"])
    if key_alg != RSA_ENCRYPTION_OID:
        raise ValueError("private key algorithm %r is not supported for leaf matching; "
                         "use a crypto library to compare the public keys" % (key_alg,))
    key_der = _rsa_public_der(*_rsa_private_public(entry.pkey_pkcs8))
    matching = []
    seen_der = set()
    for index, der, cert in parsed:
        if der in seen_der:
            continue
        seen_der.add(der)
        try:
            cert_alg, cert_key = _public_key_from_cert_der(der)
        except Exception:
            continue
        if cert_alg == key_alg and cert_key == key_der:
            matching.append((index, der, cert))
    return matching


def prepare_identity(entry, trusted_roots=None, now=None, leaf_hint=None):
    """Validate a decrypted ``PrivateKeyEntry`` for TLS use.

    ``leaf_hint`` is an optional DER certificate that names the intended
    leaf. It is a *selection hint*, not an assertion: it must still match
    the private key and pass the same checks, otherwise it is rejected.

    Raises :class:`ChainVerificationError` when the entry is undecrypted,
    empty, malformed, or the leaf cannot be selected unambiguously. A
    returned :class:`Identity` can still be ``ok == False`` for a failed
    link; trust is always outstanding.
    """
    if not entry.is_decrypted():
        raise ChainVerificationError("entry is not decrypted; call decrypt() with the key password first")
    if not entry.cert_chain:
        raise ChainVerificationError("certificate chain is empty")

    checks = Checks()
    checks.add("store_integrity", UNVERIFIED,
               "PyJKS checks the JKS signature only when load() receives a store password; "
               "that cannot be observed from this entry")
    checks.add("private_key_decrypted", PASS,
               "PyJKS key-protection hash accepted the password; proves password correctness, "
               "not signer identity")

    parsed = []
    for index, (type_name, der) in enumerate(entry.cert_chain):
        if type_name != "X.509":
            raise ChainVerificationError("certificate %d has unsupported type %r" % (index, type_name))
        try:
            parsed.append((index, der, _parse_cert(der)))
        except Exception as exc:
            raise ChainVerificationError("certificate %d is not parseable X.509 DER: %s" % (index, exc))

    try:
        matching = _select_leaf(entry, parsed)
    except ValueError as exc:
        checks.add("leaf_matches_private_key", UNVERIFIED, str(exc))
        raise ChainVerificationError(str(exc))

    if not matching:
        checks.add("leaf_matches_private_key", FAIL,
                   "no certificate's public key equals the private key's public key")
        raise ChainVerificationError("leaf certificate does not match the private key")

    if leaf_hint is not None:
        hinted = [m for m in matching if m[1] == leaf_hint]
        if not hinted:
            checks.add("leaf_matches_private_key", FAIL,
                       "leaf_hint does not match the private key")
            raise ChainVerificationError("leaf_hint does not match the private key")
        matching = hinted

    checks.add("leaf_matches_private_key", PASS,
               "certificate index(es) %s match the private key (SPKI %s)"
               % ([m[0] for m in matching], _spki_id(matching[0][2])))

    # With several same-key certificates, a hint or a unique chain decides.
    selected = matching[0] if len(matching) == 1 else None
    if selected is None:
        completed = []
        for index, der, cert in matching:
            result = verify_certificate_chain(der, [(i, d) for i, d, _ in parsed if i != index],
                                              trusted_roots=trusted_roots, now=None)
            link = result.checks.get("chain_links")
            if link is not None and link.status == PASS:
                completed.append((index, der, cert))
        if len(completed) == 1:
            selected = completed[0]
            checks.add("leaf_selection", PASS,
                       "one of %d same-key certificates forms a chain; selected index %d by "
                       "signature/provenance, not by position" % (len(matching), selected[0]))
        else:
            checks.add("leaf_selection", FAIL,
                       "%d certificates carry the private key and %d of them form chains; "
                       "the leaf is ambiguous without an explicit leaf_hint"
                       % (len(matching), len(completed)))
            raise ChainVerificationError(
                "leaf is ambiguous: %d certificates carry the same public key; "
                "pass leaf_hint with the intended certificate" % len(matching))
    elif len(matching) > 1:
        checks.add("leaf_selection", PASS, "explicit leaf_hint selected certificate index %d" % selected[0])

    index, leaf_der, leaf = selected
    others = [(i, d) for i, d, _ in parsed if i != index]
    chain = verify_certificate_chain(leaf_der, others, trusted_roots=trusted_roots, now=now)

    # Merge chain checks after this module's key checks. A leaf that is
    # itself in the pool is excluded, so duplicates of the leaf's bytes
    # are handled by the chain engine's dedup on path membership.
    for result in chain.checks:
        checks.add(result.name, result.status, result.detail)

    checks.add("leaf_eku", UNVERIFIED,
               "extendedKeyUsage is not interpreted here; the TLS library must enforce server/client usage")
    checks.add("key_usage", UNVERIFIED,
               "keyUsage is not interpreted here; the TLS library must enforce signing usage")

    return Identity(entry.alias, entry.pkey_pkcs8, leaf_der, chain.issuer_ders, checks,
                    chain.termination)
