# -*- coding: utf-8 -*-
"""
BKS v1 vs v2 MAC key-derivation audit (local, offline; standard library only).

Uses only the public test keystores shipped in tests/keystores/bks and their
public test passwords ("", "12345678", "store_password"). No real user
passwords, no online guessing. RFC 7292 KDF re-implemented independently with
hmac/hashlib so the observed key lengths do not depend on trusting pyjks itself.
"""
import hashlib
import hmac as hmac_mod
import struct
import os
import sys

KS_DIR = os.path.join(os.path.dirname(__file__), "..", "tests", "keystores", "bks")

PURPOSE_MAC_MATERIAL = 3  # RFC 7292 purpose byte ID 3

# --- independent RFC 7292 Appendix B KDF (stdlib only) ---------------------
def pkcs12_derive_key(hashfn, purpose_byte, password_str, salt,
                      iteration_count, desired_key_size):
    password_bytes = (password_str.encode("utf-16be") + b"\x00\x00") \
        if len(password_str) > 0 else b""
    u = hashfn().digest_size          # 20 for SHA-1
    v = hashfn().block_size           # 64 for SHA-1
    salt = bytearray(salt)
    pw = bytearray(password_bytes)
    D = bytearray([purpose_byte]) * v
    S = bytearray([salt[n % len(salt)] for n in range(((len(salt)+v-1)//v)*v)])
    P = bytearray([pw[n % len(pw)] for n in range(((len(pw)+v-1)//v)*v)]) if pw else bytearray()
    I = S + P
    c = (desired_key_size + u - 1) // u
    out = b""
    for _ in range(c):
        A = hashfn(bytes(D + I)).digest()
        for _ in range(iteration_count - 1):
            A = hashfn(A).digest()
        B = bytearray([A[n % len(A)] for n in range(v)])
        for j in range(len(I) // v):
            off = j * v
            x = (B[-1] & 0xFF) + (I[off + v - 1] & 0xFF) + 1
            I[off + v - 1] = x & 0xFF
            carry = x >> 8
            for k in range(v - 2, -1, -1):
                x = carry + (B[k] & 0xFF) + (I[off + k] & 0xFF)
                I[off + k] = x & 0xFF
                carry = x >> 8
        out += A
    return out[:desired_key_size]


def parse_header(data):
    pos = 0
    version = struct.unpack(">I", data[pos:pos+4])[0]; pos += 4
    salt_len = struct.unpack(">I", data[pos:pos+4])[0]; pos += 4
    salt = data[pos:pos+salt_len]; pos += salt_len
    iters = struct.unpack(">I", data[pos:pos+4])[0]; pos += 4
    return version, salt, iters, pos


def pyjks_requested_key_size(version):
    """Mirror of jks/bks.py lines 282-284."""
    digest_size = hashlib.sha1().digest_size          # 20 bytes
    hmac_key_size_bits = digest_size * 8 if version != 1 else digest_size
    return hmac_key_size_bits // 8                    # bytes actually requested


def main():
    print("=" * 78)
    print("PART 1  Derivation length per version field")
    print("=" * 78)
    for v in (1, 2):
        n = pyjks_requested_key_size(v)
        print("version=%d -> hmac_key_size param = %d %s; bytes requested from "
              "RFC7292 KDF = %d" %
              (v, 20*8 if v != 1 else 20, "bits" if v != 1 else "BITS(=20!)", n))

    cases = [
        ("empty.bksv1", ""),
        ("empty.bksv2", ""),
        ("christmas.bksv1", "12345678"),
        ("christmas.bksv2", "12345678"),
        ("custom_entry_passwords.bksv1", "store_password"),
        ("custom_entry_passwords.bksv2", "store_password"),
    ]

    print()
    print("=" * 78)
    print("PART 2  Independent HMAC verification over shipped test stores")
    print("=" * 78)
    parsed = {}
    for name, pw in cases:
        path = os.path.join(KS_DIR, name)
        data = open(path, "rb").read()
        version, salt, iters, entry_start = parse_header(data)
        stored_hmac = data[-20:]
        store_data = data[entry_start:-20]
        key_len = pyjks_requested_key_size(version)
        mac_key = pkcs12_derive_key(hashlib.sha1, PURPOSE_MAC_MATERIAL,
                                    pw, salt, iters, key_len)
        calc = hmac_mod.new(mac_key, store_data, hashlib.sha1).digest()
        ok = hmac_mod.compare_digest(calc, stored_hmac)
        parsed[name] = (data, version, salt, iters, entry_start, store_data,
                        stored_hmac, pw, mac_key)
        print("%-32s v%d key=%2d bytes key_hex=%s HMAC %s" %
              (name, version, len(mac_key), mac_key.hex(),
               "MATCH" if ok else "MISMATCH"))

    print()
    print("=" * 78)
    print("PART 3  HMAC coverage: what bytes are / are not authenticated")
    print("=" * 78)
    name = "christmas.bksv2"
    data, version, salt, iters, entry_start, store_data, stored_hmac, pw, _ = parsed[name]
    print("file length            : %d" % len(data))
    print("header (version+salt+iter), bytes 0..%d : NOT covered by HMAC" % (entry_start-1))
    print("entry region covered   : bytes %d..%d (%d bytes)" %
          (entry_start, len(data)-21, len(store_data)))
    print("stored HMAC tail       : bytes %d..%d (20 bytes SHA-1)" %
          (len(data)-20, len(data)-1))
    # prove it: flip a byte inside the salt (header bytes 8..27), keep the
    # stored HMAC tail unchanged. Two observations follow:
    #  (a) recomputing the MAC over the same entry region with the ORIGINAL key
    #      still reproduces the stored HMAC -> header is outside coverage;
    #  (b) a real parser deriving a key from the MODIFIED salt gets a new key
    #      and therefore fails -> tampering is caught only via the KDF input.
    tampered = bytearray(data)
    tampered[8] ^= 0x01  # first content byte of the 20-byte salt
    _, salt2, iters2, es2 = parse_header(bytes(tampered))
    orig_key = pkcs12_derive_key(hashlib.sha1, 3, pw, salt, iters,
                                 pyjks_requested_key_size(version))
    calc_orig_key = hmac_mod.new(orig_key, bytes(tampered[es2:-20]),
                                 hashlib.sha1).digest()
    new_key = pkcs12_derive_key(hashlib.sha1, 3, pw, salt2, iters2,
                                pyjks_requested_key_size(version))
    calc_new_key = hmac_mod.new(new_key, bytes(tampered[es2:-20]),
                                hashlib.sha1).digest()
    print("proof: flip 1 salt byte (header, outside HMAC region), tail untouched")
    print("  (a) MAC over unchanged entry region with ORIGINAL derived key: %s"
          % ("MATCH" if calc_orig_key == bytes(tampered[-20:]) else "mismatch"))
    print("  (b) MAC re-derived from MODIFIED salt (what a real parser uses): "
          "%s -> tampering detected only because the KDF input changed"
          % ("MATCH" if calc_new_key == bytes(tampered[-20:]) else "mismatch"))

    print()
    print("=" * 78)
    print("PART 4  Required anomaly scenarios")
    print("=" * 78)
    import jks
    from jks import bks as jks_bks
    from jks.util import (UnsupportedKeystoreVersionException,
                          KeystoreSignatureException,
                          BadKeystoreFormatException)

    def label(exc):
        return "%s: %s" % (type(exc).__name__, exc)

    # 4a. version field rewritten
    print("\n[4a] version field rewritten (christmas v1/v2, correct password)")
    for base in ("christmas.bksv1", "christmas.bksv2"):
        raw, ver, *_rest = parsed[base][0], parsed[base][1], None
        pw_b = parsed[base][7]
        for newver in (1, 2, 3):
            if newver == ver:
                continue
            mod = bytearray(raw)
            mod[0:4] = struct.pack(">I", newver)
            try:
                jks_bks.BksKeyStore.loads(bytes(mod), pw_b)
                result = "LOADED (unexpected)"
            except Exception as e:
                result = label(e)
            print("  %s version %d->%d : %s" % (base, ver, newver, result))

    # 4b. empty stores
    print("\n[4b] empty stores (public test password \"\")")
    for base in ("empty.bksv1", "empty.bksv2"):
        raw = parsed[base][0]
        ver, salt_e, it_e, es_e = parse_header(raw)
        region = raw[es_e:-20]
        print("  %s: entry region length = %d (single 0x00 terminator=%s)" %
              (base, len(region), region == b"\x00"))
        try:
            ks = jks_bks.BksKeyStore.loads(raw, "")
            print("    loads() OK -> type=%s version=%d entries=%d" %
                  (ks.store_type, ks.version, len(ks.entries)))
        except Exception as e:
            print("    " + label(e))

    # 4c. correct password but corrupted MAC (flip one stored HMAC byte)
    print("\n[4c] correct password, MAC tail corrupted by one bit")
    for base in ("christmas.bksv1", "christmas.bksv2",
                 "empty.bksv1", "empty.bksv2"):
        raw = parsed[base][0]
        pw_b = parsed[base][7]
        mod = bytearray(raw)
        mod[-1] ^= 0x01
        try:
            jks_bks.BksKeyStore.loads(bytes(mod), pw_b)
            result = "LOADED (unexpected)"
        except Exception as e:
            result = label(e)
        # note: entries are structurally parseable before the MAC gate runs
        ver, salt_e, it_e, es_e = parse_header(bytes(mod))
        entries, size = jks_bks.BksKeyStore._load_bks_entries(
            bytes(mod)[es_e:], "bks", pw_b, try_decrypt_keys=False)
        print("  %-32s %s | parseable entries before MAC gate = %d" %
              (base, result, len(entries)))

    # 4d. wrong password (for completeness)
    print("\n[4d] wrong password (public test material only)")
    for base in ("christmas.bksv1", "christmas.bksv2"):
        raw = parsed[base][0]
        try:
            jks_bks.BksKeyStore.loads(raw, "wrong-public-test-pw")
            result = "LOADED (unexpected)"
        except Exception as e:
            result = label(e)
        print("  %-32s %s" % (base, result))

    print()
    print("=" * 78)
    print("PART 5  v1 key-space exhaustion (offline, on test material only)")
    print("=" * 78)
    # v1 MAC key is only 2 bytes -> at most 65536 candidate keys. Demonstrate
    # that the stored HMAC can be reproduced by brute force without the password,
    # using only public test bytes. This validates effective key length, not a
    # user password attack.
    base = "empty.bksv1"
    raw = parsed[base][0]
    ver, salt_e, it_e, es_e = parse_header(raw)
    region = raw[es_e:-20]
    target = raw[-20:]
    found = None
    for cand in range(65536):
        k = struct.pack(">H", cand)
        if hmac_mod.new(k, region, hashlib.sha1).digest() == target:
            found = k
            break
    real_key = parsed[base][8]
    print("store              : %s" % base)
    print("candidates tried   : %d (2-byte space)" % 65536)
    print("key recovered w/o password : %s" % (found.hex() if found else None))
    print("key derived from password   : %s (length %d)" %
          (real_key.hex(), len(real_key)))
    print("identical          : %s" % (found == real_key))

    # same attempt against a v2 store: show why 2-byte space is irrelevant there
    base2 = "empty.bksv2"
    raw2 = parsed[base2][0]
    _, _, _, es2 = parse_header(raw2)
    target2 = raw2[-20:]
    hit = any(hmac_mod.new(struct.pack(">H", c), raw2[es2:-20],
                           hashlib.sha1).digest() == target2
              for c in range(65536))
    print("v2 store hit within same 65536 2-byte attempts: %s (v2 key is "
          "20 bytes = 160-bit space)" % hit)


if __name__ == "__main__":
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
    main()
