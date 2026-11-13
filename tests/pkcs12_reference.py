# vim: set ai et ts=4 sts=4 sw=4:
"""
Small, self-contained PKCS#12 key-derivation reference (RFC 7292, Appendix B).

This module intentionally does not import :mod:`jks` and does not use any of
the library's KDF helpers.  It is only used by the tests to cross-check the
production implementation; keep it short and obvious rather than fast.
"""


def utf16be_code_units(text):
    """Return the big-endian UTF-16 code units of ``text``, without a BOM.

    Python strings are sequences of code points, whereas the PKCS#12 password
    is a sequence of UTF-16 code units (Java's ``char``).  Supplementary-plane
    characters therefore have to be turned into an explicit surrogate pair.
    """
    result = bytearray()
    for ch in text:
        cp = ord(ch)
        if cp < 0x10000:
            result.append((cp >> 8) & 0xFF)
            result.append(cp & 0xFF)
        else:
            cp -= 0x10000
            high = 0xD800 + (cp >> 10)
            low = 0xDC00 + (cp & 0x3FF)
            result.append((high >> 8) & 0xFF)
            result.append(high & 0xFF)
            result.append((low >> 8) & 0xFF)
            result.append(low & 0xFF)
    return bytes(result)


def password_bytes(text):
    """PKCS#12 password bytes: UTF-16BE code units plus a two-byte terminator.

    An empty password is encoded as an empty byte string (not as just the
    terminator), matching BouncyCastle's PKCS12PasswordToBytes().
    """
    if len(text) == 0:
        return b""
    return utf16be_code_units(text) + b"\x00\x00"


def repeat_to_block(data, block_size):
    """Repeat ``data`` to the smallest positive multiple of ``block_size``.

    Empty input stays empty; this is what makes empty salt and empty password
    well-defined in RFC 7292.
    """
    if len(data) == 0:
        return b""
    target = ((len(data) + block_size - 1) // block_size) * block_size
    return (data * ((target // len(data)) + 1))[:target]


def add_block_mod_2v(block, addend):
    """(block + addend + 1) mod 2^(8*len(block)), with byte-wise carry.

    Returns ``(result, carry_chain)`` where ``carry_chain`` is the number of
    consecutive bytes, starting from the least significant end, through which
    the +1/carry propagates.  Exposing this counter lets the tests assert that
    a deliberately crafted I-block really does exercise a long carry chain.
    """
    if len(block) != len(addend):
        raise ValueError("block and addend must have equal length")

    result = bytearray(block)
    carry = 1
    carry_chain = 0
    chain_open = True
    for i in range(len(result) - 1, -1, -1):
        total = result[i] + addend[i] + carry
        result[i] = total & 0xFF
        carry = total >> 8
        if chain_open:
            if carry:
                carry_chain += 1
            else:
                chain_open = False
    return bytes(result), carry_chain


def derive_blocks(digest_factory, purpose, password, salt, iterations, block_count):
    """Derive ``block_count`` raw digest-sized blocks of PKCS#12 key material.

    The returned dictionary contains the individually expanded D, S and P
    inputs, every raw A block, the intermediate I state after each round, and
    the per-round carry-chain counts.  No truncation to a final key size is
    performed here, which is what makes the block-by-block comparison possible.
    """
    digest_size = digest_factory().digest_size
    block_size = digest_factory().block_size

    D = bytes(bytearray([purpose]) * block_size)
    S = repeat_to_block(salt, block_size)
    P = repeat_to_block(password_bytes(password), block_size)
    I = S + P
    I0 = I

    blocks = []
    states = [I]
    carry_chains = []

    for unused in range(block_count):
        A = digest_factory(D + I).digest()
        for unused_iteration in range(iterations - 1):
            A = digest_factory(A).digest()
        blocks.append(A)

        B = repeat_to_block(A, block_size)
        next_I = bytearray()
        round_chains = []
        for offset in range(0, len(I), block_size):
            adjusted, chain = add_block_mod_2v(I[offset:offset + block_size], B)
            next_I.extend(adjusted)
            round_chains.append(chain)
        I = bytes(next_I)
        states.append(I)
        carry_chains.append(round_chains)

    return {
        "D": D,
        "S": S,
        "P": P,
        "I0": I0,
        "blocks": blocks,
        "states": states,
        "carry_chains": carry_chains,
        "digest_size": digest_size,
        "block_size": block_size,
    }


def derive_key(digest_factory, purpose, password, salt, iterations, size):
    """Convenience wrapper returning exactly ``size`` bytes of key material."""
    digest_size = digest_factory().digest_size
    block_count = (size + digest_size - 1) // digest_size
    blocks = derive_blocks(digest_factory, purpose, password, salt, iterations, block_count)["blocks"]
    return b"".join(blocks)[:size]
