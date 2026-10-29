"""WA6 root/intermediate/leaf checks recovered from C1lC.A03.

The Montgomery-to-Edwards verification follows Signal's curve_sigs.c.
No network or phone signing is required; this module only verifies.
"""
import hashlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from .wire import fields, get, blob, scalar, ProtocolError

ROOT_PUBLIC = bytes.fromhex('142375574d0a587166aae71ebe516437c4a28b73e3695c6ce1f7f9545da8ee6b')
P = 2 ** 255 - 19

def verify_signature(public, message, signature):
    if len(public) != 32 or len(signature) != 64:
        return False
    u = int.from_bytes(public, 'little') & ((1 << 255) - 1)
    if u >= P or u == P - 1:
        return False
    y = (u - 1) * pow(u + 1, P - 2, P) % P
    ed_public = bytearray(y.to_bytes(32, 'little'))
    ed_public[31] |= signature[63] & 128
    ed_signature = bytearray(signature)
    ed_signature[63] &= 127
    try:
        Ed25519PublicKey.from_public_bytes(bytes(ed_public)).verify(bytes(ed_signature), message)
        return True
    except (InvalidSignature, ValueError):
        return False

def canonical_details(items):
    known = {1: 0, 2: 0, 3: 2, 4: 0, 5: 0}
    result = bytearray()
    for number, wire in known.items():
        value = get(items, number, wire, required=False)
        if value is not None:
            result.extend(blob(number, value) if wire == 2 else scalar(number, value))
    for field in items:
        if known.get(field.number) != field.wire:
            result.extend(field.encoded)
    return bytes(result)

def verify_chain(payload, server_static, root=ROOT_PUBLIC):
    chain = fields(payload)
    leaf, intermediate = fields(get(chain, 1)), fields(get(chain, 2))
    leaf_raw, int_raw = get(leaf, 1), get(intermediate, 1)
    leaf_details, int_details = fields(leaf_raw), fields(int_raw)
    int_serial = get(int_details, 1, 0)
    issuer = get(leaf_details, 2, 0)
    if int_serial != issuer or get(int_details, 2, 0) != 0:
        raise ProtocolError('certificate issuer/serial mismatch')
    key = get(leaf_details, 3)
    int_key = get(int_details, 3)
    if len(key) != 32 or len(int_key) != 32 or key != server_static:
        raise ProtocolError('certificate static key binding mismatch')
    # APK serializes parsed leaf details but verifies intermediate raw bytes.
    if not verify_signature(int_key, canonical_details(leaf_details), get(leaf, 2)):
        raise ProtocolError('invalid leaf certificate signature')
    if not verify_signature(root, int_raw, get(intermediate, 2)):
        raise ProtocolError('invalid intermediate certificate signature')
    return {'chain_verified': True, 'server_static_bound': True,
            'issuer_serial': issuer, 'payload_bytes': len(payload),
            'root_sha256': hashlib.sha256(root).hexdigest(),
            'time_policy': 'WA6 branch: validity timestamps parsed but not enforced by observed APK path'}
