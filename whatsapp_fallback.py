#!/usr/bin/env python3
"""Single-connection WhatsApp fallback example; see README for binary inputs.

Caller supplies the account key and fresh payload. No credentials are bundled.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from noise.whatsapp import Handshake, ProtocolError
from noise.whatsapp.wire import intro, frame, recv_frame


def unrelated_x25519_public():
    return X25519PrivateKey.generate().public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw
    )


def exchange_once(handshake, payload, routing=b'', expected_fallback=None):
    hello = intro(handshake.prologue, routing) + frame(
        handshake.client_hello(payload)
    )
    address = socket.getaddrinfo(
        'g.whatsapp.net', 443, type=socket.SOCK_STREAM
    )[0]
    with socket.socket(address[0], address[1], address[2]) as sock:
        sock.settimeout(20)
        sock.connect(address[4])
        sock.sendall(hello)
        finish = handshake.server_hello(recv_frame(sock), payload)
        summary = handshake.public_summary()
        if expected_fallback and summary['pattern'] != expected_fallback:
            raise ProtocolError('server did not complete the requested fallback')
        if finish is not None:
            sock.sendall(frame(finish))
        plaintext = handshake.decrypt_transport(recv_frame(sock))
    return handshake.public_summary(), plaintext


def classical_once(private_key, payload, routing=b'', server_key=None,
                   force_fallback=False):
    if force_fallback:
        server_key = unrelated_x25519_public()
    if server_key is None:
        raise ValueError('IK requires a cached server key or force_fallback')
    handshake = Handshake(private_key, cached_server=server_key)
    return exchange_once(
        handshake, payload, routing,
        'XXfallback' if force_fallback else None
    )


def pq_once(private_key, payload, routing=b'', server_key=None,
            server_pq_key=None, force_fallback=False):
    # Classical calls do not import or require pqcrypto.
    from noise.whatsapp.pq_fs import PqFsHandshake, ml_kem_512

    if force_fallback:
        server_key = unrelated_x25519_public()
        server_pq_key, _ = ml_kem_512.generate_keypair()
    if server_key is None or server_pq_key is None:
        raise ValueError('PQ requires both cached keys or force_fallback')
    handshake = PqFsHandshake(
        private_key, b'WA\x06\x03', server_key, server_pq_key
    )
    return exchange_once(
        handshake, payload, routing,
        'XXKEM_FS_FALLBACK' if force_fallback else None
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--mode', choices=('classic', 'pq'), required=True)
    parser.add_argument('--private-key', type=Path, required=True)
    parser.add_argument('--payload', type=Path, required=True)
    parser.add_argument('--routing', type=Path)
    parser.add_argument('--server-key', type=Path)
    parser.add_argument('--server-pq-key', type=Path)
    parser.add_argument('--force-fallback', action='store_true')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not args.force_fallback and (
        args.server_key is None or
        (args.mode == 'pq' and args.server_pq_key is None)
    ):
        parser.error('provide the cached key file(s) or --force-fallback')

    private_key = args.private_key.read_bytes()
    payload = args.payload.read_bytes()
    routing = args.routing.read_bytes() if args.routing else b''
    server_key = (args.server_key.read_bytes()
                  if args.server_key and not args.force_fallback else None)
    server_pq_key = (args.server_pq_key.read_bytes()
                     if args.mode == 'pq' and args.server_pq_key
                     and not args.force_fallback else None)
    # Reserve a new private output before connecting. If the attempt fails,
    # the empty file remains; reusing the same output cannot resend it.
    fd = os.open(str(args.output), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        if args.mode == 'classic':
            summary, plaintext = classical_once(
                private_key, payload, routing, server_key, args.force_fallback
            )
        else:
            summary, plaintext = pq_once(
                private_key, payload, routing, server_key, server_pq_key,
                args.force_fallback
            )
        stream.write(plaintext)
        stream.flush()
        os.fsync(stream.fileno())
    print(json.dumps({
        'handshake': summary,
        'transport_authenticated': True,
        'plaintext_bytes': len(plaintext),
        'plaintext_sha256': hashlib.sha256(plaintext).hexdigest(),
    }, indent=2))


if __name__ == '__main__':
    main()
