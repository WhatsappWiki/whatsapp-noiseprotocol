noiseprotocol-whatsapp
======================
[![Upstream CI](https://circleci.com/gh/plizonczyk/noiseprotocol.svg?style=svg)](https://circleci.com/gh/plizonczyk/noiseprotocol)
[![Upstream PyPI](https://img.shields.io/pypi/v/noiseprotocol.svg)](https://pypi.python.org/pypi/noiseprotocol)
[![Upstream Documentation](https://readthedocs.org/projects/noiseprotocol/badge/)](http://noiseprotocol.readthedocs.io/)

**WhatsApp Noise protocol for Python**, with classical XX/IK handshakes,
IK → XXfallback, and IKKEM_FS → XXkem-FSfallback using ML-KEM-512. Includes WA6
certificate verification, optional post-quantum cryptography support, and the
single-connection `python -m whatsapp_fallback` CLI.

Fork of [plizonczyk/noiseprotocol](https://github.com/plizonczyk/noiseprotocol),
an implementation of the [Noise Protocol Framework](https://noiseprotocol.org/)
compatible with revisions 32 and 33. Standard Noise remains the default;
WhatsApp compatibility is enabled explicitly. The distribution keeps the
`noiseprotocol` package name and `noise` imports for compatibility.

## Documentation
The upstream [Read the Docs](https://noiseprotocol.readthedocs.io) describes
HandshakeState, CipherState and SymmetricState. This README documents the
WhatsApp additions in this fork.

## Installation and prerequisites
Only Python 3.5+ is supported.
The author provides support for Linux systems only. Theoretically, package should work under Windows and OS X too, but those systems are not included in CI workflow.

Install this checkout from the repository root to use its WhatsApp additions:
```sh
python -m pip install .
# Optional PQ support (Python 3.9+):
python -m pip install '.[whatsapp-pq]'
```
Installing `noiseprotocol` by name from a package index does not select this
local checkout or its uncommitted changes. Pandoc is not needed for installation.
*noiseprotocol* depends on [Cryptography](https://github.com/pyca/cryptography/) package (and its' pre-packaged OpenSSL v1.1) as a source of crypto-primitives. Usage of non-default crypto backend is possible as of version 0.3.0. 
 
## Usage

#### Basic usage
NoiseConnection class provides highest level of abstraction for the package. You can access full functionality of the package
through this class' interfaces. An example for setting up NoiseConnection could look like this:

```python
import socket

from noise.connection import NoiseConnection

sock = socket.socket()
sock.connect(('localhost', 2000))

# Create instance of NoiseConnection, set up to use NN handshake pattern, Curve25519 for
# elliptic curve keypair, ChaCha20Poly1305 as cipher function and SHA256 for hashing.  
proto = NoiseConnection.from_name(b'Noise_NN_25519_ChaChaPoly_SHA256')

# Set role in this connection as initiator
proto.set_as_initiator()
# Enter handshake mode
proto.start_handshake()

# Perform handshake - as we are the initiator, we need to generate first message. 
# We don't provide any payload (although we could, but it would be cleartext for this pattern).
message = proto.write_message()
# Send the message to the responder - you may simply use sockets or any other way 
# to exchange bytes between communicating parties. 
sock.sendall(message)
# Receive the message from the responder 
received = sock.recv(2048)
# Feed the received message into noise
payload = proto.read_message(received)

# As of now, the handshake should be finished (as we are using NN pattern). 
# Any further calls to write_message or read_message would raise NoiseHandshakeError exception.
# We can use encrypt/decrypt methods of NoiseConnection now for encryption and decryption of messages.
encrypted_message = proto.encrypt(b'This is an example payload')
sock.sendall(encrypted_message)

ciphertext = sock.recv(2048)
plaintext = proto.decrypt(ciphertext)
print(plaintext)
```

The example above covers the connection from the initiator's ("client") point of view. The snippet below is an example of responder's code ("server") using a socket connection to send and receive ciphertext.

```python
import socket
from itertools import cycle

from noise.connection import NoiseConnection

if __name__ == '__main__':
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('localhost', 2000))
    s.listen(1)

    conn, addr = s.accept()
    print('Accepted connection from', addr)

    noise = NoiseConnection.from_name(b'Noise_NN_25519_ChaChaPoly_SHA256')
    noise.set_as_responder()
    noise.start_handshake()

    # Perform handshake. Break when finished
    for action in cycle(['receive', 'send']):
        if noise.handshake_finished:
            break
        elif action == 'send':
            ciphertext = noise.write_message()
            conn.sendall(ciphertext)
        elif action == 'receive':
            data = conn.recv(2048)
            plaintext = noise.read_message(data)

    # Endless loop "echoing" received data
    while True:
        data = conn.recv(2048)
        if not data:
            break
        received = noise.decrypt(data)
        conn.sendall(noise.encrypt(received))
```

#### Wireguard integration example
In *examples* directory, there is an example of interoperation of this package with Wireguard VPN solution. Please refer to [README.md](examples/wireguard/README.md) of that example for details.

#### WhatsApp compatibility

This fork provides an explicit compatibility profile for
`Noise_XX_25519_AESGCM_SHA256`, `Noise_IK_25519_AESGCM_SHA256`, and
`Noise_XXfallback_25519_AESGCM_SHA256`:

```python
from noise.connection import NoiseConnection

proto = NoiseConnection.from_name(
    b'Noise_XX_25519_AESGCM_SHA256', whatsapp_compat=True
)
```

The default (`whatsapp_compat=False`) retains standard Noise behavior. The
compatibility profile skips hashing an empty unkeyed payload and consumes the
decryption nonce before authentication, including when authentication fails.
Discard the connection after an authentication failure.

WhatsApp `XXfallback` keeps the client as initiator and starts a fresh transcript
under the fallback protocol name. To switch from IK, create a new compatible
`XXfallback` connection with the same static key, prologue, and already-sent
ephemeral key. Call `write_message(b'')` locally to mix that ephemeral into the
new transcript; do not send its returned bytes again. Then process the server's
fallback message. This does not implement standard Noise fallback semantics.

The adapters in `noise.whatsapp` implement the complete client-side handshake
exchange, including response-driven fallback, certificate verification,
ClientFinish construction, key splitting, and both transport directions:

| Adapter | Supported paths |
| --- | --- |
| `noise.whatsapp.Handshake` | XX, IK, and automatic IK → XXfallback |
| `noise.whatsapp.pq_fs.PqFsHandshake` | IKKEM_FS resume and automatic XXkem-FSfallback with ML-KEM-512 |

Install this checkout for classical handshakes, or select the optional PQ extra
(Python 3.9+ is required by pqcrypto):

```sh
python -m pip install .
# For PQ handshakes:
python -m pip install '.[whatsapp-pq]'
```

The classical adapter does not import pqcrypto. The PQ extra pins the supported
`pqcrypto==0.3.4` implementation and does not vendor native binaries.

The PQ cache must contain a trusted 32-byte X25519 public key and an 800-byte
ML-KEM-512 public key. The same exchange code handles resume and fallback.
`server_hello()` recognizes a fallback ServerHello by its encrypted-static
field. It keeps the already-sent ephemeral key and initializes the appropriate
fallback transcript. PQ fallback authenticates the new server certificate,
encapsulates to the supplied ML-KEM key, and includes the resulting ciphertext
in ClientFinish. No second ClientHello or socket connection is needed.

Both adapters use the WA6 prologue and pinned CA root, verify the certificate
chain and its binding to the handshake static key on XX/fallback, and reject
unsupported branches. Cached-key resume authenticates the response using the
configured server keys. The WA6 certificate profile parses validity timestamps
without enforcing expiry. A certificate or AEAD failure makes the adapter
unusable; it never triggers an automatic retry or a switch from PQ to classical
Noise. `client_hello()` and `server_hello()` each run once per adapter. After
completion, use `encrypt_transport()` and `decrypt_transport()` for ciphertext
bodies and `public_summary()` for state. These mutable objects are not intended
for concurrent access.

`client_hello()` and `server_hello()` exchange unframed HandshakeMessage Protobuf
bodies; frame helpers add/remove the three-byte length. Completion means local
key splitting, not account acceptance: the caller must authenticate and decode
the server's transport response to determine login success. Account storage,
login payload generation, socket creation, reconnect policy, and application
messages remain the caller's responsibility.

##### Live fallback validation

Two single-connection account probes used this fork's adapters with the same
previously exported account key and configuration. Python generated a fresh
223-byte login payload, including a new session ID, for each probe. The cache
inputs were replaced only in the probe's memory with newly generated, valid but
unrelated server public keys: X25519 for both paths, plus ML-KEM-512 for PQ.
The saved configuration was not modified.

| Observed path | TCP connections | Client protocol bytes sent | Authenticated response |
| --- | ---: | ---: | --- |
| IK → `XXfallback` | 1 | 647 | `success`, 46-byte plaintext |
| IKKEM_FS → `XXKEM_FS_FALLBACK` | 1 | 2984 | `success`, 1133-byte plaintext |

Both exchanges verified the pinned-root certificate chain and server static-key
binding, retained the original client ephemeral key across fallback, sent
ClientFinish, and authenticated the first transport frame. Complete binary-node
decoding confirmed `success` and an identity matching the generated login
payload. The PQ response additionally contained `static_pq_key`, decoding to an
800-byte public key. Each probe used a 20-second socket timeout and allowed at
most four status frames, stopping on the first `success`.

There were no retries, ADB/Frida calls, phone operations, or application-message
sends. The connections closed after the response. This demonstrates acceptance
of both fallback paths for that account/profile in those two attempts; it does
not cover chat, persistent synchronization, or arbitrary future attempts.
Account keys, login payloads, response identities, and private probe harnesses are not
distributed in this repository. The byte counts include the mobile/routing
header and frame lengths and depend on the supplied routing and payload.

##### Installed `python -m` live validation

A separate verification built a wheel from this checkout and installed it into
an isolated virtual environment. From a working directory outside the source
checkout, the environment's Python actually executed
`python -I -B -m whatsapp_fallback` with `--force-fallback` and each of
`--mode classic` and `--mode pq`. The main module and all `noise` modules loaded
from the environment's `site-packages`; their Python files matched the reviewed
source bytes. Runtime access to the source checkout was blocked.

Each invocation used the previously exported account's own static key and a
newly generated 223-byte login payload with its own fresh session ID. The
installed CLI generated unrelated valid cache public keys in memory to induce
fallback. The original account export was unchanged.

| Mode | Actual handshake path | TCP connections | Client protocol bytes sent | Authenticated plaintext | Offline decoded root |
| --- | --- | ---: | ---: | ---: | --- |
| `classic` | `XXfallback` | 1 | 647 | 46 bytes | `success` |
| `pq` | `XXKEM_FS_FALLBACK` | 1 | 2984 | 1133 bytes | `success` |

Both installed-module calls verified the pinned-root certificate chain and
server static-key binding, retained the same client ephemeral key across the
fallback, sent ClientFinish, and authenticated the first transport response.
The PQ response also contained an 800-byte `static_pq_key` after Base64 decoding.

The installed CLI saved the authenticated binary plaintext and printed its
handshake summary, size, and SHA-256. A separate offline complete binary-node
decoder then confirmed the `success` root and its identity matching the
generated payload. The CLI's `transport_authenticated` flag alone was not used
as proof of account acceptance; the CLI itself does not decode login nodes.

The audit observed one DNS lookup, one socket connection, and two client writes
per invocation. Each socket used a 20-second timeout and read one transport
frame. There were no retries, external processes in the CLI, ADB/Frida calls,
phone operations, or application-message sends. A Python audit observer recorded
module origins and I/O without replacing the CLI, socket, or cryptographic
functions. The temporary raw private-key input was removed after verification.

These two results confirm account acceptance through the installed module for
that exported account/profile. They do not cover persistent sessions or chat.
Only aggregate results are documented here; no account credentials, payload
values, response identities, private paths, or private probe/audit harnesses are bundled.

##### Complete classical and PQ call example

The repository includes [whatsapp_fallback.py](whatsapp_fallback.py) at its root;
the complete source is shown below. Run the commands from that directory after
installing this checkout. The script provides both adapters, creates one socket
for one selected DNS address, handles ServerHello and ClientFinish on that
socket, authenticates the first transport
frame, and closes the connection. It does not retry. All credential and payload
files are supplied by the caller:

| Input | Format |
| --- | --- |
| `--private-key` | The account's own raw 32-byte X25519 static private key |
| `--payload` | A newly generated, serialized login ClientPayload |
| `--routing` | Optional raw routing bytes, already Base64-decoded if exported as text |
| `--server-key` | Trusted cached raw 32-byte server X25519 public key |
| `--server-pq-key` | Trusted cached raw 800-byte ML-KEM-512 public key; PQ only |

These are binary inputs, not XML preference files or Base64 text. The example
does not implement extraction, saved-key decryption, or payload generation.
Account configuration should already match the supported primary-device login
profile. In ordinary use, supply the trusted cache keys. For a deliberate
fallback probe, `--force-fallback` generates unrelated valid public keys locally
and ignores the cache-key file arguments; it leaves the account key and payload
intact. It still requires the server to actually return a fallback response:
a mismatch can instead cause disconnection. It does not bypass certificate
verification or fall back from PQ to classical Noise.

```python
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
```

From the repository root, install with `python -m pip install .`, then run one
classical fallback probe using files prepared by your own account source reader:

```sh
umask 077
python whatsapp_fallback.py --mode classic --force-fallback \
  --private-key /path/to/account-static.raw \
  --payload /path/to/fresh-classic-payload.bin \
  --routing /path/to/routing.raw \
  --output ./classic-response.bin
```

For PQ, install `python -m pip install '.[whatsapp-pq]'` and use a separately
generated fresh payload and a new output path:

```sh
umask 077
python whatsapp_fallback.py --mode pq --force-fallback \
  --private-key /path/to/account-static.raw \
  --payload /path/to/fresh-pq-payload.bin \
  --routing /path/to/routing.raw \
  --output ./pq-response.bin
```

Omit `--routing` when no routing data is needed. To allow normal cached-key
resume and response-driven fallback, remove `--force-fallback`, pass
`--server-key /path/to/server-static.raw`, and for PQ also pass
`--server-pq-key /path/to/server-mlkem512.raw`. Each invocation attempts one
connection. It can replace an existing connection for the same account.

The installed package also provides the same script as a module, so outside
the source directory use `python -m whatsapp_fallback` with the same arguments:

```sh
python -m whatsapp_fallback --help
```

`/path/to/...` paths in the examples are placeholders for caller-supplied
binary files. The repository does not generate or include these account inputs.

The saved response is an authenticated **binary WhatsApp node**, not UTF-8/XML.
The printed `transport_authenticated` flag proves transport AEAD verification;
`summary['pattern']` identifies the actual handshake branch. A complete node
decoder supplied by the calling application must inspect the root tag for
`success`, `failure`, or `stream:error`. This example reads only the first
transport frame and does not claim login acceptance from its contents. The
live-validation results above included that additional complete decoding.
The library provides no node decoder or account configuration in this example.
Timeouts, EOF, certificate errors, and authentication failures propagate;
the socket closes and there is no retry.

At the lower level, `NoiseProtocol` also accepts
`whatsapp_compat=True, whatsapp_kem_profile=True` with either
`Noise_IKkem-FS+X25519+MLKEM512+AESGCM256+SHA256` or
`Noise_XXkem-FSfallback_25519_MLKEM512_AESGCM_SHA256`. This low-level entry point
selects X25519/AES-GCM/SHA-256 primitives while retaining the exact protocol name
for symmetric-state initialization. `PqFsHandshake` drives the KEM transcript
and `SymmetricState`; generic `NoiseConnection.from_name` cannot select a KEM
protocol and accidentally omit the KEM operations.

----
## Bug reports
This software was tested only on Linux. It may or may not work on Windows, explicit support for this system may be added in future.

Please file any bug reports in project's [issue tracker](https://github.com/plizonczyk/noiseprotocol/issues). 

## Development & contributing
Additional packages that may be useful during development are contained in dev_requirements.txt.
Installation:

```
pip install -r dev_requirements.txt
```

Running tests (from root directory):
```
pytest
```

### Todo-list for the project:

- [x] add non-default crypto algorithms support, as requested
- [ ] General standard Noise fallback patterns (WhatsApp adapters are supported above)
- [ ] scripts for keypair generation (+ console entry points)
- [ ] "echo" (noise-c like) example
- [ ] extensive logging
- [x] move away from custom ed448 implementation
- [ ] implement countermeasures for side-channel attacks
- [ ] **get peer review of the code**

You are more than welcome to propose new things to this list and/or implement them and file a merge request.

Contact the author: plizonczyk.public [at] gmail.com

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
