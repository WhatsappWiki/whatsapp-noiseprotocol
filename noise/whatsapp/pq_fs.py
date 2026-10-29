"""APK IKKEM_FS and its XXkem-FSfallback using standard-library symmetric state.

Normal resume includes static-server ML-KEM encapsulation plus fresh client
ML-KEM material. No KEM/private material from old handshakes is replayed.
"""
import hashlib
from types import SimpleNamespace
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pqcrypto.kem import ml_kem_512
from noise.noise_protocol import NoiseProtocol
from noise.backends.default import noise_backend
from noise.state import SymmetricState
from .wire import fields, get, blob, scalar, ProtocolError
from .certificates import verify_chain
from ._state import handshake_step

IK_NAME = b'Noise_IKkem-FS+X25519+MLKEM512+AESGCM256+SHA256'
FALLBACK_NAME = b'Noise_XXkem-FSfallback_25519_MLKEM512_AESGCM_SHA256'
KEM_TYPE = b'\x11\x00'

def tlv(kind, value):
    return bytes([kind]) + len(value).to_bytes(2, 'big') + value

def read_tlv(value, kind, size=None):
    if len(value) < 3 or value[0] != kind:
        raise ProtocolError('unexpected KEM TLV type/extent')
    length = int.from_bytes(value[1:3], 'big')
    if (size is not None and length != size) or length > len(value) - 3:
        raise ProtocolError('unexpected KEM TLV payload length')
    return value[3:3 + length], value[3 + length:]

class PqFsHandshake:
    def __init__(self, private, prologue, cached_server, cached_server_pq):
        if len(private) != 32 or len(cached_server) != 32 or len(cached_server_pq) != 800:
            raise ProtocolError('IKKEM_FS source key extent mismatch')
        if prologue != b'WA\x06\x03':
            raise ProtocolError('unsupported KEM mobile prologue')
        self.static = X25519PrivateKey.from_private_bytes(private)
        self.static_public = self.static.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.ephemeral = X25519PrivateKey.generate()
        self.ephemeral_public = self.ephemeral.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.remote_static, self.remote_pq = cached_server, cached_server_pq
        self.prologue = prologue
        self.pattern = 'IKKEM_FS'
        self._phase = 'new'
        self.server_authenticated = False
        self.finished = False
        self.certificate_result = None
        self.transcript_events = []
        self._initialize(IK_NAME)
        self.sym.decrypt_and_hash(cached_server)  # unkeyed pre-message MixHash

    def _initialize(self, name):
        self.protocol = NoiseProtocol(name, noise_backend, whatsapp_compat=True, whatsapp_kem_profile=True)
        self.protocol.initiator = True
        self.protocol.handshake_state = SimpleNamespace(initiator=True)
        self.sym = SymmetricState.initialize_symmetric(self.protocol)
        self.protocol.symmetric_state = self.sym
        self.sym.mix_hash(self.prologue)

    def dh(self, private, public):
        self.sym.mix_key(private.exchange(X25519PublicKey.from_public_bytes(public)))

    @handshake_step('new', 'hello_sent')
    def client_hello(self, payload):
        self.sym.mix_hash(self.ephemeral_public)
        ciphertext, shared = ml_kem_512.encrypt(self.remote_pq)
        if len(ciphertext) != 768 or len(shared) != 32:
            raise ProtocolError('static ML-KEM encapsulation extent mismatch')
        self.sym.mix_hash(ciphertext)
        self.sym.mix_key(shared)
        self.fs_public, self.fs_private = ml_kem_512.generate_keypair()
        serialized_fs = KEM_TYPE + self.fs_public
        self.sym.mix_hash(serialized_fs)
        self.dh(self.ephemeral, self.remote_static)
        encrypted_payload = self.sym.encrypt_and_hash(self.static_public + payload)
        self.dh(self.static, self.remote_static)
        self.transcript_events.extend(['rs', 'e', 'static-kem-ct', 'static-kem-ss',
                                       'serialized-fs-public', 'es', 'encrypted-static-and-payload', 'ss'])
        hello = (blob(1, self.ephemeral_public) + blob(3, encrypted_payload)
                 + blob(5, tlv(1, ciphertext)) + scalar(9, 6) + blob(10, tlv(3, serialized_fs)))
        return blob(2, hello)

    def _finish(self):
        self.sym.split()
        self.finished = True

    @handshake_step('hello_sent', 'complete')
    def server_hello(self, wrapped, payload):
        hello = fields(get(fields(wrapped), 3))
        if get(hello, 2, required=False) is not None:
            return self._fallback(hello, payload)
        remote_ephemeral = get(hello, 1)
        if len(remote_ephemeral) != 32:
            raise ProtocolError('invalid responder ephemeral key')
        self.sym.mix_hash(remote_ephemeral)
        ct, trailing = read_tlv(get(hello, 6), 4, 768)
        if trailing:
            raise ProtocolError('trailing bytes after responder KEM ciphertext')
        shared = ml_kem_512.decrypt(self.fs_private, ct)
        self.sym.mix_hash(ct)
        self.sym.mix_key(shared)
        self.dh(self.ephemeral, remote_ephemeral)
        self.dh(self.static, remote_ephemeral)
        server_payload = self.sym.decrypt_and_hash(get(hello, 3))
        self.server_authenticated = True
        self.certificate_result = {'cached_static_and_static_MLKEM_authenticated': True,
                                   'fresh_client_MLKEM_authenticated': True,
                                   'server_payload_bytes': len(server_payload),
                                   'source': 'authenticated cached X25519 and ML-KEM-512 server public keys'}
        self.transcript_events.extend(['re', 'fs-kem-ct', 'fs-kem-ss', 'ee', 'se', 'server-payload'])
        self._finish()
        return None

    def _fallback(self, hello, payload):
        # Same connection, same already-sent e. Discard failed resume state.
        self.pattern = 'XXKEM_FS_FALLBACK'
        self._initialize(FALLBACK_NAME)
        self.sym.mix_hash(self.ephemeral_public)
        remote_ephemeral = get(hello, 1)
        if len(remote_ephemeral) != 32:
            raise ProtocolError('invalid fallback responder ephemeral key')
        self.sym.mix_hash(remote_ephemeral)
        self.dh(self.ephemeral, remote_ephemeral)
        encrypted_static = get(hello, 2)
        if len(encrypted_static) != 48:
            raise ProtocolError('invalid encrypted fallback static key')
        remote_static = self.sym.decrypt_and_hash(encrypted_static)
        if len(remote_static) != 32:
            raise ProtocolError('invalid fallback responder static key')
        self.dh(self.ephemeral, remote_static)
        combined = self.sym.decrypt_and_hash(get(hello, 3))
        algorithm, rest = read_tlv(combined, 1, 8)
        if algorithm != b'MLKEM512':
            raise ProtocolError('unexpected fallback KEM algorithm')
        pq_public, certificate = read_tlv(rest, 2, 800)
        ciphertext, shared = ml_kem_512.encrypt(pq_public)
        self.sym.mix_hash(ciphertext)
        self.sym.mix_key(shared)
        self.certificate_result = verify_chain(certificate, remote_static)
        self.server_authenticated = True
        encrypted_static = self.sym.encrypt_and_hash(self.static_public)
        self.dh(self.static, remote_ephemeral)
        encrypted_payload = self.sym.encrypt_and_hash(payload)
        finish = blob(4, blob(1, encrypted_static) + blob(2, encrypted_payload) + blob(3, ciphertext))
        self._finish()
        return finish

    @handshake_step('complete', 'complete')
    def decrypt_transport(self, ciphertext):
        if not self.finished or not self.server_authenticated:
            raise ProtocolError('PQ handshake not complete')
        return self.protocol.cipher_state_decrypt.decrypt_with_ad(b'', ciphertext)

    @handshake_step('complete', 'complete')
    def encrypt_transport(self, plaintext):
        return self.protocol.cipher_state_encrypt.encrypt_with_ad(b'', plaintext)

    def public_summary(self):
        return {'pattern': self.pattern, 'library_split_completed': self.finished, 'state': self._phase,
                'server_authenticated': self.server_authenticated, 'certificate': self.certificate_result,
                'handshake_hash_sha256': hashlib.sha256(self.protocol.handshake_hash).hexdigest()
                if self.finished else None}
