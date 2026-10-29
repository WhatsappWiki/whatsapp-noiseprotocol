"""Classical XX/IK/XXfallback, using the modified standard library state machine."""
import hashlib
from noise.connection import NoiseConnection, Keypair
from .wire import blob, fields, get, ProtocolError
from .certificates import verify_chain
from ._state import handshake_step

SUFFIX = b'_25519_AESGCM_SHA256'

class Handshake:
    def __init__(self, private, prologue=b'WA\x06\x03', cached_server=None):
        if len(private) != 32:
            raise ValueError('connection static private key must be 32 bytes')
        if prologue != b'WA\x06\x03':
            raise ProtocolError('only APK WA6 certificate profile is implemented')
        if cached_server is not None and len(cached_server) != 32:
            raise ProtocolError('cached server static key must be 32 bytes')
        self.private = private
        self.prologue = prologue
        self.pattern = 'IK' if cached_server else 'XX'
        self.cached_server = cached_server
        self.connection = self._new(self.pattern, cached_server)
        self.first_ephemeral = None
        self.first_private = None
        self._phase = 'new'
        self.server_authenticated = False
        self.certificate_result = None
        self.pending_finish = None

    def _new(self, pattern, cached_server=None, ephemeral=None):
        connection = NoiseConnection.from_name(b'Noise_' + pattern.encode() + SUFFIX, whatsapp_compat=True)
        connection.set_as_initiator()
        connection.set_prologue(self.prologue)
        connection.set_keypair_from_private_bytes(Keypair.STATIC, self.private)
        if cached_server:
            connection.set_keypair_from_public_bytes(Keypair.REMOTE_STATIC, cached_server)
        if ephemeral:
            connection.set_keypair_from_private_bytes(Keypair.EPHEMERAL, ephemeral)
        connection.start_handshake()
        return connection

    @handshake_step('new', 'hello_sent')
    def client_hello(self, payload):
        message = bytes(self.connection.write_message(payload if self.pattern == 'IK' else b''))
        state = self.connection.noise_protocol.handshake_state
        from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
        self.first_private = state.e.private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        self.first_ephemeral = message[:32]
        hello = blob(1, message[:32])
        if self.pattern == 'IK':
            hello += blob(2, message[32:80]) + blob(3, message[80:])
        return blob(2, hello)

    @handshake_step('hello_sent', 'complete')
    def server_hello(self, wrapped, payload):
        hello = fields(get(fields(wrapped), 3))
        # Reject PQ extensions instead of silently altering security mode.
        if any(f.number in (4, 6) and f.wire == 2 and f.value for f in hello):
            raise ProtocolError('server returned PQ extension; classical profile cannot process it')
        ephemeral = get(hello, 1)
        encrypted_static = get(hello, 2, required=False)
        encrypted_payload = get(hello, 3)
        if len(ephemeral) != 32:
            raise ProtocolError('invalid server ephemeral extent')
        if self.pattern == 'IK' and encrypted_static is not None:
            # Same TCP exchange; replay e into a fresh named transcript locally.
            self.pattern = 'XXfallback'
            self.connection = self._new('XXfallback', ephemeral=self.first_private)
            if bytes(self.connection.write_message(b'')) != self.first_ephemeral:
                raise ProtocolError('fallback ephemeral identity changed')
        if self.pattern == 'IK':
            certificate_payload = bytes(self.connection.read_message(ephemeral + encrypted_payload))
            self.server_authenticated = True  # cached static plus successful IK AEAD
            self.certificate_result = {'cached_static_IK_authenticated': True,
                                       'server_payload_bytes': len(certificate_payload)}
            return None
        if encrypted_static is None or len(encrypted_static) != 48:
            raise ProtocolError('invalid encrypted server static extent')
        certificate_payload = bytes(self.connection.read_message(ephemeral + encrypted_static + encrypted_payload))
        server_key = self.connection.noise_protocol.handshake_state.rs.public_bytes
        self.certificate_result = verify_chain(certificate_payload, server_key)
        self.server_authenticated = True
        finish = bytes(self.connection.write_message(payload))
        self.pending_finish = blob(4, blob(1, finish[:48]) + blob(2, finish[48:]))
        return self.pending_finish

    @handshake_step('complete', 'complete')
    def decrypt_transport(self, ciphertext):
        if not self.server_authenticated or not self.connection.handshake_finished:
            raise ProtocolError('handshake not complete')
        return self.connection.decrypt(ciphertext)

    @handshake_step('complete', 'complete')
    def encrypt_transport(self, plaintext):
        return self.connection.encrypt(plaintext)

    def public_summary(self):
        return {'pattern': self.pattern, 'library_split_completed': self.connection.handshake_finished,
                'state': self._phase,
                'server_authenticated': self.server_authenticated, 'certificate': self.certificate_result,
                'handshake_hash_sha256': hashlib.sha256(self.connection.get_handshake_hash()).hexdigest()
                if self.connection.handshake_finished else None}
