import warnings
from functools import partial
from typing import Tuple

from noise.exceptions import NoiseProtocolNameError, NoisePSKError, NoiseValidationError
from noise.state import HandshakeState
from .constants import MAX_PROTOCOL_NAME_LEN, Empty


class NoiseProtocol(object):
    """
    TODO: Document
    """
    def __init__(self, protocol_name: bytes, backend: 'NoiseBackend', whatsapp_compat=False, *, whatsapp_kem_profile=False):
        # Explicit APK-specific profile; the default remains standard Noise.
        self.whatsapp_compat = bool(whatsapp_compat)
        kem_profiles = (
            b'Noise_IKkem-FS+X25519+MLKEM512+AESGCM256+SHA256',
            b'Noise_XXkem-FSfallback_25519_MLKEM512_AESGCM_SHA256',
        )
        if whatsapp_kem_profile and (not self.whatsapp_compat or protocol_name not in kem_profiles):
            raise NoiseProtocolNameError('Unsupported explicit WhatsApp KEM symmetric-state profile')
        if self.whatsapp_compat and not whatsapp_kem_profile and protocol_name not in (
            b'Noise_XX_25519_AESGCM_SHA256',
            b'Noise_IK_25519_AESGCM_SHA256',
            b'Noise_XXfallback_25519_AESGCM_SHA256',
        ):
            raise NoiseProtocolNameError('WhatsApp compatibility supports classical XX/IK/XXfallback only')
        self.name = protocol_name
        self.backend = backend
        # The KEM adapter drives SymmetricState explicitly. Only primitive
        # lookup uses the classical alias; self.name remains the exact APK
        # transcript name, and the generic HandshakeState API cannot opt in.
        primitive_name = (b'Noise_IK_25519_AESGCM_SHA256' if protocol_name == kem_profiles[0]
                          else b'Noise_XX_25519_AESGCM_SHA256') if whatsapp_kem_profile else self.name
        unpacked_name = UnpackedName.from_protocol_name(primitive_name)
        mappings = self.backend.map_protocol_name_to_crypto(unpacked_name)

        # A valid Pattern instance (see Section 7 of specification (rev 32))
        self.pattern = mappings['pattern']()
        self.pattern_modifiers = unpacked_name.pattern_modifiers
        if self.pattern_modifiers:
            # APK XXfallback retains client/server roles, initializes a fresh
            # named transcript, then hashes the already-sent client ephemeral.
            # The caller consumes the first XX write without sending it again.
            if not (self.whatsapp_compat and self.pattern_modifiers == ['fallback']):
                self.pattern.apply_pattern_modifiers(self.pattern_modifiers)

        # Handle PSK handshake options
        self.psks = None
        self.is_psk_handshake = any([modifier.startswith('psk') for modifier in self.pattern_modifiers])

        # Preinitialized
        self.dh_fn = mappings['dh']()
        self.hash_fn = mappings['hash']()
        self.hmac = partial(backend.hmac, algorithm=self.hash_fn.fn)
        self.hkdf = partial(backend.hkdf, hmac_hash_fn=self.hmac)

        # Initialized where needed
        self.cipher_class = mappings['cipher']
        self.keypair_class = mappings['keypair']

        self.prologue = None
        self.initiator = None
        self.handshake_hash = None

        self.handshake_state = Empty()
        self.symmetric_state = Empty()
        self.cipher_state_handshake = Empty()
        self.cipher_state_encrypt = Empty()
        self.cipher_state_decrypt = Empty()

        self.keypairs = {'s': None, 'e': None, 'rs': None, 're': None}

    def handshake_done(self):
        if self.pattern.one_way:
            if self.initiator:
                self.cipher_state_decrypt = None
            else:
                self.cipher_state_encrypt = None
        self.handshake_hash = self.symmetric_state.get_handshake_hash()
        del self.handshake_state
        del self.symmetric_state
        del self.cipher_state_handshake
        del self.prologue
        del self.initiator
        del self.dh_fn
        del self.hash_fn
        del self.keypair_class

    def validate(self):
        if self.is_psk_handshake:
            if any([len(psk) != 32 for psk in self.psks]):
                raise NoisePSKError('Invalid psk length! Has to be 32 bytes long')
            if len(self.psks) != self.pattern.psk_count:
                raise NoisePSKError('Bad number of PSKs provided to this protocol! {} are required, '
                                    'given {}'.format(self.pattern.psk_count, len(self.psks)))

        if self.initiator is None:
            raise NoiseValidationError('You need to set role with NoiseConnection.set_as_initiator '
                                       'or NoiseConnection.set_as_responder')

        for keypair in self.pattern.get_required_keypairs(self.initiator):
            if self.keypairs[keypair] is None:
                raise NoiseValidationError('Keypair {} has to be set for chosen handshake pattern'.format(keypair))

        if self.keypairs['e'] is not None or self.keypairs['re'] is not None:
            warnings.warn('One of ephemeral keypairs is already set. '
                          'This is OK for testing, but should NEVER happen in production!')

    def initialise_handshake_state(self):
        kwargs = {'initiator': self.initiator}
        if self.prologue:
            kwargs['prologue'] = self.prologue
        for keypair, value in self.keypairs.items():
            if value:
                kwargs[keypair] = value
        self.handshake_state = HandshakeState.initialize(self, **kwargs)
        self.symmetric_state = self.handshake_state.symmetric_state


class UnpackedName:
    def __init__(self, pattern, dh, cipher, hash, keypair, pattern_modifiers):
        self.pattern = pattern
        self.dh = dh
        self.cipher = cipher
        self.hash = hash
        self.keypair = keypair
        self.pattern_modifiers = pattern_modifiers

    @classmethod
    def from_protocol_name(cls, name):
        if not isinstance(name, bytes):
            raise NoiseProtocolNameError('Protocol name has to be of type "bytes" not {}'.format(type(name)))
        if len(name) > MAX_PROTOCOL_NAME_LEN:
            raise NoiseProtocolNameError('Protocol name too long, has to be at most '
                                         '{} chars long'.format(MAX_PROTOCOL_NAME_LEN))

        unpacked = name.decode().split('_')
        if unpacked[0] != 'Noise':
            raise NoiseProtocolNameError('Noise Protocol name shall begin with Noise! Provided: {}'.format(name))

        # Extract pattern name and pattern modifiers
        pattern = ''
        modifiers_str = None
        for i, char in enumerate(unpacked[1]):
            if char.isupper():
                pattern += char
            else:
                # End of pattern, now look for modifiers
                modifiers_str = unpacked[1][i:]  # Will be empty string if it exceeds string size
                break
        modifiers = modifiers_str.split('+') if modifiers_str else []

        return cls(
            pattern=pattern,
            dh=unpacked[2],
            cipher=unpacked[3],
            hash=unpacked[4],
            keypair=unpacked[2],
            pattern_modifiers=modifiers
        )
