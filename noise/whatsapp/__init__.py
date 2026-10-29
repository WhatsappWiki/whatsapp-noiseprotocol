"""WhatsApp WA6 handshake adapters; no account storage or automatic networking.

Import PqFsHandshake from noise.whatsapp.pq_fs when the whatsapp-pq extra is
installed. Importing the classical adapter does not require pqcrypto.
"""
from .handshake import Handshake
from .wire import ProtocolError

__all__ = ['Handshake', 'ProtocolError']
