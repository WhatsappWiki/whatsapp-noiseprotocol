"""Single-use handshake transitions shared by the WhatsApp adapters."""
from functools import wraps

from .wire import ProtocolError


def handshake_step(expected, following):
    def decorate(method):
        @wraps(method)
        def call(self, *args, **kwargs):
            if self._phase != expected:
                raise ProtocolError('invalid handshake state: ' + self._phase)
            try:
                result = method(self, *args, **kwargs)
            except Exception:
                # Authentication may already have consumed a nonce or changed
                # the transcript. Never retry using that state.
                self._phase = 'failed'
                self.server_authenticated = False
                raise
            self._phase = following
            return result
        return call
    return decorate
