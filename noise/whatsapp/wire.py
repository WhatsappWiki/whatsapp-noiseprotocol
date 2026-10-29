"""Bounded protobuf wire and 24-bit frame handling; no generated message guesses."""
from collections import namedtuple

MAX_FRAME = 1024 * 1024

class ProtocolError(ValueError):
    pass

def varint(value):
    if not 0 <= value < 1 << 64:
        raise ProtocolError('varint out of range')
    out = bytearray()
    while value >= 128:
        out.append((value & 127) | 128)
        value >>= 7
    out.append(value)
    return bytes(out)

def read_varint(data, pos):
    value = 0
    for index in range(10):
        if pos >= len(data):
            raise ProtocolError('truncated varint')
        byte = data[pos]
        pos += 1
        if index == 9 and byte > 1:
            raise ProtocolError('overflow varint')
        value |= (byte & 127) << (index * 7)
        if byte < 128:
            return value, pos
    raise ProtocolError('overflow varint')

Field = namedtuple('Field', 'number wire value encoded')

def fields(data):
    if len(data) > MAX_FRAME:
        raise ProtocolError('protobuf too large')
    pos = 0
    result = []
    while pos < len(data):
        start = pos
        tag, pos = read_varint(data, pos)
        number, wire = tag >> 3, tag & 7
        if not 0 < number < 1 << 29:
            raise ProtocolError('invalid field number')
        if wire == 0:
            value, pos = read_varint(data, pos)
        elif wire in (1, 2, 5):
            if wire == 2:
                length, pos = read_varint(data, pos)
            else:
                length = 8 if wire == 1 else 4
            if length > len(data) - pos:
                raise ProtocolError('truncated field')
            value = data[pos:pos + length]
            pos += length
        else:
            raise ProtocolError('unsupported protobuf group/wire type')
        result.append(Field(number, wire, value, data[start:pos]))
    return result

def scalar(number, value):
    return varint(number << 3) + varint(value)

def blob(number, value):
    value = bytes(value)
    return varint(number << 3 | 2) + varint(len(value)) + value

def get(items, number, wire=2, required=True):
    values = [f.value for f in items if f.number == number and f.wire == wire]
    if not values:
        if required:
            raise ProtocolError('required protobuf field missing: ' + str(number))
        return None
    # Generated scalar proto2 parsers keep the final occurrence.
    return values[-1]

def frame(data):
    if not 0 < len(data) <= MAX_FRAME:
        raise ProtocolError('frame outside supported bound')
    return len(data).to_bytes(3, 'big') + data

def read_exact(sock, size):
    result = bytearray()
    while len(result) < size:
        part = sock.recv(size - len(result))
        if not part:
            raise EOFError('connection ended before full frame')
        result.extend(part)
    return bytes(result)

def recv_frame(sock):
    size = int.from_bytes(read_exact(sock, 3), 'big')
    if not 0 < size <= MAX_FRAME:
        raise ProtocolError('incoming frame outside supported bound')
    return read_exact(sock, size)

def intro(prologue, routing=b''):
    if prologue not in (b'WA\x06\x03', b'WA\x05\x03'):
        raise ProtocolError('unsupported mobile header')
    if len(routing) > MAX_FRAME:
        raise ProtocolError('routing info too large')
    return (b'ED\0\1' + len(routing).to_bytes(3, 'big') + routing if routing else b'') + prologue
