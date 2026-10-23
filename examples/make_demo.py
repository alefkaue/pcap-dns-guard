"""Generate a synthetic single-query Ethernet/IPv4 PCAP; never captures traffic."""
import struct
from pathlib import Path
dns = struct.pack('!6H', 1, 0x0100, 1, 0, 0, 0) + b'\x07example\x03com\x00' + struct.pack('!2H', 1, 1)
udp = struct.pack('!4H', 53000, 53, 8 + len(dns), 0) + dns
ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                 bytes([192, 0, 2, 1]), bytes([192, 0, 2, 53])) + udp
frame = bytes(12) + b'\x08\x00' + ip
capture = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
capture += struct.pack('<4I', 1, 0, len(frame), len(frame)) + frame
out = Path(__file__).with_name('synthetic.pcap')
out.write_bytes(capture)
print('Synthetic fixture created:', out.name)
