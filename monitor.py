#!/usr/bin/env python3
"""Passively count OpenFlow PacketIn messages arriving at Floodlight."""

import argparse
import collections
import select
import socket
import struct
import subprocess
import sys
import time


IPV4_HEADER = struct.Struct("!BBHHHBBH4s4s")
TCP_HEADER = struct.Struct("!HHIIHHHH")
OPENFLOW_HEADER = struct.Struct("!BBHI")
OPENFLOW_PACKET_IN = 10
SEQ_MASK = 0xFFFFFFFF


def seq_delta(sequence, expected):
    """Return a signed TCP sequence distance, accounting for wraparound."""
    return ((sequence - expected + 0x80000000) & SEQ_MASK) - 0x80000000


class TCPStream:
    """Reassemble an observed TCP byte stream and extract OpenFlow frames."""

    def __init__(self):
        self.expected = None
        self.buffer = bytearray()
        self.pending = {}

    def _append(self, data):
        self.buffer.extend(data)
        if len(self.buffer) > 1024 * 1024:
            del self.buffer[:-65536]

    def _drain_pending(self):
        while self.expected in self.pending:
            data = self.pending.pop(self.expected)
            self._append(data)
            self.expected = (self.expected + len(data)) & SEQ_MASK

    def feed(self, sequence, payload):
        """Add TCP payload and return the OpenFlow message types completed."""
        if not payload:
            return []
        if self.expected is None:
            self.expected = sequence

        distance = seq_delta(sequence, self.expected)
        if distance > 0:
            if len(self.pending) < 128:
                self.pending[sequence] = payload
            return []
        if distance < 0:
            overlap = -distance
            if overlap >= len(payload):
                return []
            payload = payload[overlap:]

        self._append(payload)
        self.expected = (self.expected + len(payload)) & SEQ_MASK
        self._drain_pending()
        return self._extract_frames()

    def _extract_frames(self):
        types = []
        while len(self.buffer) >= OPENFLOW_HEADER.size:
            version, message_type, length, _xid = OPENFLOW_HEADER.unpack_from(self.buffer)
            if not 1 <= version <= 6 or length < OPENFLOW_HEADER.size:
                del self.buffer[0]
                continue
            if len(self.buffer) < length:
                break
            types.append(message_type)
            del self.buffer[:length]
        return types


def parse_ipv4_tcp(packet):
    """Return (src_ip, dst_ip, src_port, dst_port, seq, payload), or None."""
    if len(packet) < IPV4_HEADER.size:
        return None
    fields = IPV4_HEADER.unpack_from(packet)
    version_ihl, _tos, total_length, _ident, fragment, _ttl, protocol, _sum, src, dst = fields
    if version_ihl >> 4 != 4 or protocol != socket.IPPROTO_TCP:
        return None
    header_length = (version_ihl & 0x0F) * 4
    if header_length < IPV4_HEADER.size or len(packet) < header_length + TCP_HEADER.size:
        return None
    # Fragmented IPv4 payloads are unusual on this control connection; ignore them.
    if fragment & 0x3FFF:
        return None
    end = min(total_length, len(packet))
    tcp = packet[header_length:end]
    src_port, dst_port, sequence, _ack, offset_flags, _window, _check, _urgent = TCP_HEADER.unpack_from(tcp)
    tcp_header_length = ((offset_flags >> 12) & 0xF) * 4
    if tcp_header_length < TCP_HEADER.size or len(tcp) < tcp_header_length:
        return None
    payload = tcp[tcp_header_length:]
    return (
        socket.inet_ntoa(src), socket.inet_ntoa(dst), src_port, dst_port,
        sequence, payload,
    )


class PacketInMonitor:
    def __init__(self, args):
        self.args = args
        self.streams = {}
        self.total = collections.Counter()
        self.recent = collections.defaultdict(collections.deque)
        self.alerted = set()

    def handle_packet(self, packet, now):
        parsed = parse_ipv4_tcp(packet)
        if parsed is None:
            return
        src_ip, dst_ip, src_port, dst_port, sequence, payload = parsed
        if dst_port != self.args.port or not payload:
            return

        connection = (src_ip, src_port, dst_ip, dst_port)
        stream = self.streams.setdefault(connection, TCPStream())
        for message_type in stream.feed(sequence, payload):
            if message_type != OPENFLOW_PACKET_IN:
                continue
            self.total[connection] += 1
            queue = self.recent[connection]
            queue.append(now)
            self._trim(queue, now)
            if len(queue) > self.args.threshold and connection not in self.alerted:
                self.alerted.add(connection)
                print(
                    "ALERT: {} PacketIn messages from {}:{} within {:.1f}s (limit {}).".format(
                        len(queue), src_ip, src_port, self.args.window, self.args.threshold
                    ),
                    flush=True,
                )
                if self.args.auto_block:
                    self.block(src_ip, src_port, dst_ip, dst_port)

    def _trim(self, queue, now):
        cutoff = now - self.args.window
        while queue and queue[0] < cutoff:
            queue.popleft()

    def block(self, src_ip, src_port, dst_ip, dst_port):
        command = [
            "iptables", "-I", "INPUT", "1", "-p", "tcp",
            "-s", src_ip, "--sport", str(src_port),
            "-d", dst_ip, "--dport", str(dst_port),
            "-m", "comment", "--comment", "lab4-packetin-auto-block",
            "-j", "DROP",
        ]
        result = subprocess.call(command)
        if result == 0:
            print(
                "MITIGATION: INPUT DROP installed for {}:{} -> {}:{}.".format(
                    src_ip, src_port, dst_ip, dst_port
                ),
                flush=True,
            )
        else:
            print("BLOCK FAILED: iptables returned {} (run with sudo).".format(result), flush=True)

    def display(self):
        now = time.monotonic()
        print("PacketIn counts (rolling window {:.1f}s)".format(self.args.window))
        found = False
        for connection in sorted(self.total):
            src_ip, src_port, dst_ip, dst_port = connection
            queue = self.recent[connection]
            self._trim(queue, now)
            print(
                "  {}:{} -> {}:{} total={} recent={}".format(
                    src_ip, src_port, dst_ip, dst_port,
                    self.total[connection], len(queue),
                )
            )
            found = True
        if not found:
            print("  waiting for PacketIn traffic")
        sys.stdout.flush()

    def run(self):
        try:
            capture = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            capture.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_BINDTODEVICE,
                self.args.interface.encode("ascii") + b"\0",
            )
        except PermissionError:
            raise RuntimeError("Raw packet capture requires root; start with sudo.")
        except OSError as exc:
            raise RuntimeError("Could not capture on {}: {}".format(self.args.interface, exc))

        print(
            "Monitoring IPv4/TCP on {} for OpenFlow port {} "
            "(threshold {}, window {:.1f}s, refresh {:.1f}s).".format(
                self.args.interface, self.args.port, self.args.threshold,
                self.args.window, self.args.refresh,
            ),
            flush=True,
        )
        next_display = time.monotonic()
        while True:
            ready, _, _ = select.select([capture], [], [], self.args.refresh)
            now = time.monotonic()
            if ready:
                packet, _address = capture.recvfrom(65535)
                self.handle_packet(packet, now)
            if now >= next_display:
                self.display()
                next_display = now + self.args.refresh


def main():
    parser = argparse.ArgumentParser(
        description="Count OpenFlow PacketIn messages arriving at a controller."
    )
    parser.add_argument("--interface", default="ens33", help="capture interface")
    parser.add_argument("--port", type=int, default=6653, help="OpenFlow TCP destination port")
    parser.add_argument("--threshold", type=int, default=100, help="PacketIn limit in the window")
    parser.add_argument("--window", type=float, default=5.0, help="detection window in seconds")
    parser.add_argument("--refresh", type=float, default=1.0, help="display interval in seconds")
    parser.add_argument(
        "--auto-block", action="store_true",
        help="insert an iptables DROP rule when one source crosses the threshold",
    )
    args = parser.parse_args()
    if not 1 <= args.port <= 65535 or args.threshold < 0:
        parser.error("port must be 1-65535 and threshold must be nonnegative")
    if args.window <= 0 or args.refresh <= 0:
        parser.error("window and refresh must be positive")
    try:
        PacketInMonitor(args).run()
    except KeyboardInterrupt:
        print("\nMonitor stopped.", flush=True)
    except RuntimeError as exc:
        parser.exit(1, "ERROR: {}\n".format(exc))


if __name__ == "__main__":
    main()
