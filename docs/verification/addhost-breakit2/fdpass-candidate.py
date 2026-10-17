#!/usr/bin/python3
"""Measure early TCP_NODELAY through OpenSSH's existing descriptor handoff on owned Docker peers only."""
import array
import ipaddress
import os
import socket
import sys


def main():
    host = ipaddress.ip_address(sys.argv[1])
    port = int(sys.argv[2])
    if host not in ipaddress.ip_network("172.17.0.0/16") or port != 22:
        raise ValueError("candidate is restricted to the owned Docker SSH fixture")
    with socket.create_connection((str(host), port), timeout=10) as stream:
        stream.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        congestion = os.environ.get("ADDHOST_FAST_CONGESTION", "default")
        if congestion not in ["default", "bbr", "cubic"]:
            raise ValueError("unsupported diagnostic congestion control")
        if congestion != "default":
            stream.setsockopt(socket.IPPROTO_TCP, socket.TCP_CONGESTION, congestion.encode())
        send_buffer = int(os.environ.get("ADDHOST_FAST_SENDBUF", "0"))
        if send_buffer not in [0, 262144, 1048576]:
            raise ValueError("unsupported diagnostic send buffer")
        if send_buffer:
            stream.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, send_buffer)
        with socket.socket(fileno=os.dup(0)) as channel:
            channel.sendmsg(
                [b"."],
                [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [stream.fileno()]))],
            )


if __name__ == "__main__":
    main()
