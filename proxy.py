#!/usr/bin/python3
# -*- coding: utf-8 -*-

import socket
import threading
from typing import Optional


def serve_client(client_socket: socket.socket) -> None:
    """
    1. receives from the client,
    2. extracts the hostname and port from its request,
    3. forwards the message unchanged to the remote,
    4. receives a response from the remote by calling receive_response,
    5. sends that message back to the client
    6. Close the out_socket at the end of the request
    """

    recieve_client = receive_header(client_socket)
    request_hostname = extract_hostname(recieve_client)  # recieves tuple of hostname

    if request_hostname is None:  # no hostname clause
        client_socket.close()
        return

    out_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    out_socket.connect(request_hostname)
    out_socket.sendall(recieve_client)
    remote_message = receive_response(out_socket)
    client_socket.sendall(remote_message)
    out_socket.close()
    client_socket.close()


def receive_header(sock: socket.socket) -> bytes:
    """
    receives from the socket until either:
    a HTTP header is received,
    or the socket is closed.
    """
    end_of_header = b"\r\n\r\n"  # the end of the header is found
    header_message = b""  # bytes
    while end_of_header not in header_message:  # while not  end of the header
        header_info = sock.recv(1024)  # buffer size
        if not header_info:
            break
        header_message += header_info

    return header_message


def extract_hostname(message: bytes) -> Optional[tuple[bytes, int]]:
    """
    Extracts the hostname and port from the HTTP header's Host field,
    and returns them as a tuple (hostname, port).
    Does not decode the hostname (leaves it as bytes)
    If no port is specified, it assumes the port is 80
    If no hostname is present, it returns None
    """

    if message.find(b"Host: ") == -1:  # if not found returns -1
        return None
    header = message.find(b"Host: ")
    header_find = b"Host: "
    hostname_port = message[
        header + len(header_find) : message.find(b"\r\n", header + len(header_find))
    ]  # finds the start hostname
    port = 80  # no specified port
    hostname = hostname_port  # only hostname, no port
    colon_split = b":"
    if colon_split in hostname_port:
        hostname, port_b = hostname_port.split(
            colon_split
        )  # split at : to get hostname and port(in bytes)
        port = int(port_b)  # change from bytes to int

    return (hostname, port)


def receive_response(out_socket: socket.socket) -> bytes:
    """
    Receives the messages from the out_socket,
    and sends them to the client_socket.
    Receives HTTP message from the out_socket
    (HTTP request must already be sent by caller)
    Receive until the content is fully transmitted
    Return the message in full
    """
    out_message = b""  # bytes
    while True:
        response_info = out_socket.recv(1024)
        if response_info:
            out_message += response_info
        else:
            break
    return out_message


def main() -> None:
    """
    Creates the proxy server's main socket and binds to it.
    With each new client that connects,
    serves their requests.
    This one is done for you.
    """
    # create the server socket, a TCP socket on localhost:6789
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind(("", 6789))

    # listen for connections
    server_sock.listen(20)

    # forever accept connections
    # thread list is never cleaned (this is a vulnerability)
    threads = []
    while True:
        client_sock, addr = server_sock.accept()
        threads.append(threading.Thread(target=serve_client, args=(client_sock,)))
        threads[-1].start()


if __name__ == "__main__":
    main()
