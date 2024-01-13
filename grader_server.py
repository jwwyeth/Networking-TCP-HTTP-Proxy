#!/usr/bin/python3
# -*- coding: utf-8 -*-

# A very simple http server.
# Does not keep-alive

import re
import socket
import threading
import os


base_dir = "goal_files/"


def server(server_port: int = 8923) -> None:
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("localhost", server_port))
    server_socket.listen(10)

    threads = []
    while True:
        sock, addr = server_socket.accept()
        threads.append(threading.Thread(target=serve_request, args=(sock,)))
        threads[-1].start()


def serve_request(sock: socket.socket) -> None:
    # receive request
    # assumes the header is in a single tcp packet
    request = sock.recv(4096)
    # in reality, this would check for the \r\n\r\n stop signal.
    try:
        re_res = re.search(b"^GET\ (?:http://[^/]*)?/*(.*)\ HTTP/.*\r\n", request)
        filepath = re_res.group(1)  # type: ignore

        # fetch file
        if os.path.exists(base_dir + filepath.decode()):
            with open(base_dir + filepath.decode(), "rb") as f:
                file = f.read()
            content_length = str(len(file))
            header = (
                b"HTTP/1.1 200 OK\r\n"
                + b"Content-Length: "
                + content_length.encode()
                + b"\r\n\r\n"
            )
            # send file back
            sock.sendall(header + file)
        else:
            sock.sendall(b"HTTP/1.1 404 NOT FOUND\r\n\r\n")
    except:
        sock.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
    sock.close()


if __name__ == "__main__":
    server()
