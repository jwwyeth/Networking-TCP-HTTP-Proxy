#!/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Your code tests start here:
# To debug in pudb3
# Highlight the line of code below below
# Type 't' to jump 'to' it
# Type 's' to 'step' deeper
# Type 'n' to 'next' over
# Type 'f' or 'r' to finish/return a function call and go back to caller
import proxy

import grader_server
import socket
import threading
import time

serverProc = threading.Thread(target=grader_server.server, args=(8924,))
serverProc.daemon = True
serverProc.start()

time.sleep(2)

out_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
out_socket.connect(("localhost", 8924))
out_socket.settimeout(None)
out_socket.sendall(b"GET /cont-len.txt HTTP/1.1\r\nHost: localhost:8924\r\n\r\n")
response = proxy.receive_response(out_socket)

assert out_socket.gettimeout() == None

with open("goal_files/cont-len.txt", "rb") as f:
    assert response[response.find(b"\r\n\r\n") + 4 :] == f.read()
