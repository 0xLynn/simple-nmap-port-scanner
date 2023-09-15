#!/usr/bin/python3

import socket

io = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
io.settimeout(5)

host = input("Enter Victim's IP Address: ")
port = int(input("Enter Port Target: "))

def portScan(port):
    if io.connect_ex((host, port)):
        print("Port is Closed")
    else:
        print("Port is Open")
portScan(port)