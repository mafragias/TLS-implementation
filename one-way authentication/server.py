#!/usr/bin/env python2
# -*- coding: utf-8 -*-

# based on https://docs.python.org/2/library/ssl.html#server-side-operation

import socket, ssl

def print_message(connstream, data):
    if data=="\x1b":
        print "Ending Connection..."    
    else:
        print "Message received : ", data
    return False

def deal_with_client(connstream):
    # receiving data from the socket.
    data = connstream.recv()
    while data:
        if not print_message(connstream, data):
            break
        data = connstream.recv()
    return data

def main():
    print "---------------------------- [SERVER] ----------------------------"
    # creating socket
    bindsocket = socket.socket()
    # binding socket to a port
    bindsocket.bind(('', 10023))
    # listening up to 1 queued connections made to the socket 
    bindsocket.listen(1)
    while True:
        # socket accepts a connection from a socket with address fromaddr
        newsocket, fromaddr = bindsocket.accept()
        # creating server side ssl.SSLSocket with self-signed certificate 
        connstream = ssl.wrap_socket(newsocket, server_side=True, certfile="extras/mycertificate.crt", keyfile="extras/mykey.key")
        try:
            data = deal_with_client(connstream)
        finally:
            # shutting down connection and further sends and receives are now allowed
            connstream.shutdown(socket.SHUT_RDWR)
            connstream.close()
            # Breaks while loop if Esc button is pressed
            if data=="\x1b":
                break
            
if __name__ == "__main__":
    main()          
