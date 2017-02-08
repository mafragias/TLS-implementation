#!/usr/bin/env python2
# -*- coding: utf-8 -*-

# based on https://docs.python.org/2/library/ssl.html#client-side-operation

import socket, ssl

def main():
    print "---------------------------- [CLIENT] ----------------------------"
    # creating socket for client with default family address AF_INET and 
    # default socket type SOCK_STREAM
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # using self-signed certificate that is required by server
    client = ssl.wrap_socket(client_socket, ca_certs="extras/mycertificate.crt", cert_reqs=ssl.CERT_REQUIRED)
    # specifies the host and port to connect to
    client.connect(('localhost', 10023))
    
    print "Note: Sending \"Esc button\"as message will terminate the server.\n"
    message = raw_input("Give a message to send : ")

    # sending data to the server socket.
    client.send(message)
    # closing the client ssl.SSLSocket, will also close the socket.socket
    client.close()

if __name__ == "__main__":
    main()     
