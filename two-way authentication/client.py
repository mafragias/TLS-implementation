#!/usr/bin/env python2
# -*- coding: utf-8 -*-

# based on https://docs.python.org/2/library/ssl.html#client-side-operation

import socket, ssl
import tools

aes = tools.AES()

def print_message(data,sym_key):
    print "[CLIENT] Encrypted Message Received : ",data
    dec_data = aes.decrypt(bytearray(data),bytearray(sym_key),aes.MODE)
    print "[CLIENT] Decrypted Message : ", dec_data
    return False

def deal_with_server(stream,sym_key):
    # receiving data from the socket.
    data = stream.recv()
    while data:
        if not print_message(data, sym_key):
            break
        data = stream.recv()
    return data
    
def main():
    first = True
    s_r = True # True: client sends, False: client receives
    data = None
    message = None
    msgCounter = 1
    
    while True:
        # creating socket for client with default family address AF_INET and 
        # default socket type SOCK_STREAM
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # using self-signed certificate that is required by server - mutual authentication
        client = ssl.wrap_socket(client_socket, certfile="extras/client.pem", keyfile="extras/client.key", ca_certs="extras/ca.pem", cert_reqs=ssl.CERT_REQUIRED)
        # specifies the host and port to connect to
        client.connect(('localhost', 10023))
        print "---------------------------- MESSAGE %d ----------------------------" %(msgCounter)
        try:
            if first==True:   # first loop
                print "[CLIENT] Send \"Esc\" button as message to end the conversation."
                # waits to recieve symmetric key
                sym_key = client.recv()
                print "[CLIENT] Symmetric Key Received : ", sym_key
                first = False
            else:
                if s_r==True:   # sends an encrypted message
                    message = raw_input("[CLIENT] Give a message to sent to server : ")
                    # encrypt the message with AES using symmetric key
                    enc_message = aes.encrypt(bytearray(message),bytearray(sym_key),aes.MODE)
                    print "[CLIENT] Sending Encrypted Message : ", enc_message
                    # sending encrypted data to the server socket.
                    client.send(enc_message)
                    s_r = False
                else:   # receives encrypted message
                    data = deal_with_server(client,sym_key)
                    s_r = True
        finally:
            # closing the client ssl.SSLSocket, will also close the socket.socket            
            client.close()
            # Breaks while loop if Esc button is pressed
            if data!=None:
                dd = aes.decrypt(bytearray(data), bytearray(sym_key), aes.MODE)
                if dd=="\x1b":
                    print "[CLIENT] End of Conversation."
                    break
            if message=="\x1b":
                print "[CLIENT] End of Conversation."
                break
        msgCounter += 1
if __name__ == "__main__":
    main()     
