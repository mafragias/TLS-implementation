#!/usr/bin/env python2
# -*- coding: utf-8 -*-

# based on https://docs.python.org/2/library/ssl.html#server-side-operation

import socket, ssl
import tools

aes = tools.AES()    # assigning AES instanse

def print_message(data,sym_key):
    print "[SERVER] Encrypted Message Received : ",data
    dec_data = aes.decrypt(bytearray(data),bytearray(sym_key),aes.MODE)
    print "[SERVER] Decrypted Message : ", dec_data
    return False

def deal_with_client(stream,sym_key):
    # receiving data from the socket.
    data = stream.recv()
    while data:
        if not print_message(data, sym_key):
            break
        data = stream.recv()
    return data

def main():
    first = True
    s_r = True # True: server receives, False: server sends
    data = None
    message = None
    msgCounter = 1
    
    # creating socket
    bindsocket = socket.socket()
    # binding socket to a port
    bindsocket.bind(('', 10023))
    # listening up to 1 queued connections made to the socket 
    bindsocket.listen(1)
    
    while True:
        # socket accepts a connection from a socket with address fromaddr
        newsocket, fromaddr = bindsocket.accept()
        # creating server side ssl.SSLSocket with self-signed certificate - mutual authentication
        server = ssl.wrap_socket(newsocket, server_side=True, certfile="extras/server.pem", keyfile="extras/server.key", ca_certs="extras/ca.pem", cert_reqs=ssl.CERT_REQUIRED)
        print "---------------------------- MESSAGE %d ----------------------------" %(msgCounter)
        try:
            if first==True:   # first loop
                print "[SERVER] Send \"Esc\" button as message to end the conversation."
                # server generates symmetric key
                sym_key = aes.generateRandomKey(aes.KEY_SIZE)
                # server send symmetric key to client
                server.send(sym_key)
                print "[SERVER] Sending Symmetric Key : ", sym_key
                first = False
            else:   # not first loop
                if s_r==True: # receives encrypted message
                    data = deal_with_client(server,sym_key)
                    s_r=False
                else:   # sends an encrypted message
                    message = raw_input("[SERVER] Give a message to sent to client : ")
                    # encrypts the message with AES using symmetric key
                    enc_message = aes.encrypt(bytearray(message),bytearray(sym_key),aes.MODE)
                    print "[SERVER] Sending Encrypted Message : ", enc_message
                    # sending encrypted data to the server socket.
                    server.send(enc_message)
                    s_r=True
        finally:
            # shutting down connection and further sends and receives are now allowed
            server.shutdown(socket.SHUT_RDWR)
            server.close()
            
            # Breaks while loop if Esc button is pressed
            if data!=None:
                dd = aes.decrypt(bytearray(data), bytearray(sym_key), aes.MODE)
                if dd=="\x1b":
                    print "[SERVER] End of Conversation."
                    break
            if message=="\x1b":
                print "[SERVER] End of Conversation."
                break
        msgCounter += 1
                
if __name__ == "__main__":
    main()          
