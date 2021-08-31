# Encrypted-Server-Android-App

## TABLE OF CONTENTS

> [ Summary ](#sum)

> [ Server ](#server)

> [ Android App Clients ](#client)

> [ Technical Details ](#tech)


<a name="sum"></a>
## SUMMARY


Implementation of an encrypted bidirectional communication channel between multiple App users and a Taylor-made multi-threaded server in python


Securing the communication channel is achieved via excecuting the 'Diffie Hellman' key-exchange protocol which results in the client and server jointly establish a shared, secret and unique key over an insecure channel. This key is used to encrypt subsequent communications using the 'AES-GCM' encryption which provides high speed of authenticated encryption and data integrity



<a name="AERVER"></a>
## Server

The server program utilizes concurrency programing allowing it to handle multiple clients. It serves as an EchoServer - sending each client the message it 
recieved.

In addition to the server-client communication, the server cocurrently maintains two logs in the form of txt files - 



<a name="client"></a>
## Android App Users


<a name="tech"></a>
### Outside Network


In order to be able to receive data from an outside network i.e your server program will be able to communicate with clients which are connected to a different network, you must contact your Internet provider and request a static public I.P.



### Python Modules
In order to run 'server.py', the following python modules must be included in your availabe modules:
- pycrypto
- pyDHE


