# Encrypted-Server-Android-App

## TABLE OF CONTENTS

> [ Summary ](#sum)

> [ Server ](#server)

> [ Android App Client ](#client)

> [ Technical Details ](#tech)


<a name="sum"></a>
## SUMMARY


Implementation of an encrypted bidirectional communication channel between multiple App users and a Taylor-made multi-threaded server in python


Securing the communication channel is achieved via executing the 'Diffie Hellman' key-exchange protocol which results in the client and server jointly establish a shared, secret, and unique key over an insecure channel. This key is used to encrypt subsequent communications using the 'AES-GCM' encryption which provides high speed of authenticated encryption and data integrity



<a name="SERVER"></a>
## Server

The server program utilizes multithreading allowing it to handle multiple clients, and serves as an EchoServer - sending each client the message it 
received.

In addition, the server concurrently maintains two logs which monitor various actions, as described in the following table:

| Log  | Records |
| ------------ | ------------ | 
| userslog.txt  | data received and sent both encrypted and decrypted, clients' times of connection and IP addresses, and key-exchange success status |
|  out.txt | server uptime | |



<a name="client"></a>
## Android App Client

The client-side is implemented as an Android App, allowing users to establish a secured communication channel, as described below:
>1. Type in your server I.P address and port number (please see _'Important Note'_ in the _'Technical Details'_ Section), and click the 'SECURE CHANNEL' button


![image](https://user-images.githubusercontent.com/72262159/131576174-8d29f3d2-4914-461b-b222-ab290f15ab0d.png)

>2. Send and receive messages from server


![image](https://user-images.githubusercontent.com/72262159/131576656-8be5dc75-310c-4925-8922-34570f8ee1e3.png)





<a name="tech"></a>
## Technical Details

### Important Note

When connecting to the server, type in the 'port' text widget: "8080". The 'port' widget was added in case you wish to establish communication via a
different port which in this case, requires you to change the port in 'server.py' as well (line 222). 

### Outside Network


In order to be able to receive data from an outside network i.e. your server program will be able to communicate with clients which are connected to a different network, you must contact your Internet provider and request a static public I.P.



### Python Modules
In order to run 'server.py', the following python modules must be included in your available modules:
- pycrypto
- pyDHE


