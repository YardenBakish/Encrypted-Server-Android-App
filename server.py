import socket
import threading
from threading import Thread
import time
import sys
import base64
import hashlib
from requests import get

from base64 import b64encode
from Crypto import Random
from Crypto.Cipher import AES
import pyDHE


from Crypto.Hash import SHA256, HMAC
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import base64


# Logging the data by thread

class AsyncLogWrite(threading.Thread):
    def __init__(self,text,out):
        threading.Thread.__init__(self)
        self.text = text
        self.out = out
    def run(self):
        f = open(self.out, 'a')
        f.write((str(time.ctime(time.time())))+": "+self.text+'\n')
        f.close
        print("Log Function Finished in Background")

# Encryption AES GCM
ALGORITHM_NONCE_SIZE = 12
ALGORITHM_TAG_SIZE = 16
ALGORITHM_KEY_SIZE = 16
PBKDF2_SALT_SIZE = 16
PBKDF2_ITERATIONS = 256 #This controls how fast the encryption will take - MUST
PBKDF2_LAMBDA = lambda x, y: HMAC.new(x, y, SHA256).digest()

def encryptString(plaintext, password):
    # Generate a 128-bit salt using CSPRNG
    salt = get_random_bytes(PBKDF2_SALT_SIZE)

    # Derive a key using PBKDF2
    key = PBKDF2(password, salt, ALGORITHM_KEY_SIZE, PBKDF2_ITERATIONS, PBKDF2_LAMBDA)

    # Encrypt and prepend salt
    ciphertextAndNonce = encrypt(plaintext.encode('utf-8'), key)
    ciphertextAndNonceAndSalt = salt + ciphertextAndNonce

    # Return as base64 string
    return base64.b64encode(ciphertextAndNonceAndSalt)

def decryptString(base64CiphertextAndNonceAndSalt, password):
    # Decode the base64.
    ciphertextAndNonceAndSalt = base64.b64decode(base64CiphertextAndNonceAndSalt)

    # Get the salt and ciphertextAndNonce
    salt = ciphertextAndNonceAndSalt[:PBKDF2_SALT_SIZE]
    ciphertextAndNonce = ciphertextAndNonceAndSalt[PBKDF2_SALT_SIZE:]

    # Derive the key using PBKDF2
    key = PBKDF2(password, salt, ALGORITHM_KEY_SIZE, PBKDF2_ITERATIONS, PBKDF2_LAMBDA)

    # Decrypt and return result.
    plaintext = decrypt(ciphertextAndNonce, key)

    return plaintext.decode('utf-8')

def encrypt(plaintext, key):
    # Generate a 96-bit nonce using CSPRNG.
    nonce = get_random_bytes(ALGORITHM_NONCE_SIZE)

    # Create the cipher
    cipher = AES.new(key, AES.MODE_GCM, nonce)

    #Encrypt anf prepend nonce.
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    ciphertextAndNonce = nonce + ciphertext + tag

    return ciphertextAndNonce

def decrypt(ciphertextAndNonce, key):
    # Get the nonce, ciphertext and tag.
    nonce = ciphertextAndNonce[:ALGORITHM_NONCE_SIZE]
    ciphertext = ciphertextAndNonce[ALGORITHM_NONCE_SIZE:len(ciphertextAndNonce) - ALGORITHM_TAG_SIZE]
    tag = ciphertextAndNonce[len(ciphertextAndNonce) - ALGORITHM_TAG_SIZE:]

    # Create the cipher.
    cipher = AES.new(key, AES.MODE_GCM, nonce)

    # Decrypt and return result.
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)

    return plaintext

#Diife Hellman
def DH_KeyGenerator(self):
    pAlice = format(self.connection.recv(16384))
    pAlice = int(pAlice[2:-3])
    sentData = str.encode(str(pAlice)+"\n")
    self.connection.sendall(sentData)
    print("recieved and sent: "+ str(pAlice))

    gAlice = format(self.connection.recv(16384))
    gAlice = int(gAlice[2:-3])
    sentData = str.encode(str(gAlice)+"\n")
    self.connection.sendall(sentData)
    print("recieved and sent: " +str(gAlice))

    pubAlice = format(self.connection.recv(16384))
    alicePubKey = int(pubAlice[2:-3])
    sentData = str.encode(str(alicePubKey)+"\n")
    self.connection.sendall(sentData)
    print("recieved and sent: " +str(alicePubKey))

    bob = pyDHE.new()
    bobPubKey = pow(gAlice, bob.a, pAlice)
    bobSharedKey = pow(alicePubKey, bob.a, pAlice)
    sentData = str.encode(str(bobPubKey)+"\n")
    self.connection.sendall(sentData)

    printByConnection(self, "DH Keys Exchange", "Successfully")

    print("sent Bob shared key:", int(bobSharedKey))

    return bobSharedKey


# Print by connection and log to database
def printByConnection(self, action, dataToPrint):
    cascadedData = str(self.client_addr)+" - "+action+" -> "+dataToPrint
    print(cascadedData)
    background = AsyncLogWrite(cascadedData, 'usersLog.txt')
    background.start()
    background.join()

#Decrypt -> Act ->Encrypt
def decActEnc(self, rawDataFromClient, secretKey, method):
    decData = "0"
    encDataToClient = "0"
    if (method == "GCM"):
        decData = decryptString(rawDataFromClient, secretKey)
    if(decData!="0"):
        dataToSend = decData
        if (method=="GCM"):
            encDataToClient = encryptString(dataToSend, secretKey)
        if (encDataToClient!="0"):
            printByConnection(self, "recieved", decData)
            printByConnection(self, "sent", dataToSend)
            #LOG THIS DATA
            return encDataToClient
    return "Error"

# Server Starting
def str_to_class(functionName):
    try:
        return getattr(sys.modules[__name__], functionName)
    finally:
        return "NULLFunction"

class ConnectionManagment(threading.Thread):
    def __init__ (self, connection, client_addr):
        threading.Thread.__init__(self)
        self.connection = connection
        self.client_addr = client_addr
    def run(self):
        try:
            print("connection from "+str(self.client_addr)+"\n")
            secret_key = str(DH_KeyGenerator(self))
            while True:
                receivedData = self.connection.recv(16384) #16k bytes
                printByConnection(self,"Received Raw:", format(receivedData))
                if(len(receivedData)!=0):
                    datas = decActEnc(self,receivedData, secret_key, "GCM")
                    after = str(datas)[2:-1]+"\n"
                    data = str.encode(after)
                    if (data!="Error"):
                        self.connection.sendall(data)
                    else:
                        self.connection.close()
                        break
                else:
                    print(str(self.client_addr)+" Disconnected! (no data)\n")
                    self.connection.close()
                    break
        finally:
            self.connection.close()

def setupServer(sIP, sPORT):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_address = (sIP, sPORT)
        print('starting up on {} port {}'.format(*server_address)+"\n")
        sock.bind(server_address)
        sock.listen(1)

        try:
            while True:
                print('\nwaiting for a connection \n')
                connection, client_address = sock.accept()
                backConnect = ConnectionManagment(connection,client_address)
                backConnect.start()
        finally:
            sock.close()
    finally:
        print("Server Creation Error on port "+str(sPORT)+"\n")
        sock.close()

#Main
def Main():
    hostname = socket.gethostname()
    print(hostname)
    local_ip = socket.gethostbyname(hostname)
    exIP =  local_ip
    print("Local IP:", exIP)
    sIP = "0.0.0.0"
    sPORT = 8080

    serverBuild = Thread(target = setupServer, args=(sIP, sPORT))
    serverBuild.start()

    message = "SERVER IS UP "+exIP+":"+str(sPORT)
    background = AsyncLogWrite(message, 'out.txt')
    background.start()
    background.join() #Will make a pause in program until background is finished

if __name__ == '__main__':
    Main()
    
    

