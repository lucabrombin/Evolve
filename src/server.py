from socket import AF_INET, socket, SOCK_STREAM
from threading import Thread

import sys
import os
import binascii
import pickle
import time
import numpy as np

from cryptography.hazmat.primitives import padding as paddingSimm

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa

import gc

tempArray = [0]
nonceList = [[0]]
keys = []


# FUNZIONE prendo la private key contenuta all'interno del file pem
def getPrivkeyAs():
    # prendo la chiave privata per decifrare il testo inviato dal client
    filename = "rsa_prvkey.pem"
    with open(filename, 'rb') as f:
        prvkey_text = f.read()
        prvkey = serialization.load_pem_private_key(
            prvkey_text,
            password=None,
            backend=default_backend()
        )
    return prvkey


# FUNZIONE per la decifrature asimmetrica
def decryptAs(ct, prvkey):
    # decifro il cipher text inviato dal clietn
    plaintext = prvkey.decrypt(
        ct,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext


# FUNZIONE creo una chiave privata e publica temporanea
def createTemporaryPrvkey():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    keys = []
    keys.append(private_key)
    keys.append(public_key)
    return keys


# FUNZIONE converto un ogetto bytes in stringa
def bytesToStr(s):
    string = s.decode("utf-8")
    string = str(string)
    return string


# FUNZIONE estraggo il numero concatenato con il ciphertext
def getP(s):
    p = ''
    for char in s:
        if char == '-':
            break
        else:
            p = p + char
    return int(p)


# FUNZIONE rimuovo il numero concatencato al plaintext
def removeP(s, lenp):
    s = s[lenp + 1:]
    return s


# FUNIONE creo una digital signature a un file con la chiave privata a lungo termine
def createDigitalSignature(privateKey, message):
    signature = privateKey.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


# FUNZIONE cifratura simmetrica
def encryptSimm(plaintext, k):
    block = int(algorithms.AES.block_size / 8)
    key_hex = k
    key = binascii.unhexlify(key_hex)

    ctx = paddingSimm.PKCS7(8 * block).padder()

    padded_plaintext = ctx.update(plaintext) + ctx.finalize()
    iv = os.urandom(block)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), default_backend())
    ctx = cipher.encryptor()
    ciphertext = ctx.update(padded_plaintext) + ctx.finalize()

    # Encrypt then MAC
    ctx = hmac.HMAC(key, hashes.SHA256(), default_backend())
    ctx.update(iv)
    ctx.update(ciphertext)
    digest = ctx.finalize()

    list = []
    list.append(digest)
    list.append(iv)
    list.append(ciphertext)
    return list


# FUNZIONE decifratura simmetrica
def decryptSimm(ciphertext, iv, digest, key):
    block = int(algorithms.AES.block_size / 8)
    key_hex = key
    key = binascii.unhexlify(key_hex)

    # verify and decrypt
    ctx = hmac.HMAC(key, hashes.SHA256(), default_backend())
    ctx.update(iv)
    ctx.update(ciphertext)
    ctx.verify(digest)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), default_backend())
    ctx = cipher.decryptor()
    padded_plaintext = ctx.update(ciphertext) + ctx.finalize()

    ctx = paddingSimm.PKCS7(8 * block).unpadder()
    plaintext = ctx.update(padded_plaintext) + ctx.finalize()
    return plaintext


# FUNZIONE per ottenere il plaintex dal ciphertext
def getPlaitext(s, SK):
    digest = pickle.loads(s)[0]
    iv = pickle.loads(s)[1]
    ct = pickle.loads(s)[2]
    msg = decryptSimm(ct, iv, digest, SK)
    return msg


# FUNZIONE che prende la chiave pubblica da utilizzare
def getPubkey(ID):
    # controllo che il client abbia a disposizione la chiave pubblica
    if os.path.isfile(ID + "_rsa_pubkeyClient.pem"):
        filename = ID + "_rsa_pubkeyClient.pem"
        print(filename)
        with open(filename, 'rb') as f:
            pubkey_text = f.read()
            pubkey = serialization.load_pem_public_key(
                pubkey_text,
                backend=default_backend()
            )
        return pubkey
    # nel caso in cui non ce l'ho, la chiedo al server e la salvo in un file .pem
    else:
        print("Non trovo la chiave..")


# FUNZIONE per cifrare il plaitext con la chiave pubblica
def encryptAs(pt, pubkey):
    ciphertext = pubkey.encrypt(
        bytes(pt),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext


# FUNZIONE per aggiungere il nonce al messaggio
def addNonce(string, client):
    i = 0

    for sock in clients:
        if sock == client:
            serial = nonceList[i][len(nonceList[i]) - 1] + 1
            nonceList[i].append(serial)
            break
        i += 1
    # serial = int(nonceList[len(nonceList)-1]) + 1
    serialT = str(serial) + "-"
    serialT = bytes(serialT.encode())
    data = serialT + bytes(string.encode())
    return data


def addNonceList(serial, client):
    i = 0
    for sock in clients:
        if sock == client:
            nonceList[i].append(serial)
            break
        i += 1


def checkNonce(serial, client, SK):
    if serial in nonceList:
        string = "{quit}"
        data = addNonce(string, client)

        ivCT = encryptSimm(data, SK)
        data = pickle.dumps(ivCT)
        client.send(data)
        client.close()

        i = 0
        for sock in clients:
            if sock == client:
                del clients[client]
                keys.pop(i)
                nonceList.pop(i)
                break
            i = i + 1
        string = "%s has left the chat." % name
        broadcast(string, SK)


# cifrare grandi file con la chiave pubblica
def digitalEnvelope(key, ct):
    tempKey = binascii.b2a_hex(os.urandom(16)).decode("utf-8")
    encCT = encryptSimm(ct, tempKey)
    encCT = pickle.dumps(encCT)
    encTempKey = encryptAs(tempKey.encode(), key)
    list = []
    list.append(encCT)
    list.append(encTempKey)
    return list


###########################################################

def accept_incoming_connections(psw):
    while True:
        client, client_address = SERVER.accept()
        prvkey = getPrivkeyAs()

        p = client.recv(1024)
        p = decryptAs(p, prvkey)

        # Ricevo l'ID del client
        ID = client.recv(1024)
        ID = ID.decode("utf-8")
        print("ID CLIENT: ", ID)
        # Prendo la chiave pubblica del client identificato
        pubkeyClient = getPubkey(ID)

        # Creo una chiave privata e pubblica temporanea per inviarla al client
        keysT = createTemporaryPrvkey()
        prvkeyT = keysT[0]
        pubkeyT = keysT[1]

        # dall'ogetto chiave RSA creo il pem
        pemPrvkeyT = prvkeyT.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        # dall'ogetto chiave RSA pubblica creo il pem corrispondente
        pemPubkeyT = pubkeyT.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        pServer = os.urandom(16)
        # Aggiungo alla chiave pubblica il parametro s per la frescezza e il nonce del client
        pemPubkeyT = pServer + p + pemPubkeyT
        # creo la firma per la chiave pubblica temporanea
        signature = createDigitalSignature(prvkey, pemPubkeyT)
        # invio al client la chiave pubblica temporanea
        DE = digitalEnvelope(pubkeyClient, pemPubkeyT + signature)
        DE = pickle.dumps(DE)
        client.send(DE)
        time.sleep(1)
        # ricevo dal client la chiave di sessione cifrata con la chiave pubblica temporanea
        encryptedSK = client.recv(5000)
        # decripto la chiave di sessione con la chiave privata temporanea
        SK = decryptAs(encryptedSK, prvkeyT)

        pServerRecived = SK[:16]
        SK = SK[16:]

        print("confronto- ", pServerRecived, "-", pServer)
        if pServerRecived != pServer:
            print("ERRORE NEL CHECK DEL NONCE...")
            break

        print("SESSIONE STABILITA CON LA CHIAVE: ", SK.decode("utf-8"))
        #Elimino le chiavi temporanee create
        del (prvkeyT)
        del (pemPubkeyT)
        del (pubkeyT)
        gc.collect()

        addresses[client] = client_address
        active[client] = '0'
        keys.append(SK)
        nonceList.append(tempArray)
        clients[client] = "temp"

        print(addresses)
        print(keys)

        Thread(target=handle_client, args=(client, SK, psw)).start()


def handle_client(client, SK, psw):
    while True:
        pswErrata = 0
        string = "Inserisci password"
        data = addNonce(string, client)

        ivCT = encryptSimm(data, SK)
        data = pickle.dumps(ivCT)
        # print("DIGEST:", data[0])
        client.send(data)

        passw = client.recv(BUFSIZ)
        passw = getPlaitext(passw, SK)
        serial = getP(passw.decode("utf-8"))
        addNonceList(serial, client)

        passw = removeP(passw, len(str(serial)))

        print(passw)
        if (passw.decode("utf-8") != psw):
            string = "Password errata, riprova.."
            data = addNonce(string, client)

            ivCT = encryptSimm(data, SK)
            data = pickle.dumps(ivCT)
            client.send(data)
            pswErrata = 1
        if pswErrata == 0:
            break

    string = "Inserisci nome"
    data = addNonce(string, client)

    active[client] = "1"

    ivCT = encryptSimm(data, SK)
    data = pickle.dumps(ivCT)
    client.send(data)

    name = client.recv(BUFSIZ)
    name = getPlaitext(name, SK)
    serial = getP(name.decode("utf-8"))
    addNonceList(serial, client)

    name = removeP(name, len(str(serial)))
    name = name.decode()
    # print(name)
    string = '>BENVENUTO' + ' ' + name
    data = addNonce(string, client)

    ivCT = encryptSimm(data, SK)
    data = pickle.dumps(ivCT)
    client.send(data)

    string = ">%s has joined the chat!" % name

    broadcast(string, SK)
    clients[client] = name

    while True:
        try:
            msg = client.recv(BUFSIZ)
        except:
            print("errore")

        msg = getPlaitext(msg, SK)
        serial = getP(msg.decode("utf-8"))
        addNonceList(serial, client)
        checkNonce(serial, client, SK)

        msg = removeP(msg, len(str(serial)))
        if msg.decode("utf-8") != "{quit}":
            # print("Sono qui!!!!!!")
            broadcast(msg, SK, name + ": ")
        else:
            print("Sto chiudendo la connessione con:", name)

            string = "{quit}"
            data = addNonce(string, client)

            ivCT = encryptSimm(data, SK)
            data = pickle.dumps(ivCT)
            client.send(data)

            client.close()

            i = 0
            for sock in clients:
                if sock == client:
                    del clients[client]
                    keys.pop(i)
                    nonceList.pop(i)
                    break
                i = i + 1
            string = "%s has left the chat." % name
            broadcast(string, SK)
            break


# Invio il messaggio del client i-esimo ai restanti client cifrandolo con la relativa chiave di ressione
def broadcast(msg, SK, prefix=""):
    i = 0
    for sock in clients:
        SK = keys[i]
        try:
            string = prefix + msg.decode("utf-8")
        except:
            string = prefix + msg

        print(string)

        data = addNonce(string, sock)
        ivCT = encryptSimm(data, SK)
        data = pickle.dumps(ivCT)
        try:
            if active[sock] == '1':
                sock.send(data)
        except:
            print("errore")
        i = i + 1


clients = {}
addresses = {}
active = {}

HOST = ''
PORT = 33000
BUFSIZ = 1024
ADDR = (HOST, PORT)

SERVER = socket(AF_INET, SOCK_STREAM)
SERVER.bind(ADDR)

if __name__ == "__main__":
    SERVER.listen(1)
    password = input("Inserisci la password per la chat room:")
    password = password.replace(" ", "")
    print("Waiting for connection...")
    ACCEPT_THREAD = Thread(target=accept_incoming_connections, args=(password,))
    ACCEPT_THREAD.start()
    ACCEPT_THREAD.join()
    SERVER.close()
