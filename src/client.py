from socket import AF_INET, socket, SOCK_STREAM
from threading import Thread
import tkinter

import sys
import os
import binascii
import pickle
import struct
import time

from cryptography.hazmat.primitives import padding as paddingSimm
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

from cryptography.hazmat.primitives import hashes, hmac


from cryptography.hazmat.primitives.asymmetric import utils

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes

import gc

nonce = []
nonce.append(0)

#################################################################
#FUNZIONE per cifrare il plaitext con la chiave pubblica
def encryptAs(pt, pubkey):
    ciphertext = pubkey.encrypt(
        bytes(pt),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes   .SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

#FUNZIONE per la decifrature asimmetrica
def decryptAs(ct, prvkey):
    #decifro il cipher text inviato dal clietn
    plaintext = prvkey.decrypt(
        ct,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

#FUNZIONE che prende la chiave pubblica da utilizzare
def getPubkey():
    # controllo che il client abbia a disposizione la chiave pubblica
    if os.path.isfile("rsa_pubkey.pem"):
        filename = "rsa_pubkey.pem"
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
        client_socket.send(bytes("requestPubKey".encode()))


#FUNZIONE prendo la private key contenuta all'interno del file pem
def getPrivkeyAs():
    # prendo la chiave privata per decifrare il testo inviato dal client
    filename = "rsa_prvkeyClient.pem"
    with open(filename, 'rb') as f:
        prvkey_text = f.read()
        prvkey = serialization.load_pem_private_key(
            prvkey_text,
            password=None,
            backend=default_backend()
        )
    return prvkey

#FUNZIONE per ottenere il plaitext dal file
def getFile():
    # predno il file da salvare nel server
    filename = "file.txt"
    with open(filename, 'rb') as f:
        plaintext = f.read()
    return plaintext

#FUNZIONE aggiungo un numero al plaintext in modo da rendere la comunicazione fresca
def addP(plaintext):
    pt = str(plaintext)[2:len(plaintext)-1]
    # creo un nuemero random a caso
    p = int.from_bytes(os.urandom(16), byteorder="big")
    print(p)
    pt = str(p)+'-'+str(pt)
    return bytes(pt.encode())

#FUNZIONE converto un ogetto bytes in stringa
def bytesToStr(s):
    string = s.decode("utf-8")
    string = str(string)
    return string

#FUNZIONE rimuovo il numero concatencato al plaintext
def removeP(s,lenp):
    s = s[lenp+1:]
    return s

#FUNZIONE cifratura simmetrica
def encryptSimm(plaintext,k):
    block = int(algorithms.AES.block_size / 8)
    key_hex = k
    key = binascii.unhexlify(key_hex)

    ctx = paddingSimm.PKCS7(8*block).padder()

    padded_plaintext = ctx.update(plaintext) + ctx.finalize()
    iv = os.urandom(block)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), default_backend())
    ctx = cipher.encryptor()
    ciphertext = ctx.update(padded_plaintext) + ctx.finalize()

    #Ecrypt then MAC
    ctx = hmac.HMAC(key, hashes.SHA256(), default_backend())
    ctx.update(iv)
    ctx.update(ciphertext)
    digest = ctx.finalize()

    list = []
    list.append(digest)
    list.append(iv)
    list.append(ciphertext)
    return list

#FUNZIONE decifratura simmetrica
def decryptSimm(ciphertext,iv,digest,key):
    block = int(algorithms.AES.block_size / 8)
    key_hex = key
    key = binascii.unhexlify(key_hex)

    #verify and decrypt
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

#FUNZIONE per ottenere il plaintex dal ciphertext
def getPlaitext(s,SK):
    digest = pickle.loads(s)[0]
    iv = pickle.loads(s)[1]
    ct = pickle.loads(s)[2]
    msg = decryptSimm(ct, iv, digest, SK)
    return msg

#FUNZIONE estraggo il numero concatenato con il ciphertext
def getP(s):
    s=str(s)
    p=''
    for char in s:
        if char == '-':
            break
        else:
            p = p+char
    return int(p)

def checknonce(p):
    if p in nonce:
        return 1
#################################################################

def receive():
    while True:
        try:
            msg = client_socket.recv(BUFSIZ)
            msg = getPlaitext(msg, SK)

            p =getP(msg.decode("utf-8"))
            if checknonce(p):
                break
            msg = removeP(msg, len(str(p)))
            msg_list.insert(tkinter.END, msg.decode("utf-8"))

            nonce.append(p)

            if (msg.decode("utf-8") == "{quit}"):
                on_closing()
        except OSError:
            break


def send(event=None):
    msg = my_msg.get()

    serial = 0
    serial = int(nonce[len(nonce)-1]) + 1
    serialT = str(serial) + "-"
    serialT = bytes(serialT.encode())
    data = serialT + bytes(msg.encode())

    nonce.append(serial)

    my_msg.set("")  # Clears input field.
    #print(SK)
    ivCT = encryptSimm(data, SK)
    iv = ivCT[0]
    ciphertext = ivCT[1]
    data = pickle.dumps(ivCT)

    client_socket.send(data)
    #if msg == "{quit}":
    #    on_closing()

def on_closing(event=None):
    #client_socket.shutdown()
    print("chiudo la connessione")
    client_socket.close()
    top.quit()

top = tkinter.Tk()
top.title("Chatter")

messages_frame = tkinter.Frame(top)
my_msg = tkinter.StringVar()  # For the messages to be sent.
#my_msg.set("INSERISCI")
scrollbar = tkinter.Scrollbar(messages_frame)  # To navigate through past messages.
# Following will contain the messages.
msg_list = tkinter.Listbox(messages_frame, height=25, width=50, yscrollcommand=scrollbar.set)
scrollbar.pack(side=tkinter.RIGHT, fill=tkinter.Y)
msg_list.pack(side=tkinter.LEFT, fill=tkinter.BOTH)
msg_list.pack()
messages_frame.pack()

entry_field = tkinter.Entry(top, textvariable=my_msg)
entry_field.bind("<Return>", send)
entry_field.pack()
send_button = tkinter.Button(top, text="Send", command=send)
send_button.pack()

top.protocol("WM_DELETE_WINDOW", on_closing)

HOST = "127.0.0.1"
PORT = 33000
if not PORT:
    PORT = 33000
else:
    PORT = int(PORT)

BUFSIZ = 1024
ADDR = (HOST, PORT)

client_socket = socket(AF_INET, SOCK_STREAM)
client_socket.connect(ADDR)

#prendo la chiave pubblica
pubkey = getPubkey()
#prendo la chiave privata del client
prvkeyClient = getPrivkeyAs()

p = int.from_bytes(os.urandom(16), byteorder="big")
pEnc = encryptAs(str(p).encode(),pubkey)
#invio al server il file che deve salvare
client_socket.send(pEnc)
ID = input("Inserisci il tuo ID:")
client_socket.send(bytes(ID.encode()))
#ricevo dal server la chiave pubblica temporanea concatenata con N e P
pubkeyT = client_socket.recv(5024)
encCT = pickle.loads(pubkeyT)[0]
encTempKey = pickle.loads(pubkeyT)[1]

tempkey = decryptAs(encTempKey, prvkeyClient)
data = getPlaitext(encCT, tempkey)

#ottengo dalla stringa P, N, signature e chiave temporanea
up = len(str(p)) + 451 + 15
pServer = data[:16]
pClient = data[16:len(str(p))+16]
pubkeyT = data[16:up]
signature = data[451 + 16 + len(str(p)):]

#Variabile che contiene il messaggio da verificare con la firma digitale
stringPubkey = data[:451 + 16 + len(str(p)) - 1] + b"\n"

#Estraggo il pem dal messaggio ricevuto dal sever, elimino i primi due 3 byte in modo da togliere il numero p concatenato
pubkeyT = pubkeyT[len(str(p)):]
#Ottengo la chiave pubblica dal pem corrispondente
pubkeyT = serialization.load_pem_public_key(
                pubkeyT,
                backend=default_backend()
            )

#Verifico la digital signature fatta dal server
pubkey.verify( #If the signature does not match, verify() will raise an InvalidSignature exception
        signature,
        stringPubkey,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
#chiave di sessione
#SK = "6EF6B30F9E557F948C402C89002C7C8A"
SK = binascii.b2a_hex(os.urandom(16)).decode("utf-8")

SKServer = pServer + bytes(SK.encode())
print("CHIAVE DI SESSIONE CREATA: ",SK)
encryptedSK = encryptAs(SKServer, pubkeyT)
#Elimino la chiave pubblica temporanea
del(pubkeyT)
gc.collect()
#print("generate: ",binascii.b2a_hex(os.urandom(16)).decode("utf-8"))
#Invio al server la chiave di sessione che verrà utilizzata per lo scambio di messaggi
client_socket.send(encryptedSK)

receive_thread = Thread(target=receive)
receive_thread.start()
tkinter.mainloop() # Starts GUI execution.