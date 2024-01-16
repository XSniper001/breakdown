
import socket
import threading
from M2Crypto import BIO, Rand, SMIME, X509


# Choosing Nickname
nickname = input("Choose your nickname: ")

# Connecting To Server
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(('25.1.91.86', 55555))

## decrypt
def decrypt(encmsg):
    s = SMIME.SMIME()

    # Load private key and cert.
    s.load_key('private_key.pem', 'certificate.pem')

    # Load the encrypted data.
    p7, data = SMIME.smime_load_pkcs7_bio(BIO.MemoryBuffer(encmsg))

    # Decrypt p7.
    out = s.decrypt(p7)
    return out
# Listening to Server and Sending Nickname
def receive():
    while True:
        try:
            # Receive Message From Server
            # If 'NICK' Send Nickname
            msg = client.recv(1024)
            message = msg.decode('ascii')
            print()
            if message == 'NICK':
                client.send(nickname.encode('ascii'))
                print("kourda")
            else:
                print(decrypt(msg).encode('ascii'))
        except:
            # Close Connection When Error
            print("An error occured!")
            client.close()
            break


### encrpyt message
def makebuf(text):
    return BIO.MemoryBuffer(text)

def encrpyt(msg):
    msg = makebuf(msg)
    s = SMIME.SMIME()

    # Load target cert to encrypt to.
    x509 = X509.load_cert('certificate.pem')
    sk = X509.X509_Stack()
    sk.push(x509)
    s.set_x509_stack(sk)

    #Set cipher: 3-key triple-DES in CBC mode.
    s.set_cipher(SMIME.Cipher('des_ede3_cbc'))

    # Encrypt the buffer.
    p7 = s.encrypt(msg)
    out = BIO.MemoryBuffer()
    s.write(out, p7)
    return out

# Sending Messages To Server
def write():
    while True:
        try:
            message = input('')
            message = encrpyt(bytes(message, 'utf-8'))
            message = message.read()
            client.send(message)
        except:
            print("pain")
            client.close()
            break



# Starting Threads For Listening And Writing
receive_thread = threading.Thread(target=receive)
receive_thread.start()

write_thread = threading.Thread(target=write)
write_thread.start()


