from M2Crypto import BIO, Rand, SMIME, X509

def makebuf(text):
    return BIO.MemoryBuffer(text)

# Make a MemoryBuffer of the message.
buf = makebuf(b'a sign of our times')

# Seed the PRNG.
Rand.load_file('randpool.dat', -1)

# Instantiate an SMIME object.
s = SMIME.SMIME()

# Load target cert to encrypt to.
x509 = X509.load_cert('certificate.pem')
sk = X509.X509_Stack()
sk.push(x509)
s.set_x509_stack(sk)

# Set cipher: 3-key triple-DES in CBC mode.
s.set_cipher(SMIME.Cipher('des_ede3_cbc'))

# Encrypt the buffer.
p7 = s.encrypt(buf)
print(p7)
# Output p7 in mail-friendly format.
out = BIO.MemoryBuffer()
s.write(out, p7)

buf = out.read()
print (buf)
# Save the PRNG's state.
Rand.save_file('randpool.dat')


print( "\n--------------------------\n")


s = SMIME.SMIME()

# Load private key and cert.
s.load_key('private_key.pem', 'certificate.pem')

# Load the encrypted data.
p7, data = SMIME.smime_load_pkcs7_bio(BIO.MemoryBuffer(buf))
# Decrypt p7.
out = s.decrypt(p7)

print(out)
