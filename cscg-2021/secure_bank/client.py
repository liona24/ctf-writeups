import random
import socket
import sys
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Util import Padding

import solve

rng = random.SystemRandom()

#RFC 3526 Primes
prime = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF
generator = 2

def readuntil(sock, char):
    ret = b''
    while True:
        c = sock.recv(1)
        if c == char:
            break
        ret += c
    return ret

def int_to_bytes(i):
    return i.to_bytes((i.bit_length() + 7) // 8, 'big')

def run_protocol(s, email, prompt, known_plain):
    _welcome_message = readuntil(s, b'\n')
    
    ### Protocol step 1 / calculate DH parameter

    # r_a = x
    r_a = rng.randint(1, prime-1)
    r_a = prime - 1 # FIXME
    t_a = pow(generator, r_a, prime)
    
    email = "server" # should not matter, but w/e
    email_hash = SHA256.new(bytes(email, 'utf-8')).digest()
    Hu = int.from_bytes(email_hash, byteorder='big')
    id_a = pow(generator, Hu, prime)
    U = id_a
    pin = 0
    # pin = int(input(prompt))

    m = (t_a * pow(id_a, pin, prime)) % prime
    assert m == 1
    X = m

    ### Send identifier and public DH parameter

    s.send(bytes(email, 'utf-8')+ b'\n')
    s.send(bytes(str(m), 'utf-8') + b'\n')

    ### Step 2 / parameter from server

    m2 = int(readuntil(s, b'\n').decode().split(':')[-1])
    Y = m2

    if not (0 < m2 < prime):
        # Invalid DH parameter
        sys.exit(1)

    id_server = pow(generator, int.from_bytes(bytes('server', 'utf-8'), byteorder='big'), prime)
    V = id_server
    t_b = (m2 * pow(id_server, -pin, prime)) % prime

    enc = bytes.fromhex(readuntil(s, b'\n').decode().split(' ')[-1])

    plain, k, pi0 = solve.solve_for_pin(U, V, X, Y, Hu, Hu, enc, known_plain, prime)
    print("Found pin:", pi0)
    print(plain)
    return str(plain, "utf-8")

    """
    ### Calculate shared secret

    z = pow(t_b, r_a, prime)

    k = SHA256.new(int_to_bytes(id_a) + int_to_bytes(id_server) + int_to_bytes(m) + int_to_bytes(m2) + int_to_bytes(pin) + int_to_bytes(z)).digest()

    ### Decrypt message from server

    enc = bytes.fromhex(readuntil(s, b'\n').decode().split(' ')[-1])

    aes = AES.new(k, AES.MODE_ECB)

    return str(Padding.unpad(aes.decrypt(enc), 16), 'utf-8')
    """


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('127.0.0.1', 1024))

# email = input('Email: ')

response = run_protocol(s, "fakemail", 'Pin 1: ', b"Challenge:").split(' ')[1]

s.send(bytes(response, 'utf-8') + b'\n')

print(run_protocol(s, "fakemail", 'Pin 2: ', b"CSCG{"))
