#!/usr/bin/env python3

import sys
import random
import os
import secret
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Util import Padding 
from Crypto.Util.number import long_to_bytes

import logging
logging.basicConfig()
log = logging.getLogger("LOG")
log.setLevel(logging.INFO)


# DH parameters from RFC3526
PRIME = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF
GEN = 2

def dh_genpub(secret):
    return pow(GEN, secret, PRIME)

def dh_exchange(peer_pub, secret):
    return pow(peer_pub, secret, PRIME)

ID_SERVER = dh_genpub(int.from_bytes(b'server', 'big'))
rng = random.SystemRandom()

def do_protocol(pin, user_id, user_pub, message):

    ### Protocol step 1 / identifier and DH parameter from client
    email_hash = SHA256.new(user_id.encode()).digest()
    email_num = int.from_bytes(email_hash, "big")

    if not (0 < user_pub < PRIME):
        # Invalid DH parameter
        sys.exit(1)

    ### Protocol step 2 / generate DH parameter
    id_a = dh_genpub(email_num)
    mask_client = dh_exchange(id_a, -pin)
    # mask_client = U ^ -pi0
    # user_pub = X
    t_a = (user_pub * mask_client) % PRIME
    # t_a = X * (U ^ -pi0)

    # r_b = y
    r_b = rng.randint(1, PRIME-1)

    t_b = dh_genpub(r_b)
    # t_b = g ^ y
    mask_server = dh_exchange(ID_SERVER, pin)
    # mask_server = V ^ pi0
    server_pub = (t_b * mask_server) % PRIME
    # server_pub = Y
    # log.info("Y = %s (g ^ y = %s)", hex(server_pub), hex(pow(2, r_b, PRIME)))

    ### Send public parameter
    print("Server public parameter:", server_pub)

    ### Calculate shared secret
    z = dh_exchange(t_a, r_b)
    # log.info("Z = %s (g ^ x = %s)", hex(z), hex(t_a))

    key = SHA256.new(long_to_bytes(id_a) + long_to_bytes(ID_SERVER) + long_to_bytes(user_pub) + long_to_bytes(server_pub) + long_to_bytes(pin) + long_to_bytes(z)).digest()

    ### Send encrypted message

    aes = AES.new(key, AES.MODE_ECB)
    enc = aes.encrypt(Padding.pad(message.encode(), 16))

    return enc


def run_protocol(pin, msg):
    print("Welcome to s3cur3 b4nk! Please follow the protocol for ultimate flag experience!")
    user_id = input("Email address:")
    user_pub = int(input("Public parameter:"))

    ct = do_protocol(pin, user_id, user_pub, msg)
    print("Ciphertext:", ct.hex())


def main():
    challenge = os.urandom(32).hex()
    msg = 'Challenge: ' + challenge

    pin = rng.randint(0000, 9999)
    log.info("PIN = %d", pin)
    run_protocol(pin, msg)

    respone = input("Response:")
    if challenge != respone:
        sys.exit(1)

    pin = rng.randint(0000, 9999)
    log.info("PIN = %d", pin)
    run_protocol(pin, secret.flag)

if __name__ == '__main__':
    main()
