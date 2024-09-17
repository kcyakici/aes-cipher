# 290201098
# 270201072

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode
import json
import sys
import argparse


def isValidFileName(args_file):
    if not (args_file.endswith(".json")):
        return False
    return True


def isValidKey(args_key):
    if (args_key != 16 and args_key != 24 and args_key != 32):
        return False
    return True


def generate_key(password, derived_key_length, salt):
    N = 2**14  # iteration count
    r = 16  # block size
    p = 1  # parallellism_factor
    key = scrypt(password, salt, derived_key_length, N, r, p)
    return key


def encrypt_message(args):
    salt = get_random_bytes(16)
    key = generate_key(args.p, args.k, salt)
    padded_message = pad(
        bytes(args.m, encoding='utf-8'), 16, style='pkcs7')
    iv_byte = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv_byte)
    ct_bytes = cipher.encrypt(padded_message)
    b64_salt = b64encode(salt).decode("utf-8")
    b64_iv = b64encode(iv_byte).decode("utf-8")
    b64_ct = b64encode(ct_bytes).decode("utf-8")
    with open(args.f, "w") as file:
        json.dump(
            {"salt": b64_salt, "iv": b64_iv, "ciphertext": b64_ct}, file)
    print("Encryption result:")
    print(json.dumps(
        {"salt": b64_salt, "iv": b64_iv, "ciphertext": b64_ct}))


def decrypt_message(args):
    with open(args.f, "r") as file:
        object = json.loads(file.readline())
    key = generate_key(args.p, args.k, b64decode(object["salt"]))
    iv_byte = b64decode(object["iv"])
    ct_bytes = b64decode(object["ciphertext"])
    cipher = AES.new(key, AES.MODE_CBC, iv=iv_byte)
    pt_bytes = cipher.decrypt(ct_bytes)
    unpadded_pt_bytes = unpad(pt_bytes, 16, style='pkcs7')
    print(f"Plaintext: \n{unpadded_pt_bytes.decode('utf-8')}")


parser = argparse.ArgumentParser(
    description='A program to encrypt and decrypt messages to json file using AES CBC mode.')
subparsers = parser.add_subparsers(help='sub-command help')
parser_enc = subparsers.add_parser(
    "enc", help="Encrypt the message using AES CBC mode with given password and key length")
parser_dec = subparsers.add_parser(
    "dec", help="Decrypt the saved message in the json file using AES CBC mode with given password and key length")
parser_enc.add_argument(
    "-m", help="Message to be encrypted", required=True)
parser_enc.add_argument("-p", help="Password to use in encryption", required=True)
parser_enc.add_argument(
    "-k", help="Key length in bytes, must be 16, 24, or 32", type=int, choices=[16, 24, 32], required=True)
parser_enc.add_argument(
    "-f", help="File to write the encryption result. Must be of extension .json", required=True)
parser_enc.set_defaults(func=encrypt_message)

parser_dec.add_argument("-p", help="Password to use in decryption", required=True)
parser_dec.add_argument(
    "-f", help="File to read the encryption result. Must be of extension .json.", required=True)
parser_dec.add_argument(
    "-k", help="Key length in bytes, must be 16, 24, or 32", type=int, choices=[16, 24, 32], required=True)
parser_dec.set_defaults(func=decrypt_message)

args = parser.parse_args()

if not isValidKey(args.k):
    print("Key length for AES encryption, decryption must be 16, 24 or 32 bytes!")
    print("Exiting the program")
    sys.exit()

if not isValidFileName(args.f):
    print("File must be of extension .json!")
    print("Exiting the program")
    sys.exit()

args.func(args)
