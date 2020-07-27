import os
import json
import logging
import argparse
import sys

from blocksec2go.comm.pyscard import open_pyscard
from blocksec2go.comm.scp03 import SCP03, SECLEVEL_CMAC
from binascii import unhexlify, hexlify
from Crypto.Cipher import AES

def select_ISD(reader):
    aid = bytes.fromhex('A000000151000000')
    response = reader.transceive(b'\x00\xA4\x04\x00', aid, le=0x12).check()

def authenticate(reader, key_enc, key_mac):
    print('Authenticating...')
    channel = SCP03()
    channel.mutualAuthenticate(reader, key_mac, key_enc, SECLEVEL_CMAC)
    print('Authentication successfull!')

def put_key(reader, new_key, key_id, key_version, key_type, key_enc_key):
    P1 = bytes([key_version]) #b'\x00' # add new key

    if(key_id > 0x7F):
        raise RuntimeError('Key identifier must be equal or less than 0x7F!')
    P2 = bytes([key_id])

    header = b'\x80\xD8' + P1 + P2
    data =  bytes([key_version]) # new key version number
    data +=  bytes([key_type]) #b'\x88' # key type: AES

    ciphered_key = bytes([len(new_key)]) + encrypt_key(key_enc_key, new_key)
    data += bytes([len(ciphered_key)]) + ciphered_key

    kcv = calc_kcv(new_key)
    data += bytes([len(kcv)])
    data += kcv

    response = reader.transceive(header, data, le=0).check()

def calc_kcv(key):
    data = b'\x01' * 16
    aes = AES.new(key, AES.MODE_CBC, IV=bytes(16))
    cipher = aes.encrypt(data)
    kcv = cipher[0:3]
    return kcv

def encrypt_key(key, data):
    aes = AES.new(key, AES.MODE_CBC, IV=bytes(16))
    data1 = aes.encrypt(data[0:16])
    data2 = aes.encrypt(data[16:32])
    return (data1 + data2)

if __name__ == '__main__':
    prog = sys.argv[0]
    args = sys.argv[1:]

    parser = argparse.ArgumentParser(
        prog=prog,
        description='Command line interface to replace keys for Infineon\'s Blockchain Security 2Go starter kit'
    )
    parser.add_argument('key_enc_key_path', help='path to file with key encryption key')
    parser.add_argument('old_key_path', help='path to file with current keys')
    parser.add_argument('new_key_path', help='path to file with new keys')

    args = parser.parse_args(args)

    #logging.basicConfig(level=0)
    reader = open_pyscard()
    select_ISD(reader)

    # get key encryption key
    if os.path.exists(args.key_enc_key_path):
        with open(args.key_enc_key_path, 'rb') as json_key_file:
            keys = json.load(json_key_file)
            key_enc_key = unhexlify(keys['key_enc_key'])
    else:
        raise Exception('File: ' + str(args.key_enc_key_path) + ' doesn\'t exist!')

    # get old keys
    if os.path.exists(args.old_key_path):
        with open(args.old_key_path, 'rb') as json_key_file:
            keys = json.load(json_key_file)
            key_mac = unhexlify(keys['key_mac'])
            key_enc = unhexlify(keys['key_enc'])
            json_key_file.close()
    else:
        raise Exception('File: ' + str(args.old_key_path) + ' doesn\'t exist!')

    # get new keys
    if os.path.exists(args.new_key_path):
        with open(args.new_key_path, 'rb') as json_key_file:
            keys = json.load(json_key_file)
            new_key_mac = unhexlify(keys['key_mac'])
            new_key_enc = unhexlify(keys['key_enc'])
            json_key_file.close()
    else:
        raise Exception('File: ' + str(args.new_key_path) + ' doesn\'t exist!')

    authenticate(reader, key_enc, key_mac)

    # replace encryption key
    key_version = 0x02
    key_id = 0x01 # key enc
    key_type = 0x88 # aes
    put_key(reader, new_key_enc, key_id, key_version, key_type, key_enc_key)

    #replace mac key
    key_version = 0x02
    key_id = 0x02 # key mac
    key_type = 0x88 # aes
    put_key(reader, new_key_mac, key_id, key_version, key_type, key_enc_key)

    print('Successfully replaced keys!')
