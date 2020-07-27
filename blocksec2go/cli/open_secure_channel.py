import sys
import json
import argparse
import smartcard.System
import os
import logging

from blocksec2go import open_pyscard, CardError, select_app
from blocksec2go.comm.scp03 import SCP03, SECLEVEL_NONE, SECLEVEL_CMAC, SECLEVEL_CENC

from binascii import unhexlify

logger = logging.getLogger(__name__)

def _open_secure_channel(args):
    reader = args.reader
    if args.key_path is not None and os.path.exists(args.key_path):
        logger.debug("key file exists")
        with open(args.key_path, 'rb') as json_key_file:
            keys = json.load(json_key_file)
            key_mac = unhexlify(keys['key_mac'])
            key_enc = unhexlify(keys['key_enc'])
            json_key_file.close()
    else:
        raise Exception('File: ' + str(args.key_path) + ' doesn\'t exist!')

    print("HERE COMES THE CHANNEL")
    channel = SCP03()
    try:
        channel.mutualAuthenticate(reader, key_mac, key_enc, int(args.security_level))
    except Exception as e:
        raise RuntimeError('Authentication failed!')

def add_subcommand(subparsers):
    parser = subparsers.add_parser('open_secure_channel', description='Todo')
    parser.set_defaults(func=_open_secure_channel)
    parser.add_argument('security_level', help='Security level: 1...CMAC, 3...CENC')
    parser.add_argument('key_path', help='Path to file which contains SE specific keys')
