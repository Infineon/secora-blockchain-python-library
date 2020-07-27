import sys
import json
import argparse
import smartcard.System
import os
import logging

from blocksec2go import (open_pyscard, CardError, create_key_label,
    get_key_label, update_key_label)

logger = logging.getLogger(__name__)

def _get_key_label(args):
    reader = args.reader

    _, received = get_key_label(reader, int(args.key_id))
    print('Label for key ID ' + args.key_id + ': \n\n' + str(received))

def add_subcommand(subparsers):
    parser = subparsers.add_parser('get_key_label', description='Gets the label'\
        + 'for a given key.')
    parser.set_defaults(func=_get_key_label)
    parser.add_argument('key_id', help='ID of the key')
