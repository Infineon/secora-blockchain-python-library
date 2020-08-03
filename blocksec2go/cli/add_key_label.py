import sys
import json
import argparse
import smartcard.System
import os
import logging

from blocksec2go import (open_pyscard, CardError, create_key_label,
    get_key_label, update_key_label)

logger = logging.getLogger(__name__)

def _add_key_label(args):
    reader = args.reader
    if(False == create_key_label(reader, int(args.key_id), len(args.label))):
        logger.debug('Storage for key ' + str(args.key_id) + ' already allocated!')
    update_key_label(reader, int(args.key_id), args.label)

def add_subcommand(subparsers):
    parser = subparsers.add_parser('add_key_label', description='Creates a label'\
        + 'for a given key.')
    parser.set_defaults(func=_add_key_label)
    parser.add_argument('key_id', help='ID of the key')
    parser.add_argument('label', help='The label for the given key')
