import sys
import json
import argparse

from blocksec2go.comm import open_pyscard, CardError
from blocksec2go import select_app, change_pin, unlock_pin
from blocksec2go.util import bytes_from_hex

def _disable_pin(args):
    reader = args.reader
    puk = change_pin(reader, args.pin, 'dummy')
    unlock_pin(reader, args.puk)

    if args.machine_readable:
        json.dump({'status': 'success'}, fp=sys.stdout)
    else:
        print('OK - unlocked')

def add_subcommand(subparsers):
    parser = subparsers.add_parser('disable_pin', description='Disable PIN on a card')
    parser.set_defaults(func=_disable_pin)
    parser.add_argument('pin', help='current PIN')
