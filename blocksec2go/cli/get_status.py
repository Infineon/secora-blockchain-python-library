import sys
import argparse
import logging

from blocksec2go import open_pyscard, CardError, select_app, get_status

logger = logging.getLogger(__name__)

STATE_UNPROTECTED = 0x00
STATE_PROTECTED = 0x01

def _get_status(args):
    reader = args.reader
    status = get_status(reader)
    logger.debug('status: ' + str(status))
    if(status[-1] == STATE_UNPROTECTED):
        print('current mode: unprotected')
    if(status[-1] == STATE_PROTECTED):
        print('current mode: protected')
    if(status[-1] not in [STATE_UNPROTECTED, STATE_PROTECTED]):
        print('current mode: unsupported')

def add_subcommand(subparsers):
	parser = subparsers.add_parser('get_status', description='Retrives application status information.')
	parser.set_defaults(func=_get_status)
