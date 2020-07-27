import sys
import argparse
import logging

from blocksec2go import open_pyscard, CardError
from blocksec2go import select_app, enable_protected_mode, get_status

logger = logging.getLogger(__name__)

def _enable_protected_mode(args):
    reader = args.reader
    enable_protected_mode(reader)

def add_subcommand(subparsers):
	parser = subparsers.add_parser('enable_protected_mode', description='Irreversibly enables Protected Mode configuration.')
	parser.set_defaults(func=_enable_protected_mode)
