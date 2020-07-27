import sys
import logging
import argparse
import json

from blocksec2go import CardError, open_pyscard, select_app

def main(argv=None):
    if argv == None:
        argv = sys.argv
    prog = sys.argv[0]
    args = sys.argv[1:]

    parser = argparse.ArgumentParser(
        prog=prog,
        description='Command line interface for Infineon\'s Blockchain Security 2Go starter kit'
    )
    subparsers = parser.add_subparsers(help='subcommands')
    parser.add_argument('--reader', help='name of the reader to use')
    parser.add_argument('--security_level',
        help='SCP03 security level')
    parser.add_argument('--key_path', help='relative path to file with keys')
    parser.add_argument('--machine-readable', help='json output', action='store_true')
    parser.add_argument(
        '--loglevel',
        help='log level',
        default='info',
        choices=['debug', 'info', 'warning', 'error', 'critical', 'nolog'],
    )

    from blocksec2go.cli import (generate_signature, generate_keypair, get_key_info,
        list_readers, get_card_info, encrypted_keyimport, set_pin, change_pin, unlock_pin,
        disable_pin, open_secure_channel, get_status, enable_protected_mode,
        add_key_label, get_key_label)
    generate_signature.add_subcommand(subparsers)
    generate_keypair.add_subcommand(subparsers)
    get_key_info.add_subcommand(subparsers)
    list_readers.add_subcommand(subparsers)
    get_card_info.add_subcommand(subparsers)
    encrypted_keyimport.add_subcommand(subparsers)
    set_pin.add_subcommand(subparsers)
    change_pin.add_subcommand(subparsers)
    unlock_pin.add_subcommand(subparsers)
    disable_pin.add_subcommand(subparsers)
    open_secure_channel.add_subcommand(subparsers)
    get_status.add_subcommand(subparsers)
    enable_protected_mode.add_subcommand(subparsers)
    add_key_label.add_subcommand(subparsers)
    get_key_label.add_subcommand(subparsers)

    args = parser.parse_args(args)
    if hasattr(args, 'func'):
        if args.loglevel != 'nolog':
            logging.basicConfig(level=args.loglevel.upper())
        try:
            args.reader = open_pyscard(args.reader)
            select_app(args.reader)
            if(args.security_level is not None):
                open_secure_channel._open_secure_channel(args)
                print("Channel opened...")
            args.func(args)
            return 0
        except CardError as e:
            if args.machine_readable:
                json.dump({'status': 'CardError', 'error': e.response.sw}, fp=sys.stdout)
            else:
                print(str(e))
            return -1
        except Exception as e:
            if args.machine_readable:
                json.dump({'status': 'error', 'error': str(e)}, fp=sys.stdout)
                return -1
            else:
                raise e
    else:
        parser.print_help()
        return 0
