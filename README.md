# SECORA<sup>TM</sup> Blockchain Python Library

This package provides basic functions to communicate with Infineon's SECORA<sup>TM</sup> Blockchain. 
It abstracts all of the commands available with SECORA<sup>TM</sup> Blockchain with some simple functions. 

To get more information about the evaluation kit of SECORA<sup>TM</sup> Blockchain - the Blockchain security 2go starter kit - go to [https://github.com/Infineon/blockchain].

## Getting Started
To use this library you need some hardware first:
* A SECORA<sup>TM</sup> Blockchain device 
and
* a contactless reader to communicate with the contactless smart card. We recommend to use 
a reader that is connected via USB (a list is available at 
[ccid.apdu.fr](https://ccid.apdu.fr/select_readers/?features=contactless)). 

To use the library you need a Python 3 installation (e.g. from http://python.org or via [Anaconda](https://www.anaconda.com/))

Then, the fastest way to install the library is to get it via pip

    $ pip install blocksec2go

Remark: When installing Python 3>=3.4 the installer program `pip` is automatically installed (see https://pip.pypa.io/en/stable/installing/). 

This will install the library, which can be imported as `blocksec2go`.
In addition the `blocksec2go` command line tool will be installed which can be used to communicate with 
the card from the command line.

To find out more, run

    $ blocksec2go --help

The library is tested with Python 3.7.1 and the Identive Cloud 4700 F Dual Interface reader.

## Protected and unprotected mode 
The secure communication is optional. The user can decide wether to use it or not. There are two possible configurations as given below:
* Unprotected Mode
* Protected Mode

It is possible to get the current product configuration by issuing 
    
    $ blocksec2go get_status
 
**IMPORTANT:** If the protected mode is already enabled, get_status will return "0x6982 Security condition not satisfied"!

The unprotected Mode is the default configuration. In this mode all commands are allowed without being preceded by the establishment of a secure communication channel between a card and an off-card entity during an application session.

**Attention: Enabling Protected Mode is an irreversible operation!**

The protected mode can be enabled by issuing 

    $ blocksec2go enable_protected_mode
    
**IMPORTANT:** If the protected mode is already enabled, enable_protected_mode will return "0x6982 Security condition not satisfied"!

Once enabled it is not possible to switch back to unprotected mode.

In the protected mode all commands shall be preceded by the establishment of a secure communication channel between a card and an off-card entity during an application session. A description for how to establish a secure channel can be found in [Running commands in protected mode](https://github.com/WaltherPachler/blocksec2go_volume#running-commands-in-protected-mode).

## Running commands in protected mode
To run a command in protected mode, a secure channel has to be established first. In order to establish a secure channel for a certain command, the command shall be preceded by the following paramters

    $ blocksec2go --security_level <level> --key_path <relative path to key> <command>

Where level is one of the following values:
* 1: Security Level C-MAC -> C-MAC is used
* 3: Security Level C-MAC and C-DECRYPTION -> C-MAC and encryption is used 

The parameter --key_path is the relative path to the file in which the 256-bit encryption and mac keys are stored. This should be a json file and of the following form:

        {
         "key_mac" : "<your key in hex format>",
         "key_enc" : "<your key in hex format>"
        }

**NOTE:** For each command, a new session is established!

## Usage Example
### Python Library
Go to the [Blockchain Security 2Go repository](https://github.com/Infineon/Blockchain/tree/master/pc) to find examples of how to use the Python library.

### Command Line Tool
Here is an example of how the command line tool could be used

    $ blocksec2go get_card_info
      PIN is: disabled
	  Card ID (hex): 02058d190004001a002d
	  Version: v1.0

	$ blocksec2go set_pin 1234
	  PUK to unlock card (hex): 5c88ce829a2ed32c

	$ blocksec2go generate_keypair
	  Key ID: 1

	$ blocksec2go get_key_info 1
	  Remaining signatures with card: 999990
      Remaining signatures with key 1: 100000
      Public key (hex, encoded according to SEC1): 0434cfd6b1bb53fc244d4881cf1f0d3b9aee7b6ac28aad8a1648fc514101961b59fa7fc58751d0dc876589e467a63ed1582e240cd18b98d408470679418a647833

	$ blocksec2go generate_signature --pin 1234 1 00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF
	  Remaining signatures with card: 999989
      Remaining signatures with key 1: 99999
      Signature (hex): 3044022049689b91545ba3bc487af7cb7267d19ea4ad8e2e8b093458e06d46837400444702207fe7cd2b6851049afe0f7c4ced0ef35bd9eb5d044c67ed95045b07a10641806c
      
	$ blocksec2go --security_level 3 --key_path keys.txt generate_signature 1 00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF
	  Channel opened...
	  Remaining signatures with card: 999971
	  Remaining signatures with key 1: 99971
	  Signature (hex): 3045022100c5b51835b25a3380a2ef3c5efc7045133a6d8e70e6c4180ff7d1e42a1e8ce74d0220743776ebb2e7dc4c48fe678df0fcc6e764bb7ae247139d2defe9aff21432d4c2

	$ blocksec2go get_key_label 11
	  Label for key ID 11:

	  b'This is my key!'

## Testing

To develop/test, it's best to use virtualenv. It allows for installing packages
in a "private" environment (for details see https://virtualenv.pypa.io/en/latest/)
(commands intended for Windows in bash, small differences for other OS/shell combinations)

    $ virtualenv venv
    $ source ./venv/Scripts/activate
    $ pip install --editable .

You can now test the library as if it would have been installed.
To exit the environment, simply run

    $ deactivate
