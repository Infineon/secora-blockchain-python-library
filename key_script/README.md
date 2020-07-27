# SCP key exchange

SECORA<sup>TM</sup> Blockchain comes with an basic SCP03 keys (MAC&ENC) which can be exchanged when needed. The following pyhton script allows the change of keys from a text file.

## Usage
To change the keys for SCP03, run the following command:

    python put_key.py <path to key-enc key file> <path to current key file> <path to new key file>
 
Where the current and old key file should be of the following format:

    {
    "key_mac" : "<MAC key in hex format>",
    "key_enc" : "<ENC key in hex format>"
    }

The key "key_enc_key" is the key which is used to encrypt the key which will be sent with the PUT KEY command. The key-enc key is usually the same as the Data Encryption Key (Key-DEK). 

The key-enc key file should be of the following format:

    {
    "key_enc_key" : "<your DEK key in hex format>"
    }


