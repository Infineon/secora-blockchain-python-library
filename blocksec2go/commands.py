from struct import pack
from binascii import hexlify
import logging


logger = logging.getLogger(__name__)

DATA_LEN_1 = 0x7F
DATA_LEN_2 = 0xFF
DATA_LEN_3 = 0x400
MAX_CMD_DATA_LEN = 0xFF
PADDING_LEN = 0x10

def select_app(reader):
    """ Sends command to select the Blockchain Security2GO application

    Needs to be called after reset to allow for access to
    blockchain commands.

    Returns:
        :obj:`tuple`: (pin_active, card_id, version).

        pin_active:
            bool: True if PIN is set on the card

        card_id:
            bytes: 10 byte unique card identifier

        version:
            str: card firmware version, following
            semantic versioning.

    Raises:
        CardError: If card indicates a failure.

        Any exceptions thrown by the reader wrapper are passed through.
    """
    logger.debug('SELECT Blockchain Security 2Go starter kit')
    aid = bytes.fromhex('D2760000041502000100000001')
    r = reader.transceive(b'\x00\xA4\x04\x00', aid, le=0x12).check()

    pin_active = True if r.resp[0] == 1 else False
    card_id = r.resp[1:11]
    version = r.resp[11:].decode('ASCII')
    return (pin_active, card_id, version)

def generate_keypair(reader):
    """ Sends command to generate new keypair

    A new keypair is generated and stored. The ID identifying this
    keypair is returned. A key using the `secp256k1`_ curve is generated.

    Args:
        reader (:obj:): object providing reader communication

    Returns:
        int: ID of the just generated keypair, to be used e.g. for
        future signatures using ``generate_signature``

    Raises:
        CardError: If card indicates a failure, e.g. if card is full.

        Any exceptions thrown by the reader wrapper are passed through.

    .. _secp256k1:
        http://www.secg.org/sec2-v2.pdf
    """
    logger.debug('GENERATE KEYPAIR')
    r = reader.transceive(b'\x00\x02\x00\x00', le=0x01).check()

    key_id = int(r.resp[0])
    logger.debug('generated key %d', key_id)
    return key_id

def get_key_info(reader, key_id):
    """ Sends command to retrieve keypair information

    Args:
        reader (:obj:): object providing reader communication
        key_id (int): key ID as returned by ``generate_keypair``

    Returns:
        :obj:`tuple`: (global_counter, counter, key)

        global_counter:
            int: overall remaining signatures for this card

        counter:
            int: signatures remaining with key ``key_id``

        key:
            bytes: public key, encoded uncompressed as
            point according to `SEC1`_

        Uncompressed SEC1 encoding in short means that the key is
        encoded to a 65 byte string. It consists of a 1 byte prefix
        followed by the coordinates (first x then y) with a constant
        length of 32 byte each.
        The prefix is always 0x04, both coordinates are encoded as
        unsigned integers, MSB first (big endian).

    Raises:
        CardError: If card indicates a failure, e.g. if ID is invalid.

        Any exceptions thrown by the reader wrapper are passed through.

    .. _SEC1:
        http://www.secg.org/sec1-v2.pdf
    """
    logger.debug('GET KEY INFO key %d', key_id)
    if key_id < 0 or key_id > 255:
        raise RuntimeError('Invalid key_id: ' + str(key_id))

    header = '0016{:02x}00'.format(key_id)
    r = reader.transceive(bytes.fromhex(header), le=0).check()

    global_counter = int.from_bytes(r.resp[0:4], byteorder='big')
    counter = int.from_bytes(r.resp[4:8], byteorder='big')
    key = r.resp[8:]
    logger.debug('global count %d, count %d, public key %s', global_counter, counter, key.hex())
    return (global_counter, counter, key)

def generate_signature(reader, key_id, hash):
    """ Send command to calculate signature

    Signs a given hash using the specified key. The signature is
    done using the sec256k1 curve, and DER encoded.
    The returned signature is canonical, as described in `BIP 62`_.
    Hashing needs to be done on the PC/terminal side, the card expects
    already hashed data.

    If a PIN is enabled on the card, a PIN session must be in
    progress to use ``encrypted_keyimport``. See ``verify_pin``
    for more information.

    Args:
        reader (:obj:): object providing reader communication
        key_id (int): key ID as returned by ``generate_keypair``
        hash (bytes): 32 byte long hash to sign

    Returns:
        :obj:`tuple`: (global_counter, counter, signature)

        global_counter:
            int: overall remaining signatures for this card

        counter:
            int: signatures remaining with key ``key_id``

        signature:
            bytes: DER encoded signature

    Raises:
        CardError: If card indicates a failure, e.g. if ID is invalid.

        Any exceptions thrown by the reader wrapper are passed through.

    .. _BIP 62:
        https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki
    """
    logger.debug('GENERATE SIGNATURE key %d hash %s', key_id, hash.hex())
    if key_id < 0 or key_id > 255:
        raise RuntimeError('Invalid key_id: ' + str(key_id))
    if len(hash) != 32:
        raise RuntimeError('Invalid hash length')

    header = '0018{:02x}00'.format(key_id)
    r = reader.transceive(bytes.fromhex(header), hash, le=0).check()

    global_counter = int.from_bytes(r.resp[0:4], byteorder='big')
    counter = int.from_bytes(r.resp[4:8], byteorder='big')
    signature = r.resp[8:]
    logger.debug('global count %d, count %d, signature %s', global_counter, counter, signature.hex())
    return (global_counter, counter, signature)

def encrypted_keyimport(reader, seed):
    """ Sends command to derive key from given seed

    The card will reproducibly generate a key from the
    given seed. This allows the user to backup the seed
    and provides a fallback in case of running our of
    signatures or destruction of the card.
    The key is generated using key derivation as defined
    in `NIST SP 800-108`_ using CMAC-AES256 as defined in
    `NIST SP 800-38B`_.

    If a PIN is enabled on the card, a PIN session must be in
    progress to use ``encrypted_keyimport``. See ``verify_pin``
    for more information.

    Args:
        reader (:obj:): object providing reader communication
        seed (bytes): 16 byte seed to use for key generation

    Raises:
        CardError: If card indicates a failure, e.g. for invalid seed length.

        Any exceptions thrown by the reader wrapper are passed through.

    .. _NIST SP 800-108:
        https://csrc.nist.gov/publications/detail/sp/800-108/final
    .. _NIST SP 800-38B:
        https://csrc.nist.gov/publications/detail/sp/800-38b/final
    """
    logger.debug('GENERATE KEY FROM SEED seed %s', seed.hex())
    if len(seed) != 16:
        raise RuntimeError('Invalid seed length')

    reader.transceive(b'\x00\x20\x00\x00', seed).check()
    logger.debug('success')

def set_pin(reader, pin):
    """ Send command to set a PIN

    Sets a PIN as long as there is no PIN enabled currently.
    Returns the PUK that is needed in the case of lockout
    because of too many incorrect PIN entries.

    Args:
        reader (:obj:): object providing reader communication
        pin (str): PIN to be used, will be used UTF-8 encoded

    Returns:
        bytes: PUK value needed for unlock

    Raises:
        CardError: If card indicates a failure, e.g. if there is alredy a PIN set.

        Any exceptions thrown by the reader wrapper are passed through.
    """
    logger.debug('SET PIN pin %s', pin)
    r = reader.transceive(b'\x00\x40\x00\x00', pin.encode(), le=0x08).check()

    logger.debug('new puk %s', r.resp.hex())
    return r.resp

def change_pin(reader, current_pin, new_pin):
    """ Send command to modify existing PIN

    Changes the PIN if a PIN is currently enabled.
    Returns a new PUK that is needed in the case of lockout
    because of too many incorrect PIN entries.

    Args:
        reader (:obj:): object providing reader communication
        current_pin (str): current PIN, will be used UTF-8 encoded
        new_pin (str): new PIN to set, will be used UTF-8 encoded

    Returns:
        bytes: PUK value needed for unlock

    Raises:
        CardError: If card indicates a failure, e.g. if too many incorrect
        PUK entry tries alrady occured and card is locked permanently.

        Any exceptions thrown by the reader wrapper are passed through.
    """
    logger.debug('CHANGE PIN from %s to %s', current_pin, new_pin)
    if len(current_pin.encode()) > 255:
        raise RuntimeError('Invalid length for current PIN')
    if len(new_pin.encode()) > 255:
        raise RuntimeError('Invalid length for new PIN')

    data = bytes([len(current_pin)]) + current_pin.encode()
    data += bytes([len(new_pin)]) + new_pin.encode()

    r = reader.transceive(b'\x00\x42\x00\x00', data, le=0x08).check()
    logger.debug('new puk %s', r.resp.hex())
    return r.resp

def verify_pin(reader, pin):
    """ Sends command to verify PIN and unlock commands

    If the provided PIN is correct, this starts a PIN
    session. An ongoing PIN session allows to use protected
    commands until the next reset/select command (``select_app``).

    Args:
        reader (:obj:): object providing reader communication
        pin (str)

    Returns:

    Raises:
        CardError: If card indicates a failure, e.g. if too many incorrect
        PIN entry tries alrady occured and card is locked.

        Any exceptions thrown by the reader wrapper are passed through.
    """
    # TODO fix interface, do not return bool or int depening on success/failure
    logger.debug('VERIFY PIN pin %s', pin)
    r = reader.transceive(b'\x00\x44\x00\x00', pin.encode()).check()

    if r.sw == 0x9000:
        logger.debug('success')
        return True
    if r.sw == 0x6983:
        logger.debug('failed - PIN locked')
        return 0
    if (r.sw & 0xFFF0) == 0x63C0:
        logger.debug('failed, %d tries remaining', r.sw & 0xF)
        return r.sw & 0xF
    r.check()

def unlock_pin(reader, puk):
    """ Send command to unlock PIN using PUK

    If too many incorrect PIN entries occured and the card is locked
    it can be unlocked using the PUK returned while setting the PIN.

    Args:
        reader (:obj:): object providing reader communication
        pin (bytes): as returned from ``set_pin`` or ``change_pin``

    Returns:
        ...

    Raises:
        CardError: If card indicates a failure, e.g. if too many incorrect
        PIN entry tries alrady occured and card is locked.

        Any exceptions thrown by the reader wrapper are passed through.
    """
    # TODO fix interface, do not return bool or int depening on success/failure
    logger.debug('UNLOCK PIN puk %s', puk.hex())
    r = reader.transceive(b'\x00\x46\x00\x00', puk).check()

    if r.sw == 0x9000:
        logger.debug('success')
        return True
    if r.sw == 0x6983:
        logger.debug('failed - card locked')
        return 0
    if (r.sw & 0xFFF0) == 0x63C0:
        logger.debug('failed, %d tries remaining', r.sw & 0xF)
        return r.sw & 0xF
    r.check()

def create_key_label(reader, key_id: int, storage_size: int):
    """ Allocates storage of given size (between 01H to 400H) in persistent
    memory to store metadata for a given Key handle.

    Args:
        reader (:obj:): object providing reader communication
        key_id (int): key index
        storage_size (bytes): 0x01 to 0x400

    Returns:
        bool:   true: storage allocation successfull
                false: storage already allocated

    Raises:
        CardError: If card indicates a failure, e.g. if card is full.

        Any exceptions thrown by the reader wrapper are passed through.
    """
    logger.debug('CREATE KEY LABEL key_id %s size %s', key_id, storage_size)
    data = storage_size.to_bytes(2, 'big')
    header = b'\x00\x1D' + bytes([key_id]) + b'\x00'
    r = reader.transceive(header, data, le=0)
    if(r.sw == 0x6A88):
        raise Exception('0x6A88 Key slot for the given index is not available')
    elif(r.sw == 0x6A80):
        raise Exception('0x6A80 Incorrect values in command data')
    elif(r.sw == 0x6985):
        return False
    else:
        r.check()

    return True

def update_key_label(reader, key_id: int, label):
    """ Sets or Resets the metadata of a given Key handle.

    Args:
        reader (:obj:): object providing reader communication
        key_id (int): key index
        occurence (): 0 Get first or all occurrence(s)
                      1 Get next occurrence(s)
    Returns:
        label: Key Label associated with the given Key Index
    Raises:
        CardError: If card indicates a failure, e.g. if card is full.

        Any exceptions thrown by the reader wrapper are passed through.
    """
    logger.debug('UPDATE KEY LABEL key_id %s label %s', key_id, label)
    len_label = len(label)
    logger.debug('len_label %s', len_label)

    len_label += 1 # 1 byte key id
    logger.debug('len_label %s', len_label)
    len_indicator = None
    if(len_label <= int(DATA_LEN_1)):
        len_indicator = bytes([len_label])
    elif(len_label <= DATA_LEN_2):
        len_indicator = b'\x81' + bytes([len_label])
    elif(len_label <= DATA_LEN_3):
        len_indicator = b'\x82' + len_label.to_bytes(2, 'big')
    else:
        raise Exception("Key label too long! Should be less or equal to 1024 bytes!")
    logger.debug('len_indicator: ' + str(hexlify(len_indicator)))

    max_data_len = MAX_CMD_DATA_LEN - PADDING_LEN
    data = b'\xDF\x1F' + len_indicator + bytes([key_id]) + label.encode()
    len_command_data = len(data)
    logger.debug('len command data %s', len_command_data)
    if(len_command_data == max_data_len):
        rounds = 1
    else:
        rounds = int(len_command_data / max_data_len) + 1
    logger.debug('rounds: ' + str(rounds))

    for i in range(0, rounds):
        logger.debug('round %s', i)
        offset = i * max_data_len
        data_to_send = data[offset:(offset + max_data_len)]
        logger.debug('to index ' + str((offset + max_data_len)))

        header = b'\x00\x1E' + (b'\x80' if i == (rounds - 1) else b'\x00') +\
           bytes([i])
        logger.debug('header ' + str(hexlify(header)))
        logger.debug('data_to_send ' + str((data_to_send)))
        logger.debug('len(data_to_send) ' + str(len(data_to_send)))

        r = reader.transceive(header, data_to_send, le=0)
        if(r.sw == 0x6384):
            raise Exception('0x6384 Not enough persistent memory available!')
        elif(r.sw == 0x6A88):
            raise Exception('0x6A88 Key slot for the given index is not available')
        elif(r.sw == 0x6A80):
            raise Exception('0x6A80 Incorrect values in command data')
        elif(r.sw == 0x6985):
            raise Exception('0x6985 Memory not allocated for Key Label Data')
        else:
            r.check()

def get_key_label(reader, key_id: int):
    """ Returns the metadata of a given Key handle.

    Args:
        reader (:obj:): object providing reader communication
        key_id (int): key index
        occurence (): 0 Get first or all occurrence(s)
                      1 Get next occurrence(s)
    Returns:
        label: Key Label associated with the given Key Index
    Raises:
        CardError: If card indicates a failure, e.g. if card is full.

        Any exceptions thrown by the reader wrapper are passed through.
    """
    logger.debug('GET KEY LABEL key_id %s', key_id)
    header = b'\x00\x1F' + bytes([key_id]) + b'\x00' # first occurence
    received = b''

    r = reader.transceive(header, le=0)
    tag = r.resp[:2]
    received = r.resp

    len_label = 0
    if(r.resp[2] == 0x81):
        len_label = r.resp[3]
    elif(r.resp[2] == 0x82):
        len_label = int.from_bytes(r.resp[3:5], byteorder='big', signed=False)
    else:
        len_label = r.resp[2]
    logger.debug('len_label %s', len_label)

    while(r.sw == 0x6310):
        header = b'\x00\x1F' + bytes([key_id]) + b'\x01' # next occurence
        r = reader.transceive(header, le=0)
        received += r.resp
        if(r.sw == 0x6A88):
            raise Exception('0x6A88 Key slot for the given index is not available')
        elif(r.sw != 0x6310):
            r.check()

    logger.debug('data received ' + str(hexlify(received)))

    if(len_label == 0):
        label = None
    else:
        label = received[-len_label:]

    return (tag, label)


def initialize_update(reader, host_challenge):
    """ Initaites a SCP ‘03’ session.

    Args:
        reader (:obj:): object providing reader communication
        host_challenge (str):

    Returns:
        :obj:`tuple`: (card_challenge, card_cryptogram)
    Raises:
        CardError: If card indicates a failure, e.g. if card is full.

        Any exceptions thrown by the reader wrapper are passed through.
    """
    logger.debug('INITIALIZE UPDATE')

    data = host_challenge
    r = reader.transceive(b'\x80\x50\x00\x00', data, le=0).check()

    key_diversification_data = r.resp[0:10]
    key_info = r.resp[10:13]
    card_challenge = r.resp[13:21]
    card_cryptogram = r.resp[21:29]
    sequence_counter = r.resp[29:]

    return (card_challenge, card_cryptogram)

def external_authenticate(reader, security_level, host_cryptogram):
    """ Authenticates the host and sets the security level for subsequent commands.

    Args:
        reader (:obj:): object providing reader communication
        security_level (str):   SCP03 Section 7.1.2.1
                                01 H – C-MAC
                                03 H – DECRYPTION and C-MAC
                                00 H – no secure messaging expected
    Returns:

    Raises:
        CardError: If card indicates a failure, e.g. if card is full.

        Any exceptions thrown by the reader wrapper are passed through.
    """
    logger.debug('EXTERNAL AUTHENTICATE')
    logger.debug('Security level: ' + str(security_level))

    assert(security_level != b'\x01' and security_level != b'\x03' and
           security_level != b'\x00')
    header = pack("BBBB", 0x84, 0x82, security_level, 0x00)
    data = host_cryptogram

    logger.debug('header ' + str(hexlify(header)))
    logger.debug('data ' + str(hexlify(data)))

    r = reader.transceive(header, data, le=0).check()
    logger.debug('response ' + str(r))

def get_status(reader):
    """ Retrives application status information according to the given tag..

    Args:
        reader (:obj:): object providing reader communication

    Returns:
        bytes: mode of protection (0x00: unprotected, 0x01: protected)
    Raises:
        CardError: If card indicates a failure, e.g. if card is full.

        Any exceptions thrown by the reader wrapper are passed through.
    """
    logger.debug('GET STATUS')

    r = reader.transceive(b'\x00\xB0\xDF\x20', le=0).check()
    return r.resp


def enable_protected_mode(reader):
    """ Irreversibly enables Protected Mode configuration.

    Args:
        reader (:obj:): object providing reader communication

    Returns:

    Raises:
        CardError: If card indicates a failure, e.g. if card is full.

        Any exceptions thrown by the reader wrapper are passed through.
    """
    logger.debug('ENABLE PROTECTED MODE')

    r = reader.transceive(b'\x00\xD0\x00\x00')
    logger.debug('response ' + str(r.resp))
    r.check()
