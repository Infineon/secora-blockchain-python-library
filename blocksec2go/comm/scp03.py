import logging
import pickle
import os
import secrets

from binascii import unhexlify, hexlify
from struct import pack, unpack
from math import ceil

from blocksec2go.commands import initialize_update, external_authenticate
from Crypto.Hash import CMAC
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

logger = logging.getLogger(__name__)

SESSION_FILE = 'session'

SECLEVEL_NONE = 0x00
SECLEVEL_CMAC = 0x01
SECLEVEL_CENC = 0x03

MASK_CMAC = 0x01
MASK_CENC = 0x02

DERIV_CONST_CARD_CRYPTO = 0x00
DERIV_CONST_HOST_CRYPTO = 0x01
DERIV_CONST_CARD_CHALLENGE = 0x02
DERIV_CONST_S_ENC = 0x04
DERIV_CONST_S_MAC = 0x06
DERIV_CONST_S_RMAC = 0x07

INS_INIT_UPDATE = 0x50
INS_EXT_AUTH = 0x82
INS_SELECT_APP = 0xA4

class BorgSingelton:
    _shared_state = {}
    def __init__(self):
        self.__dict__ = self._shared_state

class SCP03_Session(BorgSingelton):
    session = {
        "active" : 0,
        "sec_level" : SECLEVEL_NONE
    }
    def __init__(self):
        BorgSingelton.__init__(self)

    def __str__(self): return self.val

    def openSession(self, sec_level=SECLEVEL_NONE):
        self.session["active"] = 1
        self.session["sec_level"] = sec_level
        logger.debug("Create session file")
        self.dumpSession()

    def getSession(self):
        if os.path.exists(SESSION_FILE):
            logger.debug("Session file exists")
            file = open(SESSION_FILE, 'rb')
            self.session = pickle.load(file)
            file.close()
        else:
            logger.debug("Session file doesn't exist")
        return self.session

    def dumpSession(self):
        file = open(SESSION_FILE, 'wb')
        pickle.dump(self.session, file)
        file.close()

    def setInactive(self):
        self.session["active"] = 0
        self.dumpSession()

class SCP03():
    def __init__(self):
        self.MAC_chaining_value = bytearray(bytes(16))
        scp03_session = SCP03_Session()

        #check if session is active
        session = scp03_session.getSession()
        if(session["active"] == 1):
            self.loadSession()
        else: #if not... default parameter
            logger.debug("No active session found -> default parameters")
            self.active = 0
            self.sec_level = SECLEVEL_NONE
            self.S_ENC = None
            self.S_MAC = None
            self.MAC_chaining_value = bytearray(bytes(16))
            self.enc_counter = 0

    def __del__(self):
        self.updateSession()

    def loadSession(self):
        session = SCP03_Session().getSession()
        self.active = session["active"]
        self.sec_level = session["sec_level"]
        self.S_ENC = session["S_ENC"]
        self.S_MAC = session["S_MAC"]
        self.MAC_chaining_value = session["MAC_chain"]
        self.enc_counter = session["ENC_counter"]
        return session

    def updateSession(self):
        session = SCP03_Session().session
        session["active"] = self.active
        session["sec_level"] = self.sec_level
        session["S_ENC"] = self.S_ENC
        session["S_MAC"] = self.S_MAC
        session["MAC_chain"] = self.MAC_chaining_value
        session["ENC_counter"] = self.enc_counter
        return session

    def mutualAuthenticate(self, reader, key_mac, key_enc, sec_level):
        host_challenge = secrets.randbits(8*8).to_bytes(length=8, byteorder='big') # 8 bytes
        #host_challenge = bytes([len(host_challenge)]) + host_challenge

        # send init update cmd
        (card_challenge, card_cryptogram) = initialize_update(reader, host_challenge)

        # derive keys...
        context = host_challenge + card_challenge
        self.S_ENC = KDF(key_enc, DERIV_CONST_S_ENC, 8 * len(key_enc), context)
        self.S_MAC = KDF(key_mac, DERIV_CONST_S_MAC, 8 * len(key_mac), context)
        card_cryptogram_calcd = KDF(self.S_MAC, DERIV_CONST_CARD_CRYPTO, 0x0040, context)

        if(card_cryptogram != card_cryptogram_calcd):
            raise RuntimeError("Wrong key!")

        host_cryptogram = KDF(self.S_MAC, DERIV_CONST_HOST_CRYPTO, 0x0040, context)

        self.MAC_chaining_value = bytearray(bytes(16))
        self.enc_counter = 0
        self.updateSession()
        SCP03_Session().openSession(sec_level)

        # send ext auth cmd
        external_authenticate(reader, sec_level, host_cryptogram)


    def wrapApdu(self, header, data):
        if(header[1] in [INS_SELECT_APP, INS_INIT_UPDATE]):
            logger.debug("initialize_update: No data wrapping.")
            return (header, data)

        if(self.sec_level not in [SECLEVEL_NONE, SECLEVEL_CMAC, SECLEVEL_CENC]):
            raise Exception("SECURITY LEVEL NOT SUPPORTED!")

        if (self.sec_level == SECLEVEL_NONE and header[1] != INS_EXT_AUTH):
            logger.debug("SECLEVEL_NONE: No data wrapping.")
            return (header, data)

        logger.debug("SCP03 wrap apdu. seclevel %s", self.sec_level)

        #set sec-channel in cla
        cla = header[0] | 0x04
        header = bytes([cla]) + header[1:]

        if (self.sec_level & MASK_CENC and self.active == 1
            and header[1] != INS_EXT_AUTH):
            logger.debug("SECLEVEL_CENC: data wrapping with encryption.")

            # get & increment encryption counter
            self.enc_counter += 1

            if(len(data) > 0):
                data = self.encrypt(self.S_ENC, data)
                logger.debug("encrypted data: " + str(hexlify(data)))
            else:
                logger.debug("No data to encrypt...")

        #add mac
        logger.debug("SECLEVEL_CMAC: data wrapping with CMAC.")
        mac = self.generateMAC(self.S_MAC, header, data)
        self.MAC_chaining_value = mac
        cmac = mac[:8]
        data = data + cmac

        #save session
        self.updateSession()
        SCP03_Session().dumpSession()

        return (header, data)

    def generateMAC(self, key, header, data):
        mac_data = self.MAC_chaining_value + header + bytes([len(data) + 8]) + data
        cobj = CMAC.new(key, ciphermod=AES)
        cobj.update(mac_data)
        mac = cobj.digest()
        logger.debug('mac: ' + str(hexlify(mac)))
        return mac

    def encrypt(self, key, data):
        # generate ICV
        padded_enc_cnt = self.enc_counter.to_bytes(16, 'big') # left pad with zeroes
        aes_enc = AES.new(key, AES.MODE_ECB)
        iv = aes_enc.encrypt(padded_enc_cnt)
        # encrypt data
        data_padded = pad(data, 16, style='iso7816')
        aes_enc = AES.new(key, AES.MODE_CBC, IV=iv)
        encrypted_data = aes_enc.encrypt(data_padded)
        return encrypted_data


def KDF(key, data_derivation_constant, output_len, context):
    """ Key derivation function according to NIST SP 800-18.

    Args:
        key:
        data_derivation_constant:   0x00: card-cryptogram
                                    0x01: host-cryptogram
                                    0x02: card-challenge generation
                                    0x04: derivation of S-ENC
                                    0x06: derivation of S-MAC
                                    0x07: derivation of S-RMAC
        output_len: length of output in bits (2^16 bits)
        context:

    Returns:

    Raises:
        Any exceptions thrown are passed through.
    """
    h = 128 # bits
    n = ceil(output_len / h)
    result = bytearray()
    for i in range(1, n + 1):
        fixed_input_data = bytes(11) + pack(">BBHB", data_derivation_constant, 0, output_len, i)
        fixed_input_data += context
        cobj = CMAC.new(key, ciphermod=AES)
        cobj.update(fixed_input_data)
        result += cobj.digest()
    return bytes(result[:(output_len // 8)]) # leftmost L bits
