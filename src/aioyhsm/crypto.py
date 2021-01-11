from __future__ import annotations

from enum import IntEnum
from struct import pack
from typing import AnyStr, ByteString

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.algorithms import AES as AesKey
from cryptography.hazmat.primitives.cmac import CMAC
from cryptography.hazmat.primitives.constant_time import bytes_eq
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class DerivationConstant(IntEnum):
    CardCryptogram = 0x00
    HostCryptogram = 0x01
    CardChallenge = 0x02
    S_ENC = 0x04
    S_MAC = 0x06
    S_RMAC = 0x07


def compute_cmac(aes_key: AesKey, data0: ByteString, data1: ByteString) -> bytes:
    cmac = CMAC(aes_key)
    cmac.update(data0)
    cmac.update(data1)
    return cmac.finalize()


def derive_scp03(
    key: AesKey,
    constant: DerivationConstant,
    length: int,
    context: ByteString,
    counter: int = 1,
) -> bytes:
    return compute_cmac(key, pack(">11xBxHB", constant, length * 8, counter), context)[:length]


def derive_password(password: AnyStr) -> Tuple[bytes, bytes]:
    """
    Args:
        password: Password

    Returns:
        Encryption key, Mac key
    """

    if isinstance(password, str):
        password = password.encode()

    tmp = PBKDF2HMAC(hashes.SHA256(), 32, b"Yubico", 10000).derive(password)
    return tmp[:16], tmp[16:]


class SessionKeys:
    def __init__(
        self,
        enc_key: ByteString,
        mac_key: ByteString,
        host_challenge: ByteString,
        card_challenge: ByteString,
    ) -> None:
        enc_aes = AesKey(enc_key)
        mac_aes = AesKey(mac_key)

        context = host_challenge + card_challenge
        self._cipher_enc = Cipher(
            AesKey(derive_scp03(enc_aes, DerivationConstant.S_ENC, 16, context)),
            modes.CBC(bytes(16)),
        )
        self._mac_key = AesKey(derive_scp03(mac_aes, DerivationConstant.S_MAC, 16, context))
        self._rmac_key = AesKey(derive_scp03(mac_aes, DerivationConstant.S_RMAC, 16, context))
        self.card_cryptogram = derive_scp03(
            self._mac_key, DerivationConstant.CardCryptogram, 8, context
        )
        self.host_cryptogram = derive_scp03(
            self._mac_key, DerivationConstant.HostCryptogram, 8, context
        )

        self._mac = bytes(16)
        self._ctr = 1

    def calc_host_mac(self, data: ByteString) -> bytes:
        self._mac = compute_cmac(self._mac_key, self._mac, data)
        return self._mac[:8]

    # XXX race condition if multiple requests in parallel?
    # calc_host_mac-0, send-http-0
    # calc_host_mac-1, send-http-1
    # recv-http-0
    # calc_card_mac-0 -> boom
    def calc_card_mac(self, data: ByteString) -> bytes:
        return compute_cmac(self._rmac_key, self._mac, data)[:8]

    def encrypt(self, data: ByteString) -> Tuple[bytearray, bytearray]:
        encryptor = self._cipher_enc.encryptor()
        encrypted = bytearray()

        # Encrypt IV
        encrypted.extend(encryptor.update(self._ctr.to_bytes(16, "big")))

        # Encrypt main data
        encrypted.extend(encryptor.update(data))

        # Encrypt padding
        encrypted.extend(encryptor.update(b"\x80" + bytes(15 - len(data) % 16)))

        encrypted.extend(encryptor.finalize())
        iv = encrypted[:16]
        del encrypted[:16]
        self._ctr += 1
        return iv, encrypted

    def decrypt(self, iv: ByteString, data: ByteString) -> bytes:
        decryptor = self._cipher_enc.decryptor()
        decrypted = bytearray()
        decrypted.extend(decryptor.update(iv))
        decrypted.extend(decryptor.update(data))
        decrypted.extend(decryptor.finalize())

        # Remove decrypted IV
        del decrypted[:16]

        pad_idx = decrypted.rindex(0x80)
        if any(decrypted[pad_idx + 1 :]):
            raise Exception("Bad padding")
        del decrypted[pad_idx:]
        return decrypted
