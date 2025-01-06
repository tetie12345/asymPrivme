#! /usr/bin/env python

# Copyright 2024, 2025 Floris Tabak
#
# This file is part of PrivMe
# PrivMe is a free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public Licence as published by the
# Free Software Foundation, either version 3 of the License, or (at your
# option) any later version.
#
# PrivMe is distributed in the hope taht it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
# License for more details.
#
# You should have recieved a copy of the GNU General Public License
# along with PrivMe. If not, see <https://www.gnu.org/licenses/>.


from base64 import b64encode, b64decode
import datetime
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import PKCS1_OAEP, AES
from Cryptodome.Hash import SHA384, SHA512
import pickle


def generate_hash(data):
    data = bytes(data, 'utf-8')
    hashContainer = SHA512.SHA512Hash(data, '256')
    return hashContainer.hexdigest()


def generate_keys(length):
    if length < 1024:
        raise ValueError("RSA key length must be >= 1024")

    privateKey = RSA.generate(length)
    publicKey = privateKey.publickey()

    privateKey = privateKey.export_key().decode()
    publicKey = publicKey.export_key().decode()

    return privateKey, publicKey


def verify_key(key, keyType):
    if key is None:
        raise TypeError(f"No {keyType} key provided")

    if not isinstance(key, str):
        raise TypeError(f"Wrong {keyType} key provided. PEM encoded key should be passed, not bytes")

    if f"-----BEGIN {keyType} KEY-----\n" not in key:
        raise TypeError("Key does not look like a PEM encoded key")


def encrypt_message(message, publicKey):
    verify_key(publicKey, "PUBLIC")

    encryptedMsg = rsa_encrypt_message(message, publicKey)
    encryptedMsg = b64encode(encryptedMsg)

    return encryptedMsg


def rsa_encrypt_message(message, publicKey):
    publicKey = RSA.import_key(publicKey)
    rsaCipher = PKCS1_OAEP.new(key=publicKey, hashAlgo=SHA384)

    sessionKeySize = int(publicKey.size_in_bits() / 64)
    if sessionKeySize > 32: sessionKeySize = 32

    sessionKey = get_random_bytes(sessionKeySize)

    encSessionKey = rsaCipher.encrypt(sessionKey)
    encryptedMsg = aes_encrypt_message(message, sessionKey)

    return encSessionKey + encryptedMsg


def aes_encrypt_message(message, aesKey):
    try:
        nonce, tag, ciphertext = aes_encrypt(pickle.dumps(message), aesKey)

    except (TypeError, pickle.PicklingError, OverflowError):
        if isinstance(message, bytes):
            nonce, tag, ciphertext = aes_encrypt(message, aesKey)

        elif isinstance(message, str):
            nonce, tag, ciphertext = aes_encrypt(message.encode('utf-8'), aesKey)

        else:
            raise ValueError("Invalid data type for AES encryption")

    currentTime = datetime.datetime.now(datetime.timezone.utc).timestamp()
    currentTime = str(currentTime)
    # StringMagic(TM)
    currentTime = currentTime+(32-len(currentTime)%32)*chr(32-len(currentTime)%32)
    timestamp = currentTime.encode('utf-8')

    return nonce + tag + timestamp + ciphertext


def aes_encrypt(message, aesKey):
    if aesKey is not None:
        cipher = AES.new(aesKey, AES.MODE_EAX)

        aesKey = None
        del aesKey

    else:
        raise ValueError("No AES key provided")

    ciphertext, tag = cipher.encrypt_and_digest(message)
    return cipher.nonce, tag, ciphertext


def decrypt_message(message, privateKey):
    verify_key(privateKey, "RSA PRIVATE")

    decodedMsg = b64decode(message)

    decodedMsg = rsa_decrypt_message(decodedMsg, privateKey)

    return decodedMsg

def rsa_decrypt_message(message, privateKey):
    privateKey = RSA.import_key(privateKey)
    encryptedSessionKeySize = int(privateKey.size_in_bits() / 8)

    rsaCipher = PKCS1_OAEP.new(key=privateKey, hashAlgo=SHA384)
    privateKey = None
    del privateKey

    encryptedSessionKey, aesEncryptedMessage = (
            message[0:encryptedSessionKeySize],
            message[encryptedSessionKeySize:],
            )

    sessionKey = rsaCipher.decrypt(encryptedSessionKey)

    decryptedMessage = aes_decrypt_message(aesEncryptedMessage, sessionKey)

    return decryptedMessage


def aes_decrypt_message(message, aesKey):
    nonce, tag, timestamp, ciphertext = (
            message[0:16],
            message[16:32],
            message[32:64],
            message[64:],
            )

    sourceTimestamp = timestamp.decode('utf-8')
    sourceTimestamp = sourceTimestamp[0 : -ord(sourceTimestamp[-1])] # StringMagic(TM)
    sourceTimestamp = float(sourceTimestamp)
    sourceTimestamp = datetime.datetime.fromtimestamp(sourceTimestamp)

    data = aes_decrypt(aesKey, nonce, tag, ciphertext)
    aesKey = None
    del aesKey

    data = pickle.loads(data)

    return sourceTimestamp, data


def aes_decrypt(aesKey, nonce, tag, ciphertext):
    if aesKey == None:
        raise ValueError("No aes key provided")

    cipher = AES.new(aesKey, AES.MODE_EAX, nonce)
    aesKey = None
    del aesKey

    data = cipher.decrypt_and_verify(ciphertext, tag)
    return data
