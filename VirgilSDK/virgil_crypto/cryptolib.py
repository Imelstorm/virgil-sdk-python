# Copyright (C) 2016 Virgil Security Inc.
#
# Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#     (1) Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#
#     (2) Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#
#     (3) Neither the name of the copyright holder nor the names of its
#     contributors may be used to endorse or promote products derived from
#     this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

from VirgilSDK.virgil_crypto import virgil_crypto_python as crypto_helper
from VirgilSDK.helper import *


class CryptoWrapper:
    # Convert string to list of bytes
    # input - string to be converted into bytes
    @staticmethod
    def strtobytes(input):
        return list(bytearray(input, 'utf-8'))

    # PBKD function
    # value - string, value to encrypt
    # salt - string, value to add randomicity
    # algorithm - VirgilPBKDF.Hash class, hash algorithm
    # iterations - int, count of iterations
    @staticmethod
    def pbkdf(value, salt, algorithm=crypto_helper.VirgilPBKDF.Hash_SHA384, iterations=4096):
        salt_data = CryptoWrapper.strtobytes(salt)
        pbkdf = crypto_helper.VirgilPBKDF(salt_data, iterations)
        pbkdf.setHash(algorithm)
        value_data = CryptoWrapper.strtobytes(value)
        hash_value = pbkdf.derive(value_data)
        return base64.b64encode(bytearray(hash_value)).decode()

    # Generate key pair
    # type - crypto.VirgilKeyPair, type of generated key pair, example - 'crypto.VirgilKeyPair.Type_RSA_1024'
    # password - string, password for encryption of private key
    @staticmethod
    def generate_keys(type, password):
        kp = crypto_helper.VirgilKeyPair_generate(type, list(bytearray(password, 'utf-8')))
        private_key = bytearray(kp.privateKey())
        public_key = bytearray(kp.publicKey())
        key_pair = {'public_key': base64.b64encode(public_key).decode(), 'private_key': base64.b64encode(private_key).decode()}
        return key_pair

    # Sign data with private key
    # data - string, signed data
    # private_key - string, base64 encoded private key
    # password - string, password for decryption of private key
    @staticmethod
    def sign(data, private_key, password):
        signer = crypto_helper.VirgilSigner()
        try:
            return signer.sign(CryptoWrapper.strtobytes(data), CryptoWrapper.strtobytes(base64.b64decode(private_key).decode()),
                               CryptoWrapper.strtobytes(password))
        except UnicodeDecodeError:
            return signer.sign(CryptoWrapper.strtobytes(data), list(bytearray(base64.b64decode(private_key))),
                               CryptoWrapper.strtobytes(password))

    # Verify data's signature
    # data - string
    # sign - string, base64 encoded signature
    # public_key - string, base64 encoded public key
    @staticmethod
    def verify(data, sign, public_key):
        signer = crypto_helper.VirgilSigner()
        return signer.verify(CryptoWrapper.strtobytes(data), list(bytearray(base64.b64decode(sign))),
                             CryptoWrapper.strtobytes(base64.b64decode(public_key).decode()))

    # Encrypt data with recipient's public key
    # data - string, enrypted data
    # recipient_id - string, recipient's card id
    # public_key - string, base64 encoded recipient's public key
    @staticmethod
    def encrypt(data, recipient_id, public_key):
        cipher = crypto_helper.VirgilCipher()
        cipher.addKeyRecipient(CryptoWrapper.strtobytes(recipient_id),
                               CryptoWrapper.strtobytes(base64.b64decode(public_key).decode()))
        return cipher.encrypt(CryptoWrapper.strtobytes(data), True)

    # Decrypt data with recipient's private key
    # data - string, enrypted data
    # recipient_id - string, recipient's card id
    # private_key - string, base64 encoded recipient's private key
    # password - string, password to decrypt private key
    @staticmethod
    def decrypt(data, recipient_id, private_key, password):
        cipher = crypto_helper.VirgilCipher()
        return cipher.decryptWithKey(data, CryptoWrapper.strtobytes(recipient_id),
                                     CryptoWrapper.strtobytes(base64.b64decode(private_key).decode()),
                                     CryptoWrapper.strtobytes(password))

    # Decrypt data with secret password
    # data - string, base64 encoded encrypted data
    # password - string, password to decrypt data
    @staticmethod
    def decrypt_with_password(data, password):
        cipher = crypto_helper.VirgilCipher()
        try:
            return cipher.decryptWithPassword(CryptoWrapper.strtobytes(base64.b64decode(data).decode()), CryptoWrapper.strtobytes(password))
        except UnicodeDecodeError:
            return cipher.decryptWithPassword(list(bytearray(base64.b64decode(data))), CryptoWrapper.strtobytes(password))
    
    # Encrypt data with secret password
    # data - string, data to encrypt
    # password - string, password to encrypt data
    @staticmethod
    def encrypt_with_password(data, password):
        cipher = crypto_helper.VirgilCipher()
        cipher.addPasswordRecipient(CryptoWrapper.strtobytes(password))
        return cipher.encrypt(CryptoWrapper.strtobytes(data), True)
