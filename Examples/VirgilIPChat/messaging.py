import os
import datetime
import time
import binascii
from chat import Chat
import config
from VirgilSDK import virgilhub, helper
import VirgilSDK.virgil_crypto.cryptolib as cryptolib
from ConfigParser import ConfigParser


# Encrypt json serialized data using recipient public key downloaded from
# virgil key service
def encrypt_message(json_data, recipients):
    cipher = cryptolib.crypto_helper.VirgilCipher()
    for recipient in recipients:
        print("Recipient: ", helper.Helper.json_dumps(recipient))
        recipient_id = cryptolib.CryptoWrapper.strtobytes(recipient['id'])
        recipient_pubkey = cryptolib.CryptoWrapper.strtobytes(
            cryptolib.base64.b64decode(recipient['public_key']['public_key']).decode())
        cipher.addKeyRecipient(recipient_id, recipient_pubkey)
    return cipher.encrypt(cryptolib.CryptoWrapper.strtobytes(json_data), True)


# Initialization virgil application
def virgil_init(token, ident_link, virgil_card_link, private_key_link):
    virgil_hub = virgilhub.VirgilHub(token, ident_link, virgil_card_link, private_key_link)
    return virgil_hub


# Sign message using sender's private key 'prkey' and private key password 'passw'
def sign_message(message, prkey, passw):
    return cryptolib.CryptoWrapper.sign(message, prkey, passw)


# Decrypt received message 'encrypted' using private key 'prkey' and key password 'passw'
def decrypt_message(encrypted, card_id, prkey, passw):
    # msg = helper.base64.b64decode(encrypted)
    msg = helper.base64.b64decode(encrypted.decode())
    decrypted = cryptolib.CryptoWrapper.decrypt(bytearray(msg), card_id, prkey, passw)
    json_data = helper.Helper.json_loads(str(bytearray(decrypted)))
    return json_data


# Verify signature in json serialized data 'json_data' using sender identity 'sender'
def verify_signature(json_data, sender):
    card = virgil_hub.virgilcard.search_app(sender)[0]
    card_key = card['public_key']['public_key']
    is_signed = cryptolib.CryptoWrapper.verify(json_data['message'], json_data['signature'], card_key)
    if not is_signed:
        raise ValueError('Signature is invalid!')


# Sending signed and encrypted message to the chat room
def send_message(my_chat, message, recipient, prkey, passw, sender):
    sign = sign_message(message, prkey, passw)
    data = {'message': message,
            'signature': helper.base64.b64encode(str(bytearray(sign))),
            'sender': sender}
    json_data = helper.Helper.json_dumps(data)
    encrypted = encrypt_message(json_data, recipient)
    my_chat.post_message(encrypted)


# get last messages from chat
# my_chat - chat room
# last_message_id - last received message
# prkey - private key using for decryption
# passw - private key's password
# card_id - server's virgil card id
def get_messages(my_chat, card_id, private_key, private_key_password):
    messages = my_chat.get_messages(None)
    decrypted_msgs = []
    for message in messages:
        try:
            json_data = decrypt_message(message['message'], card_id, private_key, private_key_password)
        except Exception as e:
            print("Exception: ", e)
            if 'sender_identifier' in message.keys():
                decrypted_msgs.append("{} : Message cannot be decrypted".format(
                    message['sender_identifier']))
            continue
        verify_signature(json_data, json_data['sender'])
        decrypted_msgs.append(json_data['message'])
    return decrypted_msgs


def get_members_public_keys():
    members = simple_chat.channel_members()

    found_cards = []
    for member in members:
        if 'identifier' in member.keys():
            card_list = virgil_hub.virgilcard.search_card(member['identifier'], include_unauthorized=True)

            if card_list:
                found_cards.append(card_list[-1])
            else:
                print(member['identifier'])
    return found_cards


def load_virgil_pass(virgil_key_path):
    if os.path.exists(virgil_key_path):
        return helper.Helper.json_loads(open(virgil_key_path, 'r').read())


def save_virgil_pass(virgil_key_path, virgil_key):
    dir_name = os.path.dirname(virgil_key_path)[0]
    if not os.path.exists(dir_name):
        os.mkdir(os.path.dirname(virgil_key_path))
    open(virgil_key_path, 'w').write(helper.Helper.json_dumps(virgil_key))


if __name__ == '__main__':
    print("Initializing...")
    virgil_key_path = os.path.join(os.environ['HOME'], '.virgil', 'user.virgilpass')
    virgil_hub = virgil_init(config.virgil_access_token,
                             config.virgil_identity_service_url,
                             config.virgil_keys_service_url,
                             config.virgil_private_keys_service_url)

    sender_pass = load_virgil_pass(virgil_key_path)

    if not sender_pass:
        sender_pass = cryptolib.CryptoWrapper.generate_keys(
            cryptolib.crypto_helper.VirgilKeyPair.Type_EC_Curve25519, config.user_key_password)

        sender_card = virgil_hub.virgilcard.create_card('email',
                                                        'Anotherpeople@mailinator.com',
                                                        None,
                                                        None,
                                                        sender_pass['private_key'],
                                                        config.user_key_password,
                                                        sender_pass['public_key'])
        sender_pass['card_id'] = sender_card['id']
        sender_pass['identity'] = sender_card['identity']['value']
        sender_pass['identity_type'] = sender_card['identity']['type']
        save_virgil_pass(virgil_key_path, sender_pass)

    simple_chat = Chat('http://198.211.127.242:4000', 'WOW', sender_pass['identity'])

    print("Initialization has been successfully completed")
    messages = get_messages(simple_chat, sender_pass['card_id'], sender_pass['private_key'], config.user_key_password)
    print("Messages({}):\n".format(len(messages)))
    for msg in messages:
        print(msg)

    message = raw_input("Input you message here:\n")
    members_cards = get_members_public_keys()
    encrypted_message = encrypt_message(message, members_cards)
    signature = sign_message(str(encrypt_message), sender_pass['private_key'], config.user_key_password)
    encrypted_model = {
        'message': helper.base64.b64encode(str(encrypted_message)),
        'sign': helper.base64.b64encode(str(signature))
    }
    print("Encrypt model: ", helper.Helper.json_dumps(encrypted_model))
    simple_chat.post_message(encrypted_model)

    # mid = get_messages(my_chat, 0, sender_keys['private_key'], None, None)