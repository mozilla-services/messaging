import nacl.utils
import nacl.secret

from nacl.hash import sha256
from nacl.signing import SigningKey
from nacl.public import PublicKey, PrivateKey, Box as PublicBox
from nacl.encoding import RawEncoder, Base64Encoder


class SignatureError(Exception):
    pass


def generate_keypair():
    private_key = PrivateKey.generate()
    public_key = private_key.public_key
    return private_key, public_key


def get_public_keys(identifier):
    """Returns a list of public keys for the given identifier.

    One identity can map to more than one device. Each device has only one
    public key.

    :param identifier: an email address or phone number.
    """
    return [generate_keypair()[1]]


def decrypt_message(encrypted_message, keying_material, private_key):
    encrypted_key = keying_material['encrypted_key']
    message_signature = keying_material['message_signature']
    temp_public_key = PublicKey(
        keying_material['temp_public_key'],
        Base64Encoder)

    box = PublicBox(private_key, temp_public_key)

    message_key = box.decrypt(
        encrypted_key,
        encoder=Base64Encoder)

    # We got the key, so let's get the message.
    message_box = nacl.secret.SecretBox(message_key)
    message = message_box.decrypt(
        encrypted_message,
        encoder=Base64Encoder)

    # Check the signature.
    mac_key = sha256(box._shared_key, RawEncoder)
    signing_key = SigningKey(mac_key)
    if signing_key.sign(message, Base64Encoder) != message_signature:
        raise SignatureError("The signature is not valid")

    return message


def encrypt_message(message, identifier):
    """Encrypts a message so that it can be read by all the devices of the
    given identifier.

    :param message: the message itself, in clear text.
    :param identifier: the identifier of the message recipient.
    """
    # Cipher the message with a brand new random key.
    message_key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
    message_box = nacl.secret.SecretBox(message_key)
    message_nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
    encrypted_message = message_box.encrypt(message, message_nonce,
                                            Base64Encoder)

    returned = []
    # Encrypt the message key with each recipient's public key.
    for recipient_device_pub_key in get_public_keys(identifier):

        # Generate a new keypair & cipher the key with it.
        temp_private_key, temp_public_key = generate_keypair()
        box = PublicBox(temp_private_key, recipient_device_pub_key)
        nonce = nacl.utils.random(PublicBox.NONCE_SIZE)
        encrypted_key = box.encrypt(message_key, nonce, Base64Encoder)

        # Sign the message.
        mac_key = sha256(box._shared_key, RawEncoder)
        signing_key = SigningKey(mac_key)
        message_sig = signing_key.sign(message, Base64Encoder)

        # Return the public key used to cipher the message key.
        returned.append({
            'encrypted_key': encrypted_key,
            'temp_public_key': temp_public_key.encode(Base64Encoder),
            'message_signature': message_sig
        })

    return {
        'encrypted_message': encrypted_message,
        'recipients': returned
    }
