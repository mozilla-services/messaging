from unittest import TestCase
import mock
import re

from fxchat.crypto import encrypt_message, decrypt_message, generate_keypair

VALID_B64_CHARS = re.compile(r'^[a-zA-Z0-9\+/]+={0,3}$')


class TestCrypto(TestCase):

    def assertBase64(self, value, key=None):
        msg = ""
        if key:
            msg += "'%s': " % key
        try:
            matches = VALID_B64_CHARS.match(value)
        except TypeError:
            self.fail(msg + "expected to get a string, got %s" % type(value))
            return

        if not matches:
            self.fail(msg + "%r is not a base64-encoded value" % value)

    def test_encrypt_message_b64_encodes_values(self):
        keypair = generate_keypair()

        def _get_public_keys(identifier):
            return [keypair[1]]

        with mock.patch('fxchat.crypto.get_public_keys', _get_public_keys):
            returned = encrypt_message('super secret stuff', 'alexis')
            self.assertBase64(returned['encrypted_message'])

            self.assertEquals(len(returned['recipients']), 1)

            # Check all the values are base64-encoded.
            recipient_data = returned['recipients'][0]
            for key, value in recipient_data.items():
                self.assertBase64(value, key)

    def test_decrypt_an_encrypted_message(self):
        private_key, public_key = generate_keypair()

        def _get_public_keys(identifier):
            return [public_key]

        with mock.patch('fxchat.crypto.get_public_keys', _get_public_keys):
            secret_message = 'super secret stuff'
            returned = encrypt_message(secret_message, 'alexis')
            encrypted_message = returned['encrypted_message']
            message = decrypt_message(
                encrypted_message,
                returned['recipients'][0],
                private_key)
            self.assertEquals(message, secret_message)

    def test_encrypt_message_fails_if_no_recipient_pubkey_found(self):
        pass
