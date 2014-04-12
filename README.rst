FxChat-Server
#############

Definition of the service is still in flux, read the wiki here:
https://wiki.mozilla.org/CloudServices/FxChat

Tentative flow:
===============

(We assume that a keypair for each device had been generated and that the
public keypair had been uploaded to the server)

Sending messages
----------------

Overview: Each message is encrypted with an AES key and this key is sent
encrypted to the recipients.

- 1. For each message M, generate an AES Key;
- 2. For each recipient device, do the following:

    - a. ``temp_priv_key, temp_pub_key = new Keypair()``
    - b. ``shared_secret = Diffie(recipent_device_pub_key, temp_priv_key)``
    - c. derive ``encryption key`` and ``mac key`` from the ``shared_secret``

         ``encryption_key = hash(shared_secret)``

         ``mac_key = hash(encryption_key)``
    - d. encrypted_message = encrypt(M, aes_key)
    - e. 
        ::

            recipients = [{encrypted_aes_key: encrypt(aes_key, encryption_key),
                          msg_sig: sign(M, mac_key),
                          msg_pub_key: temp_pub_key}]


Receiving messages
------------------

We received the following info:
  * encrypted_message;
  * encrypted_aes_key;
  * msg_sig;
  * msg_pub_key.

We already know our private key (recipient_private_key).

Goal is to get back the AES key to decrypt the message.

1. Get back the keying material.

   shared_secret = Diffie(recipient_private_key, msg_pub_key)
   encryption_key = hash(shared_secret)
   signing_key = hash(encryption_key)

2. Decrypt the AES key.

   aes_key = decrypt(encrypted_aes_key, encryption_key)

3. Get the message.

   message = decrypt(AES, encrypted_message)

4. Verify the message is valid.

   sig = sign(message, signing_key)
   sig === msg_sig


FAQ
===

What do we want to store on the server for the user?
----------------------------------------------------

The server is storing:

- public keys for all the device of the system;
- encrypted messages in a queue until they're actually retrieved;

Do we want to store messages on the server, and for how long?
-------------------------------------------------------------

We are storing all the messages on a queue on the server for some time, and
then we store them for some more time.

What is the maximum delay before a message got lost?
----------------------------------------------------

We keep messages from some time, until 

Are we providing forward security?
----------------------------------

We currently aren't. If an attacker breaks one device private key, she might be
able to read all the messages stored on the device and / or stored on the
server.

Plans are being discussed to address that, using a ratchet and defining a new
private / public key, but we're not there yet.

Are we providing deniable auth?
-------------------------------

When a client receives a message, it discloses the signature key when ACKing
the message, so that anyone could have signed this message, not just the real
person. This is very similar to how OTR works.
