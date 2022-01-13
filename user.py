import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import AES
from state import State


class User:

    def __init__(self, name, root_key):
        self.name = name
        self.state = State(root_key)
        # Generating an object from which we will get the public key
        self.state.diffieHellman_self = X25519PrivateKey.generate()
        self.state.public_key = self.state.diffieHellman_self.public_key()
        self.other_user = "Alice" if name == "Bob" else "Bob"

    @staticmethod
    def b64(msg):
        # base64 encoding helper function
        return base64.encodebytes(msg).decode('utf-8').strip()

    def initialize_ratchet(self, user):
        """
        Function used to initialize the protocol, calculating the shared key
        :param user: External public key
        :return: Nothing, it stores the shared key within the state object
        """
        # Setting the remote public key
        self.state.diffieHellman_remote = user
        # Calculating the shared key with the remote public key
        self.state.shared_key = self.state.diffieHellman_self.exchange(user)

    @staticmethod
    def kdf_root(previous_root_key, input_key):
        """
        Function that calculates new keys for the root chain and the sending or receiving chain
        :param previous_root_key: Existing root key, used as salt for the HKDF algorithm (32 bytes)
        :param input_key: Is the shared secret after applied the Diffie Hellman algorithm (32 bytes)
        :return: First parameter, new root key, the second is the key for the sending or receiving chain (32 bytes each)
        """
        new_key = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=previous_root_key,
            info=b'Handshake data',
            backend=default_backend()
        ).derive(input_key)
        return new_key[:32], new_key[32:]

    @staticmethod
    def kdf_chain(ck):
        """
        Function that takes an existing key as input and calculates a new key for the chain and a message key
        :param ck: Actual key of the chain (32 bytes)
        :return: Two parameters, first, a message key, and second a new key for the chain
        """
        # Generating new message key (mk)
        mk_hmac = HMAC(ck, hashes.SHA256(), backend=default_backend())
        mk_hmac.update(b"0x01")
        # Generating a new chain key (ck)
        ck_hmac = HMAC(ck, hashes.SHA256(), backend=default_backend())
        ck_hmac.update(b"0x02")
        return mk_hmac.finalize(), ck_hmac.finalize()

    def send_ratchet(self):
        """
        Function to call when generating new DH key pair to send a message
        :return: Nothing, it updates the DH key pair and the shared secret
        """
        # Generating a new pair of keys each time we send a message after receiving one
        self.state.diffieHellman_self = X25519PrivateKey.generate()
        self.state.public_key = self.state.diffieHellman_self.public_key()
        self.state.shared_key = self.state.diffieHellman_self.exchange(self.state.diffieHellman_remote)
        self.state.root_key, self.state.chainKey_sending = User.kdf_root(self.state.root_key, self.state.shared_key)

    def receive_ratchet(self):
        """
        Function to call when receiving a message and the remote public key does not correspond with the one saved
        :return: Nothing, it updates the keys within the state object
        """
        # If header of the message (remote public key) is not the same as before, update shared secret
        self.state.shared_key = self.state.diffieHellman_self.exchange(self.state.diffieHellman_remote)
        # Updating receiving chain key to decrypt message
        self.state.root_key, self.state.chainKey_receiving = \
            User.kdf_root(self.state.root_key, self.state.shared_key)

    def send(self, msg=None):
        """
        Function that handles the keys and the process of sending a message, it includes some verifications,
        key generations and encryption
        :param msg: Message to send
        :return: Nothing, when finish the message should be sent
        """
        # Checking if we are going to send a message after sending another
        # In this case there is no need to update the DH keys
        if not self.state.last_message_was_sent:
            # In case last message was received update our DH key pair and sending keychain
            self.send_ratchet()

        # ratchet the sending chain once to obtain the new message key
        message_key, self.state.chainKey_sending = User.kdf_chain(self.state.chainKey_sending)
        # Encrypting the message to send
        ciphertext = User.encrypt(message_key, msg)
        message_to_send = self.state.public_key + ciphertext
        self.state.messages_sent += 1
        self.state.last_message_was_sent = True
        # TODO send ciphertext and prepend current DH public key

    def receive(self, msg=None):
        """
        Function that handles the keys and the process of receiving a message, it includes some verifications,
        key generations and decryption
        :param msg: Message received, it is a ciphertext
        :return: The plaintext of the decrypted message
        """
        # Not sure yet if checking a message exist is necessary...
        if msg:
            # Checking if the actual remote key is not the same as the specified in the message
            if not self.state.diffieHellman_remote == msg[:32]:
                self.receive_ratchet()
            message_key, self.state.chainKey_receiving = User.kdf_chain(self.state.chainKey_receiving)
            plaintext = User.decrypt(message_key, msg)
            self.state.messages_received += 1
            self.state.last_message_was_sent = False

    @staticmethod
    def encrypt(key, plaintext):
        """
        Function that encrypts a message with a key using AES encryption in GCM Mode
        :param key: Message key to encrypt the plaintext
        :param plaintext: Message that is going to be sent
        :return: The ciphertext of the message
        """
        cipher = AES.new(key, AES.MODE_GCM)
        return cipher.encrypt(plaintext)

    @staticmethod
    def decrypt(key, ciphertext):
        """
        Function that decrypts a message with a key using AES encryption in GCM Mode
        :param key: Message key to decrypt the ciphertext
        :param ciphertext: Encrypted message received
        :return: The plaintext of the message
        """
        cipher = AES.new(key, AES.MODE_GCM)
        return cipher.decrypt(ciphertext)
