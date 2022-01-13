class State:

    def __init__(self, initial_root_key):
        self.diffieHellman_self = None  # Diffie Hellman self key pair
        self.public_key = None
        self.diffieHellman_remote = None  # Remote public key
        self.root_key = initial_root_key
        self.chainKey_sending = None
        self.chainKey_receiving = None
        self.messages_sent = 0
        self.messages_received = 0
        self.last_message_was_sent = False  # To avoid updating Diffie Hellman each message sent if are consecutive
        # Variable in tests
        self.shared_key = None
