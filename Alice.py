import mqtt_utils, time
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# clientAlice = mqtt_utils.connect_mqtt("Alice_acb2022")
# mqtt_utils.publish(clientAlice, "ALICEACB.out", "Hola Bob")
# mqtt_utils.subscribe(clientAlice, "BOBACB.in")
# clientAlice.loop_start()

# while True:
#     time.sleep(100)
    
root_key = b""

alice_private_dh = X25519PrivateKey.generate()
alice_public_dh = alice_private_dh.public_key()

bob_private_dh = X25519PrivateKey.generate()
bob_public_dh = bob_private_dh.public_key()

shared_key1 = alice_private_dh.exchange(bob_public_dh)
shared_key2 = bob_private_dh.exchange(alice_public_dh)
    
root_key, chain_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=root_key,
    info=b'handshake data',
).derive(shared_key1)

hash = hmac.HMAC(chain_key, hashes.SHA256)
hash.update(b"")


    
    
