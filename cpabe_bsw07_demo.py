from charm.toolbox.pairinggroup import PairingGroup, GT
from charm.toolbox.policytree import PolicyParser
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
from charm.core.engine.util import objectToBytes, bytesToObject

# Use a pairing group (symmetric or asymmetric)
group = PairingGroup('SS512')  # or use 'SS512' for speed, 'MNT224' for better >
cpabe = CPabe_BSW07(group)

# Authority runs setup
(public_key, master_key) = cpabe.setup()

# Each user gets a secret key for their attributes
attributes = ['ONE', 'TWO', 'THREE']
secret_key = cpabe.keygen(public_key, master_key, attributes)

# Message to encrypt
message = group.random(GT)

# Define access policy using AND, OR, etc.
policy = '(ONE and TWO)'  # Example policy

# Encrypt under this policy
ciphertext = cpabe.encrypt(public_key, message, policy)

# Decrypt with user's secret key
decrypted_message = cpabe.decrypt(public_key, secret_key, ciphertext)

# Check result
assert message == decrypted_message
print("Decryption successful:", decrypted_message == message)

def save_obj(obj, filename, group):
    with open(filename, 'wb') as f:
        f.write(objectToBytes(obj, group))

def load_obj(filename, group):
    with open(filename, 'rb') as f:
        return bytesToObject(f.read(), group)

def main():
    group = PairingGroup('SS512')
    cpabe = CPabe_BSW07(group)

    # Setup
    (pk, mk) = cpabe.setup()

    # Save public and master keys
    save_obj(pk, 'public_key.charm', group)
    save_obj(mk, 'master_key.charm', group)

    # Keygen for user with attributes
    attr_list = ['ONE', 'TWO', 'THREE']
    sk = cpabe.keygen(pk, mk, attr_list)

    # Save secret key
    save_obj(sk, 'secret_key.charm', group)

    # Message encryption with policy
    msg = group.random(GT)
    policy = '(ONE and TWO)'
    ct = cpabe.encrypt(pk, msg, policy)

    # Save ciphertext
    save_obj(ct, 'ciphertext.charm', group)

    # Load everything back from files
    pk_loaded = load_obj('public_key.charm', group)
    sk_loaded = load_obj('secret_key.charm', group)
    ct_loaded = load_obj('ciphertext.charm', group)

    # Decryption
    rec_msg = cpabe.decrypt(pk_loaded, sk_loaded, ct_loaded)

    print("Decryption successful?", rec_msg == msg)

if __name__ == '__main__':
    main()
