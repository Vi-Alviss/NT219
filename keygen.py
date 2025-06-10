from charm.toolbox.pairinggroup import PairingGroup
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
from charm.core.engine.util import objectToBytes, bytesToObject

# === Setup ===
group = PairingGroup('SS512')
cpabe = CPabe_BSW07(group)

def save_obj(obj, filename, group):
    with open(filename, 'wb') as f:
        f.write(objectToBytes(obj, group))

def load_obj(filename, group):
    with open(filename, 'rb') as f:
        return bytesToObject(f.read(), group)

# === Key Generation ===
(pk, mk) = cpabe.setup()
save_obj(pk, 'pk.charm', group)
save_obj(mk, 'mk.charm', group)

# === User Secret Key ===
attrs = ['ONE', 'TWO', 'THREE']
sk = cpabe.keygen(pk, mk, attrs)
save_obj(sk, 'sk.charm', group)

# === Encryption ===
msg = group.random(group.GT)
policy = '(ONE and TWO)'
ct = cpabe.encrypt(pk, msg, policy)
save_obj(ct, 'ct.charm', group)

# === Decryption Test ===
pk = load_obj('pk.charm', group)
sk = load_obj('sk.charm', group)
ct = load_obj('ct.charm', group)

decrypted = cpabe.decrypt(pk, sk, ct)
print("[*] Decrypted:", decrypted.decode())
print("[*] Decryption successful?", decrypted == msg)
