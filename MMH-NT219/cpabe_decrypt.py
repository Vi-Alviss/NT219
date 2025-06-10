# home/quan05/doan/cpabe_decrypt.py

from charm.toolbox.pairinggroup import PairingGroup
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
from charm.core.engine.util import bytesToObject
from group import group

def cpabe_decrypt(encrypted_key_file, secret_key_file, public_key_file):
    """
    Giải mã ciphertext ABE để khôi phục lại phần tử el ∈ GT,
    từ đó có thể tạo AES key bằng SHA256(el).
    """
    
    cpabe = CPabe_BSW07(group)

    # Load khóa công khai và bí mật
    with open(public_key_file, "rb") as f:
        pk = bytesToObject(f.read(), group)
    with open(secret_key_file, "rb") as f:
        sk = bytesToObject(f.read(), group)

    print("pk", pk)
    print ("sk", sk)
    print("cipher", encrypted_key_file)
    # Load ciphertext
    with open(encrypted_key_file, "rb") as f:
        ct_bytes = f.read()
        ct = bytesToObject(ct_bytes, group)
    print("ct", ct)
    # Giải mã để lấy lại el ∈ GT
    el = cpabe.decrypt(pk, sk, ct)
    print("el", el)
    if el is None or el is False:
        raise ValueError("Giải mã thất bại.")
    print("[DEBUG] el khi mã hóa:", str(el))
    return el  # Trả về el để dùng tiếp
