# home/quan05/doan/cpabe_encrypt.py

from charm.toolbox.pairinggroup import PairingGroup, GT
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
from charm.core.engine.util import objectToBytes, bytesToObject
from group import group

def cpabe_encrypt(el, policy, public_key_file, output_file_path):
    """
    Mã hóa phần tử GT (el) bằng ABE dựa theo policy.
    el phải được truyền vào từ hàm aes_encrypt (đã dùng để sinh aes_key = SHA256(el)).
    """
    print("el khi mã hóa:", el)
    cpabe = CPabe_BSW07(group)

    print("[DEBUG] GT element el được truyền vào sẽ được mã hóa bằng ABE.")
    print("[DEBUG] policy:", policy)

    # Load public key
    with open(public_key_file, "rb") as f:
        pk = bytesToObject(f.read(), group)

    # Encrypt el ∈ GT bằng ABE
    ct = cpabe.encrypt(pk, el, policy)
    if ct is None:
        raise ValueError("Encryption failed, ciphertext is None.")

    # Ghi ciphertext ra file
    ct_bytes = objectToBytes(ct, group)
    with open(output_file_path, "wb") as f:
        f.write(ct_bytes)

    return output_file_path
