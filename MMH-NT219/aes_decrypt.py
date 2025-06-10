# home/quan05/doan/aes_decrypt.py

from Crypto.Cipher import AES
from hashlib import sha256
from charm.core.engine.util import objectToBytes
from group import group

def aes_decrypt(ciphertext_path, el_recovered, output_path):
    """
    Giải mã file AES-GCM sử dụng khóa được tạo từ el ∈ GT.
    """
    try:
        # Tạo lại AES key từ el
        print(el_recovered)
        aes_key = sha256(objectToBytes(el_recovered, group)).digest()
        print(aes_key)
        with open(ciphertext_path, "rb") as f:
            nonce = f.read(16)      # 16 bytes nonce (GCM chuẩn)
            tag = f.read(16)        # 16 bytes tag
            ciphertext = f.read()

        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)

        with open(output_path, "wb") as f:
            f.write(decrypted_data)

        print("✅ Giải mã và xác thực thành công!")
        return True

    except (ValueError, KeyError) as e:
        print(f"❌ Lỗi giải mã hoặc xác thực: {e}")
        return False
