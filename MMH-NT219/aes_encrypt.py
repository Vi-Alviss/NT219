# home/quan05/doan/aes_encrypt.py

from Crypto.Cipher import AES
from charm.toolbox.pairinggroup import GT
from charm.core.engine.util import bytesToObject
import hashlib
import requests
import base64
from charm.core.engine.util import bytesToObject, objectToBytes
from group import group

def aes_encrypt(input_file_path, output_file_path, key=None):
    """
    Mã hóa file bằng AES-GCM.
    Nếu không có `key`, tự động gọi EC2 để lấy `el` ∈ GT.
    AES key = SHA256(el), dùng cho hybrid encryption.
    
    Trả về: el ∈ GT (để mã hóa bằng ABE sau đó)
    """

    if key is None:
        try:
            print("[LOCAL] Đang gửi yêu cầu lấy el từ EC2...")
            response = requests.get("http://16.176.175.6:3001/get-el")  # ⚠️ THAY EC2-IP
            response.raise_for_status()
            el_b64 = response.json()["el"]

            el_bytes = base64.b64decode(el_b64)
            key = bytesToObject(el_bytes, group)  # 🔑 el ∈ GT

            print("[LOCAL] Nhận el từ EC2 thành công!")

        except Exception as e:
            print("[ERROR] Không thể lấy el từ EC2:", str(e))
            return None

    print("el khi tao key:", key)

    # Tạo AES key từ ela
    aes_key = hashlib.sha256(objectToBytes(key, group)).digest()
    print(aes_key)
    # Đọc dữ liệu từ file
    with open(input_file_path, "rb") as f:
        plaintext = f.read()

    # Mã hóa bằng AES-GCM
    cipher = AES.new(aes_key, AES.MODE_GCM)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    # Ghi vào file đầu ra
    with open(output_file_path, "wb") as f:
        f.write(nonce)
        f.write(tag)
        f.write(ciphertext)

    return key  # GT element
