# home/quan05/doan/send_to_cloud.py

from pymongo import MongoClient
from bson.binary import Binary
from bson.objectid import ObjectId
import datetime

# ======================================================================================
# == ĐỊNH NGHĨA HÀM ĐÃ ĐƯỢC CẬP NHẬT ĐỂ NHẬN ĐẦY ĐỦ CÁC THAM SỐ ==
# ======================================================================================
def send_to_cloud(ciphertext_path, encrypted_key_path, access_policy, patient_name, patient_id, doctor_id, record_description, uploaded_by, mongo_uri, db_name, collection_name):
    """
    Gửi dữ liệu mã hóa và khóa đã mã hóa lên MongoDB.
    """
    client = MongoClient(mongo_uri)
    db = client[db_name]
    collection = db[collection_name]

    # Đọc nội dung file ciphertext
    with open(ciphertext_path, "rb") as f_cipher:
        ciphertext = f_cipher.read()

    # Đọc nội dung file AES key đã mã hóa
    with open(encrypted_key_path, "rb") as f_key:
        encrypted_key = f_key.read()

    # Tạo document để lưu vào MongoDB
    document = {
        "patient_id": ObjectId(patient_id),
        "patient_name": patient_name,
        "access_policy": access_policy,
        "doctor_id": ObjectId(doctor_id) if doctor_id else None,
        # ==========================================================
        # == CÁC TRƯỜNG MỚI ĐÃ ĐƯỢC THÊM VÀO DOCUMENT ==
        # ==========================================================
        "record_description": record_description,
        "uploaded_by": uploaded_by,
        "ciphertext": Binary(ciphertext),
        "aes_key_cpabe": Binary(encrypted_key),
        "created_at": datetime.datetime.utcnow() 
    }

    # Lưu document vào MongoDB
    result = collection.insert_one(document)
    return result.inserted_id