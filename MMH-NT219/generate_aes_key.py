from Crypto.Random import get_random_bytes
import os

def create_aes_key_file(filename="aes_secret.key", length=32):
    """
    Tạo một file chứa khóa AES ngẫu nhiên.

    Args:
        filename (str): Tên file để lưu khóa. Mặc định là 'aes_secret.key'.
        length (int): Độ dài của khóa tính bằng bytes. Mặc định là 32 (cho AES-256).
    """
    # Tạo một khóa ngẫu nhiên
    key = get_random_bytes(length)
    
    # Lấy đường dẫn tuyệt đối của thư mục chứa script này
    current_directory = os.path.dirname(os.path.abspath(__file__))
    file_path = os.path.join(current_directory, filename)

    try:
        # Ghi khóa vào file ở chế độ nhị phân ('wb')
        with open(file_path, "wb") as key_file:
            key_file.write(key)
        
        print(f"✅ Đã tạo khóa AES thành công!")
        print(f"   - Độ dài: {length * 8}-bit ({length} bytes)")
        print(f"   - Đã lưu tại: {file_path}")

    except IOError as e:
        print(f"❌ Lỗi: Không thể ghi file. Vui lòng kiểm tra quyền truy cập.")
        print(f"   - Chi tiết lỗi: {e}")

if __name__ == "__main__":
    # Bạn có thể tùy chỉnh tên file ở đây nếu muốn
    output_filename = "my_aes_key.key"
    create_aes_key_file(filename=output_filename)