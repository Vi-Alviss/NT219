# home/quan05/doan/auth/routes.py

from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
import datetime

# Sử dụng template_folder để Flask biết tìm template ở thư mục cha
auth_bp = Blueprint('auth', __name__, template_folder='../templates')

# --- MongoDB Connection ---
MONGO_URI = "mongodb+srv://tquan7245:abe123456@abe-cluster.f8itefc.mongodb.net/?retryWrites=true&w=majority&appName=abe-cluster"
client = MongoClient(MONGO_URI)
db = client.ehr_db
users_collection = db.users
users_collection.create_index("email", unique=True)


# home/quan05/doan/auth/routes.py

# ... (các import)

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # --- Lấy thông tin ---
        full_name = request.form.get('full_name')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        role = request.form.get('role')

        # --- Validation cơ bản ---
        if not role:
            flash("Vui lòng chọn vai trò của bạn.", "danger")
            return redirect(url_for('.register'))
        if not all([full_name, email, password, confirm_password]):
            flash("Vui lòng điền đầy đủ các thông tin chung.", "danger")
            return redirect(url_for('.register'))
        if password != confirm_password:
            flash("Mật khẩu xác nhận không khớp.", "danger")
            return redirect(url_for('.register'))
        if users_collection.find_one({'email': email}):
            flash("Email này đã được sử dụng.", "danger")
            return redirect(url_for('.register'))

        # --- Tạo document để lưu vào CSDL ---
        new_user_data = {
            'full_name': full_name,
            'email': email,
            'password': generate_password_hash(password),
            'role': role,
            'status': 'pending',
            'created_at': datetime.datetime.utcnow(),
            'attributes': {} # Tạo dictionary rỗng để chứa thuộc tính riêng
        }

        # --- Xử lý thông tin riêng theo vai trò ---
        if role == 'patient':
            # Lấy thông tin bệnh nhân
            dob = request.form.get('dob')
            national_id = request.form.get('national_id')
            insurance_number = request.form.get('insurance_number')
            emergency_contact = request.form.get('emergency_contact')
            # Kiểm tra
            if not all([dob, national_id, insurance_number, emergency_contact]):
                flash("Vui lòng điền đầy đủ thông tin dành cho bệnh nhân.", "danger")
                return redirect(url_for('.register'))
            # Thêm vào dictionary attributes
            new_user_data['attributes'] = {
                'date_of_birth': dob,
                'national_id': national_id,
                'insurance_number': insurance_number,
                'emergency_contact': emergency_contact
            }

        elif role == 'doctor':
            # Lấy thông tin bác sĩ
            department = request.form.get('department')
            license_number = request.form.get('license_number')
            hospital = request.form.get('hospital')
            # Kiểm tra
            if not all([department, license_number, hospital]):
                flash("Vui lòng điền đầy đủ thông tin dành cho bác sĩ.", "danger")
                return redirect(url_for('.register'))
            # Thêm vào dictionary attributes
            new_user_data['attributes'] = {
                'department': department,
                'license_number': license_number,
                'hospital': hospital
            }
        
        # --- Lưu vào CSDL và thông báo ---
        users_collection.insert_one(new_user_data)
        flash("Đăng ký thành công! Tài khoản của bạn đang chờ phê duyệt.", "success")
        return redirect(url_for('.login'))

    return render_template('register.html')

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = users_collection.find_one({'email': email})

        if user and check_password_hash(user['password'], password):
            if user['status'] == 'pending':
                flash("Tài khoản của bạn đang chờ phê duyệt.", "warning")
                return redirect(url_for('.login'))
            
            session['user'] = {
                'id': str(user['_id']), 
                'email': user['email'], 
                'role': user['role'], 
                'name': user['full_name'],
                'attributes': user.get('attributes', {})
            }
            flash(f"Chào mừng {user['full_name']}!", "success")

            # Điều hướng chính xác đến trang chủ của ứng dụng
            return redirect(url_for('index'))
        else:
            flash("Sai email hoặc mật khẩu!", "danger")
            
    return render_template('login.html')


@auth_bp.route('/logout')
def logout():
    session.clear()
    flash("Bạn đã đăng xuất.", "info")
    return redirect(url_for('.login'))

def get_attr_list_from_logged_in_user():
    user_email = session.get('user', {}).get('email')
    if not user_email:
        return []

    user_doc = users_collection.find_one({'email': user_email})
    if not user_doc:
        return []

    attr_list = []
    role = user_doc.get('role', '').lower()

    if role == 'doctor':
        attr_list.append('role:Doctor')
        dept = user_doc.get('attributes', {}).get('department')
        if dept:
            attr_list.append(f'dept:{dept}')
    elif role == 'patient':
        attr_list.append('role:Patient')

    return attr_list
