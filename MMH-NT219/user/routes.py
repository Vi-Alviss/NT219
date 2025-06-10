import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from flask import Blueprint, render_template, request, session, flash, redirect, url_for, send_file
from functools import wraps
from pymongo import MongoClient
from bson.objectid import ObjectId
import pickle
import io
import zipfile

from aes_encrypt import aes_encrypt
from cpabe_encrypt import cpabe_encrypt
from aes_decrypt import aes_decrypt
from cpabe_decrypt import cpabe_decrypt
from send_to_cloud import send_to_cloud

from charm.toolbox.pairinggroup import PairingGroup
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
import requests

user_bp = Blueprint('user', __name__, template_folder='../templates')

UPLOAD_FOLDER = "temp/"
OUTPUT_FOLDER = "output/"

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            flash("Vui lòng đăng nhập để truy cập trang này.", "warning")
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function

@user_bp.route('/data_user', methods=['GET', 'POST'])
@login_required
def data_user():
    user = session['user']
    user_role = user['role'] # Lấy vai trò viết thường từ session, vd: 'doctor'
    results = []

    print(f"DEBUG - User Role: {user_role}")
    doctor_attributes = user.get('attributes', {})
    print(f"DEBUG - Doctor Attributes: {doctor_attributes}")
    user_department = doctor_attributes.get('department')
    print(f"DEBUG - User Department (from attributes): {user_department}")
    
    mongo_uri = "mongodb+srv://tquan7245:abe123456@abe-cluster.f8itefc.mongodb.net/?retryWrites=true&w=majority&appName=abe-cluster"
    client = MongoClient(mongo_uri)
    db = client.ehr_db

    if user_role == 'doctor':
        doctor_attributes = user.get('attributes', {})
        
        # Xây dựng chuỗi thuộc tính từ role viết thường, sau đó title() để thành chữ hoa
        search_conditions = [f"role:{user_role.title()}"]
        
        # Doctors always have a department, as per your clarification
        if 'department' in doctor_attributes:
            search_conditions.append(f"dept:{doctor_attributes['department']}")

        # Construct the query based on collected conditions
        query_parts = []
        for condition in search_conditions:
            query_parts.append({'access_policy': {'$regex': condition, '$options': 'i'}})

        final_query = {'$and': query_parts}

        results = list(db.medical_records.find(final_query, {'ciphertext': 0, 'aes_key_cpabe': 0}))

        # Flash message only if it's a POST request (from the search button)
        if request.method == 'POST':
            flash(f"Tìm thấy {len(results)} hồ sơ phù hợp.", "info")

    elif user_role == 'patient':
        patient_id_str = user['id'] # This should be the _id string of the logged-in patient
        # Ensure patient_id in medical_records is stored as ObjectId for comparison
        results = list(db.medical_records.find(
            {'patient_id': ObjectId(patient_id_str)},
            {'ciphertext': 0, 'aes_key_cpabe': 0}
        ))
        
    return render_template('data_user.html', results=results, active_tab='data_user')

# ... route download_record không đổi ...

@user_bp.route('/download-record', methods=['POST'])
@login_required
def download_record():
    doc_id = request.form.get('doc_id')
    if not doc_id:
        flash("Lỗi: Thiếu ID hồ sơ.", "danger")
        return redirect(url_for('.data_user'))

    mongo_uri = "mongodb+srv://tquan7245:abe123456@abe-cluster.f8itefc.mongodb.net/?retryWrites=true&w=majority&appName=abe-cluster"
    client = MongoClient(mongo_uri)
    db = client.ehr_db
    record = db.medical_records.find_one({'_id': ObjectId(doc_id)})
    
    if not record:
        flash("Không tìm thấy hồ sơ.", "danger")
        return redirect(url_for('.data_user'))

    # --- START: Access Control for Download (CRITICAL) ---
    user_data_from_session = session.get('user', {})
    user_role = user_data_from_session.get('role', '').lower() # Ensure role is lowercase
    user_id = user_data_from_session.get('id') # This is the string representation of ObjectId
    user_attributes = user_data_from_session.get('attributes', {}) # Attributes is a dict

    # Helper function to extract department from access_policy string
    # This assumes record.access_policy is like 'role:Doctor AND dept:Cardiology'
    def get_required_department_from_policy(policy_string):
        if not policy_string:
            return None
        # Split by ' AND ' to find individual policy parts, and remove potential extra spaces
        parts = [p.strip() for p in policy_string.split(' AND ')]
        for part in parts:
            if part.startswith('dept:'):
                return part.replace('dept:', '').strip()
        return None

    # Helper function to get the user's department from their attributes object
    def get_user_department(user_attributes_dict):
        # Directly get from the dictionary
        return user_attributes_dict.get('department')

    user_department = get_user_department(user_attributes)
    record_required_department = get_required_department_from_policy(record.get('access_policy', '')) # Use .get() with default for safety

    is_authorized = False

    if user_role == 'patient':
        # Patient can only download their own record
        # Convert record['patient_id'] to string for consistent comparison with user_id
        if str(record.get('patient_id')) == str(user_id):
            is_authorized = True
    elif user_role == 'doctor':
        # Doctors can download if their department matches the record's required department
        # And the record's policy should implicitly or explicitly include 'role:Doctor'
        
        # Rule 1: If record policy specifies a department and it matches doctor's department
        if user_department and record_required_department and user_department == record_required_department:
            is_authorized = True
        # Rule 2 (Optional, based on your broader policy): If record policy is generic for 'role:Doctor'
        # without a specific department, should any doctor access it?
        # If so, uncomment and adjust:
        # elif not record_required_department and "role:Doctor" in record.get('access_policy', ''):
        #     is_authorized = True
        
        # Make sure the doctor's general role is also considered if policies are like "role:Doctor"
        # without a dept. This is implicitly handled by the db query in data_user for display,
        # but needs explicit check here.
        # If your policies are ALWAYS "role:Doctor AND dept:X", then the above 'if' is sufficient.
        # If some policies are just "role:Doctor", then check if user is a doctor and policy matches.
        elif record_required_department is None and user_role == 'doctor' and "role:Doctor" in record.get('access_policy', ''):
            is_authorized = True


    if not is_authorized:
        flash("Bạn không có quyền truy cập để tải hồ sơ này.", "danger")
        return redirect(url_for('.data_user'))
    # --- END: Access Control for Download ---

    mem_zip = io.BytesIO()
    with zipfile.ZipFile(mem_zip, 'w', zipfile.ZIP_DEFLATED) as zipf:
        # Ensure 'ciphertext' and 'aes_key_cpabe' fields exist before trying to access
        if 'ciphertext' in record:
            zipf.writestr("ciphertext.bin", record['ciphertext'])
        else:
            flash("Lỗi: Hồ sơ không chứa dữ liệu mã hóa (ciphertext).", "danger")
            return redirect(url_for('.data_user'))
            
        if 'aes_key_cpabe' in record:
            zipf.writestr("aes_key_cpabe.ct", record['aes_key_cpabe'])
        else:
            flash("Lỗi: Hồ sơ không chứa khóa AES đã mã hóa (aes_key_cpabe).", "danger")
            return redirect(url_for('.data_user'))

    mem_zip.seek(0)

    return send_file(mem_zip, mimetype='application/zip', as_attachment=True, download_name=f'record_{doc_id}.zip')

# ... route request_secret_key không đổi ...

@user_bp.route('/request-secret-key', methods=['POST'])
@login_required
def request_secret_key():
    try:
        # Bước 1: Truy xuất thông tin người dùng từ DB
        user = session['user']
        user_id = ObjectId(user['id'])
        user_email = user['email']

        mongo_uri = "mongodb+srv://tquan7245:abe123456@abe-cluster.f8itefc.mongodb.net/?retryWrites=true&w=majority&appName=abe-cluster"
        client = MongoClient(mongo_uri)
        db = client.ehr_db
        users_collection = db.users
        user_doc = users_collection.find_one({'_id': user_id})

        if not user_doc:
            flash("Không tìm thấy người dùng trong hệ thống.", "danger")
            return redirect(url_for('.data_user'))

        role = user_doc.get('role', '').lower()
        attributes = []

        if role == 'doctor':
            attributes.append("roleDoctor")
            dept = user_doc.get('attributes', {}).get('department')
            if dept:
                attributes.append(f"dept{dept}")
        elif role == 'patient':
            attributes.append("rolePatient")
        else:
            flash("Vai trò người dùng không hợp lệ.", "danger")
            return redirect(url_for('.data_user'))

        # Bước 2: Gửi attribute lên EC2 (ví dụ chạy ở port 3001)
        ec2_url = "http://16.176.175.6:3001/generate_sk"  # <-- Cập nhật IP EC2 thật của bạn
        response = requests.post(ec2_url, json={'attributes': attributes})

        if response.status_code != 200:
            flash("Không thể tạo khóa bí mật từ máy chủ EC2.", "danger")
            return redirect(url_for('.data_user'))

        # Bước 3: Nhận file và lưu vào thư mục output/
        os.makedirs('output', exist_ok=True)
        sk_path = os.path.join('output', 'secret_key.pk')
        with open(sk_path, 'wb') as f:
            f.write(response.content)

        flash("Đã nhận khóa bí mật và lưu vào output/secret_key.pk", "success")
        return send_file(sk_path, as_attachment=True, download_name='secret_key.pk')

    except Exception as e:
        flash(f"Lỗi khi yêu cầu khóa từ máy chủ EC2: {e}", "danger")
        return redirect(url_for('.data_user'))

# ... route decrypt_record không đổi ...

@user_bp.route('/decrypt-record', methods=['POST'])
@login_required
def decrypt_record():
    ciphertext_file = request.files.get('ciphertext_file')
    encrypted_key_file = request.files.get('encrypted_key_file')
    secret_key_file = request.files.get('secret_key_file')
    public_key_file = request.files.get('public_key_file')

    if not all([ciphertext_file, encrypted_key_file, secret_key_file, public_key_file]):
        flash("Vui lòng cung cấp đủ 4 file để giải mã.", "danger")
        return redirect(url_for('.data_user'))

    try:
        os.makedirs(UPLOAD_FOLDER, exist_ok=True)
        os.makedirs(OUTPUT_FOLDER, exist_ok=True)

        ct_path = os.path.join(UPLOAD_FOLDER, "temp_ciphertext.bin")
        ek_path = os.path.join(UPLOAD_FOLDER, "temp_encrypted_key.ct")
        sk_path = os.path.join(UPLOAD_FOLDER, "temp_secret_key.sk")
        pk_path = os.path.join(UPLOAD_FOLDER, "temp_public_key.pk")
        
        ciphertext_file.save(ct_path)
        encrypted_key_file.save(ek_path)
        secret_key_file.save(sk_path)
        public_key_file.save(pk_path)

        print("[INFO] Các file đã được lưu tạm:")
        print(f" - Ciphertext: {ct_path}")
        print(f" - Encrypted AES key (ABE ciphertext): {ek_path}")
        print(f" - Secret Key: {sk_path}")
        print(f" - Public Key: {pk_path}")

        # Giải mã el ∈ GT
        el = cpabe_decrypt(ek_path, sk_path, pk_path)
        if el is None:
            raise ValueError("Không thể giải mã khóa AES. Thuộc tính không khớp với chính sách hoặc khóa không hợp lệ.")

        # Giải mã file bằng AES key (tái tạo từ el)
        decrypted_path = os.path.join(OUTPUT_FOLDER, "decrypted_record.txt")
        success = aes_decrypt(ct_path, el, decrypted_path)
        if not success:
            raise ValueError("Giải mã AES thất bại. File có thể đã bị thay đổi hoặc khóa không đúng.")

        return send_file(decrypted_path, as_attachment=True, download_name="HOSODAGIAIMA.txt")

    except Exception as e:
        flash(f"Quá trình giải mã thất bại: {e}", "danger")
        return redirect(url_for('.data_user'))


@user_bp.route('/patient-upload', methods=['GET', 'POST'])
@login_required
def patient_upload():
    # Sửa điều kiện so sánh thành chữ thường
    if session['user']['role'] != 'patient':
        flash("Chức năng này chỉ dành cho bệnh nhân.", "danger")
        return redirect(url_for('index'))

    if request.method == 'POST':
        policy = request.form.get("policy_expression")
        description = request.form.get("record_description")
        medical_file = request.files.get("medical_file")
        pk_file = request.files.get("public_key_file")
        
        if not all([policy, description, medical_file, pk_file]):
            flash("Vui lòng điền và chọn đầy đủ các tệp.", "warning")
            return redirect(url_for('.patient_upload'))

        os.makedirs(UPLOAD_FOLDER, exist_ok=True)
        os.makedirs(OUTPUT_FOLDER, exist_ok=True)

        input_path = os.path.join(UPLOAD_FOLDER, medical_file.filename)
        medical_file.save(input_path)
        public_key_path = os.path.join(UPLOAD_FOLDER, pk_file.filename)
        pk_file.save(public_key_path)

        output_ciphertext_path = os.path.join(OUTPUT_FOLDER, "patient_ciphertext.bin")
        aes_key = aes_encrypt(input_path, output_ciphertext_path)
        
        output_key_path = os.path.join(OUTPUT_FOLDER, "patient_aes_key_cpabe.ct")
        cpabe_encrypt(aes_key, policy, public_key_path, output_key_path)

        session['patient_upload_info'] = {
            'policy': policy,
            'description': description
        }
        
        flash("Mã hóa thành công! Các file đã được tạo trong 'output/'. Vui lòng chọn chúng ở Bước 2 để tải lên.", "success")
        return redirect(url_for('.patient_confirm_upload'))

    session.pop('patient_upload_info', None)
    return render_template('patient_upload.html', step='prepare', active_tab='patient_upload')


@user_bp.route('/patient-confirm-upload')
@login_required
def patient_confirm_upload():
    if 'patient_upload_info' not in session:
        return redirect(url_for('.patient_upload'))
    
    return render_template('patient_upload.html', step='confirm', active_tab='patient_upload')


@user_bp.route('/patient-do-upload', methods=['POST'])
@login_required
def patient_do_upload():
    if 'patient_upload_info' not in session:
        flash("Phiên làm việc hết hạn.", "danger")
        return redirect(url_for('.patient_upload'))

    ciphertext_file = request.files.get("ciphertext_file_upload")
    key_file = request.files.get("key_file_upload")

    if not all([ciphertext_file, key_file]):
        flash("Vui lòng chọn đủ 2 file.", "danger")
        return redirect(url_for('.patient_confirm_upload'))
    
    info = session['patient_upload_info']

    temp_ciphertext_path = os.path.join(UPLOAD_FOLDER, ciphertext_file.filename)
    ciphertext_file.save(temp_ciphertext_path)
    temp_key_path = os.path.join(UPLOAD_FOLDER, key_file.filename)
    key_file.save(temp_key_path)

    mongo_uri = "mongodb+srv://tquan7245:abe123456@abe-cluster.f8itefc.mongodb.net/?retryWrites=true&w=majority&appName=abe-cluster"
    db_name = "ehr_db"
    
    inserted_id = send_to_cloud(
        ciphertext_path=temp_ciphertext_path,
        encrypted_key_path=temp_key_path,
        access_policy=info['policy'],
        patient_name=session['user']['name'],
        patient_id=session['user']['id'],
        doctor_id=None,
        record_description=info['description'],
        # Sửa giá trị gửi đi thành chữ thường để nhất quán
        uploaded_by='patient',
        mongo_uri=mongo_uri,
        db_name=db_name,
        collection_name="medical_records"
    )
    
    session.pop('patient_upload_info', None)
    flash(f"Tải hồ sơ cá nhân thành công! ID: {inserted_id}", "success")
    return redirect(url_for('.data_user'))