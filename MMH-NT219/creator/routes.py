import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from flask import Blueprint, render_template, request, redirect, url_for, session, flash, send_file, jsonify
from functools import wraps
import io
from pymongo import MongoClient

from aes_encrypt import aes_encrypt
from cpabe_encrypt import cpabe_encrypt
from send_to_cloud import send_to_cloud

creator_bp = Blueprint('creator', __name__, template_folder='../templates')

UPLOAD_FOLDER = "temp/"
OUTPUT_FOLDER = "output/"

def doctor_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session or session['user']['role'] != 'doctor':
            flash("Bạn không có quyền truy cập trang này.", "danger")
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function

@creator_bp.route('/data_creator', methods=['GET'])
@doctor_required
def data_creator():
    return render_template('data_creator.html', active_tab='data_creator')

@creator_bp.route('/search-patient', methods=['POST'])
@doctor_required
def search_patient():
    national_id = request.json.get('national_id')
    if not national_id:
        return jsonify({'error': 'Vui lòng nhập CCCD/National ID'}), 400

    mongo_uri = "mongodb+srv://tquan7245:abe123456@abe-cluster.f8itefc.mongodb.net/?retryWrites=true&w=majority&appName=abe-cluster"
    client = MongoClient(mongo_uri)
    db = client.ehr_db
    
    patient = db.users.find_one({'role': 'patient', 'attributes.national_id': national_id})
    if patient:
        return jsonify({'found': True, 'patient_id': str(patient['_id']), 'full_name': patient['full_name']})
    else:
        return jsonify({'found': False, 'message': 'Không tìm thấy bệnh nhân với CCCD này.'})

@creator_bp.route('/generate-policy', methods=['POST'])
@doctor_required
def generate_policy():
    # JavaScript đã xây dựng sẵn chuỗi policy, ta chỉ cần nhận nó từ form
    final_policy = request.form.get('policy_string')
    if not final_policy:
        return "Lỗi: Không có chính sách nào được tạo từ client.", 400

    # Tạo file trong bộ nhớ từ chuỗi đã nhận
    mem_file = io.BytesIO(final_policy.encode('utf-8'))
    
    # Gửi file về cho trình duyệt của người dùng để tải xuống
    return send_file(
        mem_file,
        mimetype='text/plain',
        as_attachment=True,
        download_name='access_policy.txt'
    )

@creator_bp.route('/encrypt', methods=['POST'])
@doctor_required
def encrypt():
    patient_id = request.form.get("patient_id")
    patient_name = request.form.get("patient_name")
    medical_file = request.files.get("medical_file")
    pk_file = request.files.get("public_key_file")
    policy_file = request.files.get("policy_file")
    aes_key_file = request.files.get("aes_key_file")

    if not all([patient_id, patient_name, medical_file, pk_file, policy_file]):
        flash("Vui lòng tìm bệnh nhân và chọn đầy đủ các tệp bắt buộc.", "warning")
        return redirect(url_for('.data_creator'))

    try:
        policy = policy_file.read().decode('utf-8').strip()
        if not policy: raise ValueError("File rỗng")
    except Exception as e:
        flash(f"Lỗi: File chính sách không hợp lệ. {e}", "danger")
        return redirect(url_for('.data_creator'))
        
    provided_aes_key = None
    if aes_key_file:
        try:
            key_data = aes_key_file.read()
            if len(key_data) != 32:
                flash(f"Lỗi: File khóa AES phải có kích thước đúng 32 bytes, file của bạn có {len(key_data)} bytes.", "danger")
                return redirect(url_for('.data_creator'))
            provided_aes_key = key_data
            flash("Sử dụng khóa AES từ file được cung cấp.", "info")
        except Exception as e:
            flash(f"Lỗi khi đọc file khóa AES: {e}", "danger")
            return redirect(url_for('.data_creator'))
    else:
        flash("Không có file khóa AES nào được cung cấp, hệ thống sẽ tạo khóa ngẫu nhiên.", "info")

    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    os.makedirs(OUTPUT_FOLDER, exist_ok=True)
    input_path = os.path.join(UPLOAD_FOLDER, medical_file.filename)
    medical_file.save(input_path)
    public_key_path = os.path.join(UPLOAD_FOLDER, pk_file.filename)
    pk_file.save(public_key_path)

    output_ciphertext_path = os.path.join(OUTPUT_FOLDER, "ciphertext.bin")
    aes_key_used = aes_encrypt(input_path, output_ciphertext_path, key=provided_aes_key)
    
    output_key_path = os.path.join(OUTPUT_FOLDER, "aes_key_cpabe.ct")
    cpabe_encrypt(aes_key_used, policy, public_key_path, output_key_path)

    session['upload_info'] = {
        'patient_id': patient_id,
        'patient_name': patient_name,
        'policy': policy,
        'doctor_id': session['user']['id']
    }
    flash("Mã hóa thành công! Các file đã được tạo trong 'output/'. Vui lòng chọn chúng ở Bước 3.", "success")
    return redirect(url_for('.confirm_upload'))

@creator_bp.route('/confirm_upload')
@doctor_required
def confirm_upload():
    if 'upload_info' not in session:
        return redirect(url_for('.data_creator'))
    info = session['upload_info']
    return render_template('data_creator.html', step='confirm', info=info, active_tab='data_creator')

@creator_bp.route('/upload', methods=['POST'])
@doctor_required
def upload():
    if 'upload_info' not in session:
        flash("Phiên làm việc hết hạn, vui lòng bắt đầu lại.", "danger")
        return redirect(url_for('.data_creator'))

    ciphertext_file = request.files.get("ciphertext_file_upload")
    key_file = request.files.get("key_file_upload")

    if not all([ciphertext_file, key_file]):
        flash("Vui lòng chọn đủ 2 file được yêu cầu để upload.", "danger")
        return redirect(url_for('.confirm_upload'))
    
    info = session['upload_info']
    temp_ciphertext_path = os.path.join(UPLOAD_FOLDER, ciphertext_file.filename)
    ciphertext_file.save(temp_ciphertext_path)
    temp_key_path = os.path.join(UPLOAD_FOLDER, key_file.filename)
    key_file.save(temp_key_path)
    mongo_uri = "mongodb+srv://tquan7245:abe123456@abe-cluster.f8itefc.mongodb.net/?retryWrites=true&w=majority&appName=abe-cluster"
    db_name = "ehr_db"
    
    # ====================================================================
    # == SỬA Ở ĐÂY: Thêm các tham số còn thiếu vào lời gọi send_to_cloud ==
    # ====================================================================
    record_description = f"Hồ sơ do bác sĩ {session['user']['name']} tạo cho bệnh nhân {info['patient_name']}."
    
    inserted_id = send_to_cloud(
        ciphertext_path=temp_ciphertext_path,
        encrypted_key_path=temp_key_path,
        access_policy=info['policy'],
        patient_name=info['patient_name'],
        patient_id=info['patient_id'],
        doctor_id=info['doctor_id'], 
        record_description=record_description, # Thêm tham số này
        uploaded_by='doctor', # Thêm tham số này
        mongo_uri=mongo_uri,
        db_name=db_name,
        collection_name="medical_records"
    )   
    session.pop('upload_info', None)
    flash(f"Tải hồ sơ lên Cloud thành công! ID: {inserted_id}", "success")
    return redirect(url_for('.data_creator'))