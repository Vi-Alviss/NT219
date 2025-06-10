# home/quan05/doan/app.py

from flask import Flask, session, redirect, url_for

# Import các biến blueprint trực tiếp từ các file routes
from auth.routes import auth_bp
from creator.routes import creator_bp
from user.routes import user_bp

app = Flask(__name__)
app.secret_key = "sieu_bi_mat_khong_ai_biet_123"

# Đăng ký các blueprint đã import
app.register_blueprint(auth_bp, url_prefix='/auth')
app.register_blueprint(creator_bp)
app.register_blueprint(user_bp)


@app.route('/')
def index():
    """
    Trang chủ, điều hướng người dùng dựa trên trạng thái đăng nhập và vai trò.
    """
    if 'user' in session:
        role = session['user']['role']
        if role == 'doctor':
            return redirect(url_for('creator.data_creator'))
        elif role == 'patient':
            return redirect(url_for('user.data_user'))
        else:
            return redirect(url_for('auth.login'))
    
    return redirect(url_for('auth.login'))


if __name__ == "__main__":
    app.run(debug=True)