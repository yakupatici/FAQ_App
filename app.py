from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os
from markupsafe import Markup
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, EmailField, TextAreaField, SelectField
from wtforms.validators import DataRequired, Email, Length, EqualTo

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'  # Sabit bir secret key kullan
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///faq.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Form Sınıfları
class LoginForm(FlaskForm):
    email = EmailField('Email', validators=[
        DataRequired(message='Email adresi gerekli'),
        Email(message='Geçerli bir email adresi girin')
    ])
    password = PasswordField('Şifre', validators=[
        DataRequired(message='Şifre gerekli'),
        Length(min=6, message='Şifre en az 6 karakter olmalı')
    ])

class RegisterForm(FlaskForm):
    email = EmailField('Email', validators=[
        DataRequired(message='Email adresi gerekli'),
        Email(message='Geçerli bir email adresi girin')
    ])
    password = PasswordField('Şifre', validators=[
        DataRequired(message='Şifre gerekli'),
        Length(min=8, message='Şifre en az 8 karakter olmalı')
    ])
    confirm_password = PasswordField('Şifre Tekrar', validators=[
        DataRequired(message='Şifre tekrarı gerekli'),
        EqualTo('password', message='Şifreler eşleşmiyor')
    ])

class FAQForm(FlaskForm):
    question = StringField('Soru', validators=[DataRequired(message='Soru alanı gerekli')])
    answer = TextAreaField('Cevap', validators=[DataRequired(message='Cevap alanı gerekli')])
    category = SelectField('Kategori', 
                         choices=[('pc', 'Bilgisayar'), ('network', 'Ağ'), ('printer', 'Yazıcı')],
                         validators=[DataRequired(message='Kategori seçimi gerekli')])

# nl2br filtresi ekle
@app.template_filter('nl2br')
def nl2br(value):
    return Markup(value.replace('\n', '<br>'))

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    role = db.Column(db.String(20), nullable=False, default='user')  # 'admin' or 'user'

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class FAQ(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question = db.Column(db.String(200), nullable=False)
    answer = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    updated_at = db.Column(db.DateTime, server_default=db.func.now(), onupdate=db.func.now())

def load_sample_faqs():
    # FAQ'ları yükle
    try:
        with open('sample_faqs.txt', 'r', encoding='utf-8') as file:
            faqs = file.readlines()
            
        for faq in faqs:
            faq = faq.strip()
            if faq:  # Boş satırları atla
                question, answer, category = faq.split('|')
                # FAQ zaten var mı kontrol et
                existing_faq = FAQ.query.filter_by(question=question).first()
                if not existing_faq:
                    new_faq = FAQ(
                        question=question,
                        answer=answer.replace('\\n', '\n'),  # \n karakterlerini gerçek satır sonlarına çevir
                        category=category
                    )
                    db.session.add(new_faq)
        
        db.session.commit()
        print("Örnek FAQ'lar başarıyla yüklendi.")
    except Exception as e:
        print(f"FAQ'lar yüklenirken hata oluştu: {e}")
        db.session.rollback()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash('Bu sayfaya erişim yetkiniz yok.', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# Create admin user if not exists
def create_admin():
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        admin = User(username='admin', email='admin@example.com', role='admin')
        admin.set_password('admin123')
        db.session.add(admin)
        db.session.commit()
        print("Admin user created successfully")
    # Örnek FAQ'ları yükle
    load_sample_faqs()

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            flash('Başarıyla giriş yaptınız!', 'success')
            return redirect(url_for('dashboard'))
        flash('Email veya şifre hatalı!', 'danger')
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = RegisterForm()
    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data).first():
            flash('Bu email adresi zaten kayıtlı!', 'danger')
            return redirect(url_for('register'))
        
        user = User(
            username=form.email.data.split('@')[0],  # email'in @ öncesini username olarak kullan
            email=form.email.data,
            role='user'
        )
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        
        flash('Kayıt başarılı! Şimdi giriş yapabilirsiniz.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    search = request.args.get('search', '')
    category = request.args.get('category', 'all')
    
    query = FAQ.query
    
    if search:
        search = f"%{search}%"
        query = query.filter(
            db.or_(
                FAQ.question.ilike(search),
                FAQ.answer.ilike(search)
            )
        )
    
    if category and category != 'all':
        query = query.filter_by(category=category)
    
    faqs = query.all()
    categories = db.session.query(FAQ.category).distinct()
    return render_template('dashboard.html', faqs=faqs, categories=categories, selected_category=category)

@app.route('/manage-faqs')
@login_required
@admin_required
def manage_faqs():
    faqs = FAQ.query.order_by(FAQ.updated_at.desc()).all()
    return render_template('manage_faqs.html', faqs=faqs)

@app.route('/add-faq', methods=['GET', 'POST'])
@login_required
@admin_required
def add_faq():
    if request.method == 'GET':
        return render_template('add_faq.html')
    
    question = request.form.get('question')
    answer = request.form.get('answer')
    category = request.form.get('category')
    
    if question and answer and category:
        faq = FAQ(question=question, answer=answer, category=category)
        db.session.add(faq)
        db.session.commit()
        flash('SSS başarıyla eklendi', 'success')
        return redirect(url_for('dashboard'))
    
    flash('Tüm alanları doldurun', 'danger')
    return redirect(url_for('add_faq'))

@app.route('/edit-faq/<int:faq_id>', methods=['GET'])
@login_required
@admin_required
def edit_faq_form(faq_id):
    faq = FAQ.query.get_or_404(faq_id)
    return render_template('edit_faq.html', faq=faq)

@app.route('/edit-faq', methods=['POST'])
@login_required
@admin_required
def edit_faq():
    faq_id = request.form.get('faq_id')
    faq = FAQ.query.get_or_404(faq_id)
    
    faq.question = request.form.get('question')
    faq.answer = request.form.get('answer')
    faq.category = request.form.get('category')
    
    db.session.commit()
    flash('FAQ başarıyla güncellendi', 'success')
    return redirect(url_for('dashboard'))

@app.route('/delete-faq/<int:faq_id>', methods=['POST'])
@login_required
@admin_required
def delete_faq(faq_id):
    faq = FAQ.query.get_or_404(faq_id)
    db.session.delete(faq)
    db.session.commit()
    flash('SSS başarıyla silindi', 'success')
    return redirect(url_for('dashboard'))

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()  # Veritabanı işlemlerini geri al
    return render_template('error.html', error=error), 500

@app.errorhandler(404)
def not_found_error(error):
    return render_template('error.html', error=error), 404

# Production ortamında tablo oluşturma ve admin yaratma
with app.app_context():
    db.create_all()
    create_admin()

if __name__ == '__main__':
    app.run(debug=True, port=5001) 