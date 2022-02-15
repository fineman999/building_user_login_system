from flask import Flask, render_template,request,redirect,url_for, make_response,jsonify,session,flash
from flask_cors import CORS
from flask_bootstrap import Bootstrap
from site_control.user_mgmt import User
from flask_login import current_user, login_required, login_user,LoginManager, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
import datetime

app = Flask(__name__)
app.secret_key ="hottofixit123"
app.permanent_session_lifetime = datetime.timedelta(minutes=30)
Bootstrap(app)
CORS(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.session_protection = 'strong'
login_manager.login_view='login'

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/dologin',methods=['GET','POST'])
def dologin():
    user = User.find(request.form['username'])
    if user !=None:
        if check_password_hash(user.passwords,request.form['password']):
            login_user(user,remember=request.form.get('remember'))
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid password")
            return  redirect(url_for('login'))
    flash("Invalid username")
    return  redirect(url_for('login'))
   

@app.route('/login')
def login():
    return render_template('login.html')


@app.route('/set',methods=['GET','POST'])
def set():
    hashed_password = generate_password_hash(request.form['password'], method = 'sha256')
    user = User.create(request.form['username'],request.form['email'],hashed_password)
    if user is None:
        flash("중복된 이메일 주소입니다.")
        print('---------------------')
        return redirect(url_for('signup'))
    login_user(user, remember = True,duration = datetime.timedelta(days=365))
    return redirect(url_for('dashboard'))


@app.route('/signup')
def signup():    
    ''' if request.method == "POST":
        hashed_password = generate_password_hash(request.form['password'], method = 'sha256')
        user = User.create(request.form['username'],request.form['email'],hashed_password)
        if user is None:
            flash("중복된 이메일 주소입니다.")
            print('---------------------')
            return render_template('signup.html')
        login_user(user, remember = True,duration = datetime.timedelta(days=365))
        return redirect(url_for('dashboard'))'''
    return render_template('signup.html')


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html',name = current_user.username)

@app.route('/indexx')
def indexx():
    flash('warning','info')
    return render_template('index.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))
if __name__ == '__main__':
    app.run(debug=True)