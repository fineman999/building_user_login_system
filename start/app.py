import pathlib
from flask import Flask, render_template,request,redirect,url_for, make_response,jsonify,session,flash,abort
from flask_cors import CORS
from flask_bootstrap import Bootstrap
from site_control.user_mgmt import User
from flask_login import current_user, login_required, login_user,LoginManager, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
import datetime

from google_auth_oauthlib.flow import Flow
from google.oauth2 import id_token
from pip._vendor import cachecontrol
import google.auth.transport.requests
import requests
import os

app = Flask(__name__)
app.secret_key ="hottofixit123"
app.permanent_session_lifetime = datetime.timedelta(minutes=30)
Bootstrap(app)
CORS(app)

# https 만을 지원하는 기능을 http에서 테스트할 때 필요한 설정
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.session_protection = 'strong'
login_manager.login_view='login'


@app.before_request
def app_before_request():
    if 'client_id' not in session:
        session['client_id'] = request.environ.get('HTTP_X_REAL_IP',request.remote_addr)
        
        
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
            session['username'] = request.form['username']
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
    return render_template('signup.html')


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html',name = current_user.username)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('username',None)
    return redirect(url_for('index'))



#---------------------------------------------
GOOGLE_CLIENT_ID = "331035226120-tvkjug28vq65n89mf4c9bnfl8fu9i52o.apps.googleusercontent.com"
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "./google/client_secret.json")

flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri="http://127.0.0.1:5000/callback"
)

@app.route("/googlelogin",methods=['GET','POST'])
def googlelogin():
    authorization_url, state = flow.authorization_url()
    session['state'] = state
    return redirect(authorization_url)

@app.route("/callback")
def callback():
    flow.fetch_token(authorization_response=request.url)
    if not session['state'] == request.args['state']:
        abort(500)  # State does not match!
    
    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
    )
    
    session["username"] = id_info.get("name")
   
    hashed_password = generate_password_hash(id_info.get("sub"), method = 'sha256')
    user = User.create(id_info.get("name"),id_info.get("email"),hashed_password)
    if user is None:
        user = User.find(id_info.get("name"))
        
        print('---------------------')
        login_user(user, remember = True,duration = datetime.timedelta(days=365))
        return redirect(url_for('dashboard'))
    login_user(user, remember = True,duration = datetime.timedelta(days=365))
    return redirect(url_for('dashboard'))


if __name__ == '__main__':
    app.run(debug=True)