from flask import Flask, render_template,request,redirect,url_for, make_response,jsonify,session
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from site_control.user_mgmt import User
from flask_login import login_user,LoginManager
import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] ="hottofixit123"
bootstrap=Bootstrap(app)

class LoginForm(FlaskForm):
    username = StringField('username', validators = [InputRequired(), Length(min=4,max = 15)])
    password = PasswordField('password', validators=[InputRequired(),Length(min=8,max=80)])
    remember = BooleanField('remember me')
    
class RegisterForm(FlaskForm):
    email = StringField('email', validators = [InputRequired(), Email(message="Invalide email"),Length(max=50)])
    username = StringField('username', validators = [InputRequired(), Length(min=4,max = 15)])
    password = PasswordField('password', validators=[InputRequired(),Length(min=8,max=80)])
  

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.session_protection = 'strong'

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)


@login_manager.unauthorized_handler
def unauthorized():
    return make_response(jsonify(success=False),401)

@app.before_request
def app_before_request():
    if 'client_id' not in session:
        session['client_id'] = request.environ.get('HTTP_X_REAL_IP',request.remote_addr)
      
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login',methods=['GET','POST'])
def login():
    form = LoginForm()
    
    if form.validate_on_submit():
        print("Ok")
        return '<h1>' +form.username.data + ' ' + form.password.data +'</h1>'
    return render_template('login.html',form = form)

@app.route('/set',methods=['GET','POST'])
def set():
    print('hahaha',request.headers)
    print('haha',request.form)
    
    user = User.create(request.form['username'],request.form['email'],request.form['password'])
    return '<h1> succed</h1>'
    #login_user(user, remember = True,duration = datetime.timedelta(days=365))
    #return redirect(url_for('blog.blog_fullstack1'))


@app.route('/signup')
def signup():    
    return render_template('signup.html')


@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

if __name__ == '__main__':
    app.run(debug=True)