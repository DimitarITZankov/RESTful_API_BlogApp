from flask import Flask,request
from flask_restful import Api,Resource,reqparse,abort,fields,marshal_with
from flask_sqlalchemy import SQLAlchemy
import os
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash,check_password_hash




#Initialize the flask app
app = Flask(__name__)
api = Api(app)
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(basedir, "database/database.db")}'
#Initialize the database
db = SQLAlchemy(app)
#Flask-Login stuff:
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))



#Create Users Table
class Users(db.Model):
    id = db.Column(db.Integer,primary_key=True,nullable=False,unique=True)
    name = db.Column(db.String(40),nullable=False)
    username = db.Column(db.String(40),unique=True,nullable=False)
    email = db.Column(db.String(40),unique=True,nullable=False)
    password = db.Column(db.String(512),nullable=False)

    def __repr__(self):
        return f"User(name = {self.name},email = {self.email})"

register_args = reqparse.RequestParser()
register_args.add_argument("name",type=str,required=True,help="Please enter your name")
register_args.add_argument("username",type=str,required=True,help="Please enter your username")
register_args.add_argument("email",type=str,required=True,help="Please enter your email")
register_args.add_argument("password",type=str,required=True,help="Please enter your password")
registerFields = {
    "id" : fields.Integer,
    "username" : fields.String,
    "email" : fields.String,
}


#Create main page
class MainPage(Resource):
    def get(self):
        return {"message":"Welcome To Our Main Page"}


class Register(Resource):
    @marshal_with(registerFields)
    def post(self):
        args = register_args.parse_args()
        user = Users.query.filter_by(email=args['email']).first()

        #Checking if the username or the email exists in the database
        if user:
            abort(409,message="User with this email already exist")
        user2 = Users.query.filter_by(username=args['username']).first()
        if user2:
            abort(409,message="User with this username already exist")

        #Generate Hashed Password
        hashed_password = generate_password_hash(args['password'],method="pbkdf2:sha256")
        user = Users(name=args['name'],username=args['username'],
                    email=args['email'],password=hashed_password)

        #Add to the database
        try:
            db.session.add(user)
            db.session.commit()
        except Exception as e:
            print(e)
            return {"message":"Something went wrong with the database, please try again"}, 500

        return user,201
































#Adding resources (the routes)
api.add_resource(MainPage, '/')
api.add_resource(Register, '/register')


#App Runner
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
