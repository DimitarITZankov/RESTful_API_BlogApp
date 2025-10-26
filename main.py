from flask import Flask,request
from flask_restful import Api,Resource,reqparse,abort,fields,marshal_with
from flask_sqlalchemy import SQLAlchemy
import os
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash,check_password_hash
from datetime import datetime
from flask_migrate import Migrate



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
@login_manager.unauthorized_handler
def unauthorized():
    # This is called whenever a non-logged-in user tries to access @login_required
    return {"message": "You must be logged in to perform this action"}, 401
#Create secret key for flask-login
app.secret_key = os.urandom(24)
migrate = Migrate(app,db)



#Create Users Table
class Users(db.Model,UserMixin):
    id = db.Column(db.Integer,primary_key=True)
    name = db.Column(db.String(40),nullable=False)
    username = db.Column(db.String(40),unique=True,nullable=False)
    email = db.Column(db.String(40),unique=True,nullable=False)
    password = db.Column(db.String(512),nullable=False)
    posts = db.relationship('Posts',backref='poster')

    def __repr__(self):
        return f"User(name = {self.name},email = {self.email})"


#Create Posts Table
class Posts(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    title = db.Column(db.String,nullable=False)
    content = db.Column(db.Text,nullable=False)
    date_posted = db.Column(db.DateTime, default=datetime.utcnow)
    poster_id = db.Column(db.Integer,db.ForeignKey('users.id'), nullable=False)

    def __repr__(self):
        return f"Post(title={self.title}, poster_id={self.poster_id})"






#Register Arguments
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

#Login Arguments
login_args = reqparse.RequestParser()
login_args.add_argument("username",type=str,required=True,help="Please enter your username")
login_args.add_argument("password",type=str,required=True,help="Please enter your password")

#AddPost Arguments
addpost_args = reqparse.RequestParser()
addpost_args.add_argument("title",type=str,required=True,help="Enter title of the post")
addpost_args.add_argument("content",type=str,required=True,help="Tell us your story ..")
addpostFields = {
    "id" : fields.Integer,
    "title" : fields.String,
    "content" : fields.String,
    "poster_name" : fields.String(attribute="poster.username"),
    "date_posted": fields.DateTime
}


#Create Main Page
class MainPage(Resource):
    def get(self):
        return {"message":"Welcome To Our Main Page"}

# Register endpoint: handles user registration
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

#Login endpoint: handles user loging
class Login(Resource):
    def post(self):
        args = login_args.parse_args()
        user = Users.query.filter_by(username=args['username']).first()
        if not user:
            return {"message":"The user doesn't exist"}
        if check_password_hash(user.password,args['password']):
            login_user(user)
            return {"message": f"Welcome back {user.name}","id": user.id,
                    "username": user.username,"email": user.email}, 200
        else:
            return {"message":"Invalid username or password"}, 401

#Logout endpoint
class Logout(Resource):
    @login_required
    def post(self):
        logout_user()
        return {"message": "Logged out successfully"}, 200

#Add Post endpoint: handles adding posts
class AddPost(Resource):
    @login_required
    @marshal_with(addpostFields)
    def post(self):
        args = addpost_args.parse_args()
        post = Posts(title=args['title'],content=args['content'],poster_id=current_user.id)
        db.session.add(post)
        db.session.commit()
        posts = Posts.query.all()
        return posts,201

#View Post endpoint: View every post by it's ID 
class Post(Resource):
    @marshal_with(addpostFields)
    def get(self,id):
        post = Posts.query.filter_by(id=id).first()
        if not post:
            abort(404, message=f"Post with ID {id} doesn't exist")
        else:
            return post,200


#Edit Post endpoint: Only the poster of the post, can edit this post
class EditPost(Resource):
    @login_required
    def patch(self,id):
        post = Posts.query.filter_by(id=id).first()
        if not post:
            abort(404, message="Post not found")
        if current_user.id != post.poster_id:
            abort(403, message="You do not have permission to edit this post")
        post.title = args['title']
        post.content = args['content']
        db.session.commit()
        return {"message":f"Post with ID {id} has been edited successfully"}


#Delete Post endpoint: Only the poster of the post can delete this post
class DeletePost(Resource):
    @login_required
    def delete(self,id):
        post = Posts.query.filter_by(id=id).first()
        if not post:
            abort(404, message="Post not found")
        if current_user.id != post.poster_id:
            abort(403, message="You do not have permission to delete this post")
        db.session.delete(post)
        db.session.commit()
        return {"message":f"Post with ID {id} has been deleted successfully"}































#Adding resources (the routes)
api.add_resource(MainPage, '/')
api.add_resource(Register, '/register')
api.add_resource(Login, '/login')
api.add_resource(Logout, '/logout')
api.add_resource(AddPost, '/add_post')
api.add_resource(Post, '/post/<int:id>')
api.add_resource(EditPost, '/edit_post/<int:id>')
api.add_resource(DeletePost, '/delete_post/<int:id>')



#App Runner
if __name__ == "__main__":
    app.run(debug=True)


#Temporary ready to copy-paste input
'''{
    "name": "Dimitar",
    "username": "dimitar123",
    "email": "dimitar@example.com",
    "password": "secret123"
}'''