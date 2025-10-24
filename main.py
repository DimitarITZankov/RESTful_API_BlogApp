from flask import Flask,request
from flask_restful import Api,Resource,reqparse,abort,fields,marshal_with

#Initialize the flask app
app = Flask(__name__)
api = Api(app)

#Create main page
class MainPage(Resource):
    def get(self):
        return {"message":"Welcome To Our Main Page"}



#Adding resources (the routes)
api.add_resource(MainPage, '/')
