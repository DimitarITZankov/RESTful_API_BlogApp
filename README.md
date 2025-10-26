RESTful API Blog Application

A comprehensive RESTful API built using Python's Flask framework, enabling users to register, authenticate, create and manage posts, and interact through comments. This project demonstrates the implementation of CRUD operations, user authentication, and authorization in a backend environment.

=== Features ===

User Authentication: Secure user registration and login with password hashing and session management.

Post Management: Create, edit, and delete blog posts.

Comment System: Add, view, and delete comments on posts.

User Profile: View and edit user information, including name, username, and email.

Authorization: Role-based access control ensuring users can only modify their own data.

Database Integration: Utilizes SQLAlchemy with SQLite for data storage.

=== Technologies Used ===

Backend Framework: Flask

Database: SQLite (via SQLAlchemy)

Authentication: Flask-Login

Password Security: Werkzeug Security

API Documentation: Flask-RESTful

Database Migration: Flask-Migrate

=== Installation ===
1. Clone the repository:
   -git clone https://github.com/DimitarITZankov/RESTful_API_BlogApp.git
   -cd RESTful_API_BlogApp

2. Set up a virtual environment:
   -python -m venv venv
   -source venv/bin/activate  # On Windows, use `venv\Scripts\activate`

3.Install dependencies:
  -pip install -r requirements.txt

4.Set up the database:
  -flask db init
  -flask db migrate
  -flask db upgrade

5.Run the application:
  -flask run


=== API Endpoints ===
== User Endpoints ==

POST /register: Register a new user.

POST /login: Log in an existing user.

POST /logout: Log out the current user.

PATCH /edit_user/<id>: Edit user profile information.

DELETE /delete_user/<id>: Delete user account and associated posts.

== Post Endpoints ==

POST /add_post: Create a new blog post.

GET /post/<id>: Retrieve a specific post by ID.

PATCH /edit_post/<id>: Edit an existing post.

DELETE /delete_post/<id>: Delete a post.

== Comment Endpoints ==

POST /post/<id>/add_comment: Add a comment to a post.

GET /post/<id>/comments: Retrieve all comments for a post.

DELETE /comment/<comment_id>/delete: Delete a specific comment.

== Dashboard ==

GET /dashboard: View user profile and all associated posts.
