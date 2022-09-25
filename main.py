from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
import sqlalchemy
from sqlalchemy import Table, Column, Integer, String, Date, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
from functools import wraps
import os

# Create admin_only decorator
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # if the login user id is not 1, abort and show page 403
        if current_user.id != 1:
            return abort(403)
        # otherwise continue with the route function
        return f(*args, **kwargs)
    return decorated_function

# Base = declarative_base()


app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("APP_SECRET")
ckeditor = CKEditor(app)
Bootstrap(app)
# To make an image
gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False, force_lower=False, use_ssl=False,
                    base_url=None)

# CONNECT TO DB 'sqlite:///blog.db'
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Declaring the LoginManager
login_manager = LoginManager()
login_manager.init_app(app)


# Mandatory user_loader call back...it takes a string user_id and return the user object from the database
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Creating two tables with one-to-many relation
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    register_date = db.Column(db.Date, nullable=False)
    # This will act like a list of BlogPost objects attached to each User
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="author")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    # Creating a forign key to
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    # Create a reference to the User object, posts refer to posts in User class
    # Note if we use backref instead of back_populates we won't need the following column
    author = relationship("User", back_populates="posts")
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    comments = relationship("Comment", back_populates="post")

class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    c_post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    author = relationship("User", back_populates="comments")
    post = relationship("BlogPost", back_populates="comments")
    body = db.Column(db.Text, nullable=False)


db.create_all()


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        # 1- Check if email exists in the database, if it does direct them to login page
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash("Found a user with this email in our database. Use a different email OR log in.")
            return redirect(url_for('login'))
        # 2- If new user, then hash and salt the password
        hashed_and_salted_password = generate_password_hash(password=form.password.data,
                                                            method="pbkdf2:sha256",
                                                            salt_length=8)
        # 3- Add the user to the database
        new_user = User(name=form.name.data,
                        email=form.email.data,
                        password=hashed_and_salted_password,
                        register_date=date.today())
        db.session.add(new_user)
        db.session.commit()

        # Log in and authenticate user after adding details to the database
        login_user(new_user)
        return redirect(url_for('get_all_posts'))


        # 4- Redirect the user to home page
    return render_template("register.html", form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        logedin_user = User.query.filter_by(email=form.email.data).first()
        # Search by email to see if user exists or not
        if not logedin_user:
            flash("Couldn't find a user with this email address, register first!")
        elif not check_password_hash(logedin_user.password, form.password.data):
            # Check if the password entered matches the password in the database
            flash("Password incorrect, please try again.")
        else:
            # Log in and authenticate user after adding details to the database
            login_user(logedin_user)
            return redirect(url_for('get_all_posts'))
    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    form = CommentForm()
    if form.validate_on_submit():
        # if user is loggedin
        if not current_user.is_active:
            flash("You need to login or register to comment")
            return redirect(url_for("login"))

        new_comment = Comment(
            body=form.comment_body.data,
            author_id=current_user.id,
            c_post_id=post_id)
        db.session.add(new_comment)
        db.session.commit()

    return render_template("post.html", post=requested_post, form=form)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author_id=current_user.id,
            date=date.today().strftime("%B %d, %Y"))
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    if post:
        if post.author.id == current_user.id:
            edit_form = CreatePostForm(
                title=post.title,
                subtitle=post.subtitle,
                img_url=post.img_url,
                author_id=current_user.id,
                body=post.body
            )
            if edit_form.validate_on_submit():
                post.title = edit_form.title.data
                post.subtitle = edit_form.subtitle.data
                post.img_url = edit_form.img_url.data
                post.author_id = current_user.id
                post.body = edit_form.body.data
                db.session.commit()
                return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='localhost', port=5000)
