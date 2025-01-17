import hashlib
import psycopg2
from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import *
from functools import wraps
from forms import CreatePostForm
import os
# from flask_socketio import SocketIO, emit

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')

# socketio = SocketIO(app)
ckeditor = CKEditor(app)
Bootstrap(app)

# CONNECT TO DB
# app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# to track users logins
login_manager = LoginManager()
login_manager.init_app(app)


# charger un utilisateur à partir de la base de données en utilisant son identifiant
# loading the current user
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


# Create admin-only decorator
def admin_only(f):
    @wraps(f)  # pour préserver le nom et la documentation de la fonction originale dans la fonction décorée
    def decorated_function(*args, **kwargs):
        # If id is not 1 then return abort with 403 error
        if current_user.id != 1:
            return abort(403)
        # Otherwise continue with the route function
        return f(*args, **kwargs)

    return decorated_function


# CONFIGURE TABLES
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    # This will act like a List of BlogPost objects attached to each User.
    # The "author" refers to the author property in the BlogPost class.
    posts = relationship("BlogPost", back_populates="author")
    # this will act like a List of Comments objects attached to each user
    comments = relationship("Comment", back_populates="comment_author")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    # Create Foreign Key, "users.id" the users refers to the tablename of User.
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    # Create reference to the User object, the "posts" refers to the posts protperty in the User class.
    author = relationship("User", back_populates="posts")

    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    comments = relationship("Comment", back_populates="parent_post")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    comment_author = relationship("User", back_populates="comments")

    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")

    text = db.Column(db.Text, nullable=False)


with app.app_context():
    db.create_all()


def add_line_breaks(text, max_length=30):
    """
    Adds a line break after every 'max_length' characters in the given text,
    but doesn't cut a word.

    Args:
        text (str): The input text.
        max_length (int, optional): The maximum length of each line. Defaults to 30.

    Returns:
        str: The text with line breaks added.
    """
    words = text.split()
    result = ''
    current_line = ''

    for word in words:
        if len(current_line + word) > max_length:
            result += current_line.strip() + '\n'
            current_line = word + ' '
        else:
            current_line += word + ' '

    if current_line:
        result += current_line.strip()

    return result

# Fonction personnalisée pour le hachage MD5 pour le gravatar images
@app.template_filter('md5')
def md5_filter(value):
    return hashlib.md5(value.encode('utf-8')).hexdigest()


# to emit comments in real time to all users
# @socketio.on('comment_added')
# def handle_comment_added(comment):
#     comment_data = {
#         'author': comment['author'],
#         'text': comment['text'],
#         'author_email': comment['author_email'],
#         'gravatar_url': get_gravatar_url(comment['author_email'])
#     }
#     print("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
#     emit('comment_added', comment_data, broadcast=True)
#
#
# def get_gravatar_url(email):
#     email_hash = hashlib.md5(email.encode('utf-8')).hexdigest()
#     size = 200
#     default_image = 'identicon'
#     return f'https://www.gravatar.com/avatar/{email_hash}?d={default_image}&s={size}'


@app.route('/')
def get_all_posts():
    if not hasattr(get_all_posts, 'is_called'):
        # First time the function is called
        setattr(get_all_posts, 'is_called', True)
        user = None
    else:
        user = current_user
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, current_user=user)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        user = User.query.filter_by(email=email).first()
        # Email doesn't exist
        if not user:
            flash("That email does not exist, please try again.")
        # Password incorrect
        elif not check_password_hash(user.password, password):
            flash('Password incorrect, please try again.')
        else:
            login_user(user)
            return redirect(url_for('get_all_posts'))
    return render_template("login.html", form=form, current_user=current_user)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    return render_template("about.html", current_user=current_user)


@app.route("/contact")
def contact():
    users = User.query.all()
    return render_template("contact.html",
                           current_user=current_user,
                           users=users,
                           number_user=User.query.count(),
                           number_comment=Comment.query.count(),
                           number_post=BlogPost.query.count())


#  ....................   POST   ...........................


@app.route("/new-post", methods=['GET', 'POST'])
@login_required  # only user will add blogs
def add_new_post():
    form = CreatePostForm(
        img_url='https://static.vecteezy.com/system/resources/thumbnails/030/353/225/small_2x/beautiful-night-sky-background-ai-generated-photo.jpg'
    )
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, edit=False)


@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    form = CommentForm()
    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to login or register to comment.")
            return redirect(url_for("login"))

        new_comment = Comment(
            text=form.comment.data,
            comment_author=current_user,
            parent_post=requested_post
        )
        db.session.add(new_comment)
        db.session.commit()
        form.comment.data = ''
    return render_template("post.html", form=form, post=requested_post, current_user=current_user)


@app.route("/edit-post/<int:post_id>", methods=['GET', 'POST'])
@login_required
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    if post.author != current_user and current_user.id != 1:
        return redirect(url_for('get_all_posts'))
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, edit=True)


@app.route("/delete/<int:post_id>")
@login_required
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    if post_to_delete.author == current_user or current_user.id == 1:
        # deleting all the comments in the post to delete
        for comment in Comment.query.filter_by(parent_post=post_to_delete).all():
            db.session.delete(comment)
            db.session.commit()
        db.session.delete(post_to_delete)
        db.session.commit()
    return redirect(url_for('get_all_posts'))


#  ....................   USER   ...........................


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hash_and_salted_password = generate_password_hash(
            form.password.data,
            method='pbkdf2:sha256',
            salt_length=8
        )
        if User.query.filter_by(email=form.email.data).first():
            flash("You've already signed up with that email,login instead.")
            return redirect(url_for('login'))
        if User.query.filter_by(name=form.name.data).first():
            flash('Name unavailable,already taken.')
            return redirect(url_for('register'))
        new_user = User(
            email= form.email.data,
            name=form.name.data,
            password=hash_and_salted_password,
        )
        db.session.add(new_user)
        db.session.commit()
        # Log in and authenticate user after adding details to database.
        login_user(new_user)
        return redirect(url_for('get_all_posts'))
    return render_template("register.html", form=form, current_user=current_user, edit=False)


@app.route("/edit-user/<int:user_id>", methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if user_id == 1:
        return redirect(url_for('get_all_posts'))
    if current_user.id != 1 and current_user.id != user_id:
        return redirect(url_for('get_all_posts'))
    user_to_edit = User.query.get(user_id)
    form = RegisterForm(
        email=user_to_edit.email,
        name=user_to_edit.name
    )
    if form.validate_on_submit():
        hash_and_salted_password = generate_password_hash(
            form.password.data,
            method='pbkdf2:sha256',
            salt_length=8
        )
        user_to_edit.name = form.name.data
        user_to_edit.password = hash_and_salted_password
        user_to_edit.email = form.email.data
        db.session.commit()
        logout_user()  # you first log out the actual user
        # Log in and authenticate user after adding details to database.
        login_user(user_to_edit)
        return redirect(url_for('get_all_posts'))
    return render_template("register.html", form=form, current_user=current_user, edit=True)


@app.route("/delete-user/<int:user_id>")
@login_required
def delete_user(user_id):
    if user_id == 1:
        return redirect(url_for('get_all_posts'))
    if user_id == current_user.id or current_user.id == 1:
        user_to_delete = User.query.get(user_id)
        # deleting all the comments of the user to delete
        for comment in Comment.query.filter_by(comment_author=user_to_delete).all():
            db.session.delete(comment)
            db.session.commit()
        # deleting all the posts of the user
        for post in BlogPost.query.filter_by(author=user_to_delete).all():
            # deleting all comments of each post
            for comment in Comment.query.filter_by(parent_post=post).all():
                db.session.delete(comment)
                db.session.commit()
            db.session.delete(post)
            db.session.commit()
        db.session.delete(user_to_delete)
        db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/reset-user/<int:user_id>")
@admin_only  # only Admins will reset
def reset_user(user_id):
    if user_id == 1:
        return redirect(url_for('get_all_posts'))
    user = User.query.get(user_id)
    hash_and_salted_password = generate_password_hash(
        '0000',
        method='pbkdf2:sha256',
        salt_length=8
    )
    user.password = hash_and_salted_password
    db.session.commit()
    return redirect(url_for('get_all_posts'))


#  ....................   COMMENT   ...........................

@app.route("/delete-comment/<int:comment_id>")
@login_required
def delete_comment(comment_id):
    comment_to_delete = Comment.query.get(comment_id)
    if current_user.id != 1 and current_user.id != comment_to_delete.comment_author.id:
        return redirect(url_for('get_all_posts'))
    post = comment_to_delete.post_id
    db.session.delete(comment_to_delete)
    db.session.commit()
    return redirect(url_for('show_post', post_id=post))


@app.route("/edit-comment/<int:comment_id>", methods=['GET', 'POST'])
@login_required
def edit_comment(comment_id):
    requested_comment = Comment.query.get(comment_id)
    if current_user.id != 1 and current_user.id != requested_comment.comment_author.id:
        return redirect(url_for('get_all_posts'))
    post = requested_comment.parent_post
    form = CommentForm(
        comment=requested_comment.text
    )
    print(requested_comment.text)
    if form.validate_on_submit():
        requested_comment.text = form.comment.data
        db.session.commit()
        return redirect(url_for('show_post', post_id=post.id))
    return render_template("post.html", form=form, post=post, current_user=current_user, edit=True)


if __name__ == "__main__":
    # socketio.run(app, debug=True, allow_unsafe_werkzeug=True)
    app.run(debug=True)
