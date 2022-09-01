from flask import Flask, render_template, redirect, url_for, flash, abort, request
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps
import smtplib
import os
from email_validator import validate_email, EmailNotValidError

MY_EMAIL = "pythoncoursea@gmail.com"
PASSWORD = "zftadfdvngefnegr"

Base = declarative_base()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
ckeditor = CKEditor(app)
Bootstrap(app)

login_manager = LoginManager()
login_manager.init_app(app)


gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)



@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL", "sqlite://blog.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


##CONFIGURE TABLES

class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))
    is_admin = db.Column(db.Integer)
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="comment_author")




class BlogPost(db.Model, Base):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)

    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    author = relationship("User", back_populates="posts")

    comments = relationship("Comment", back_populates="parent_post")

    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)


class Comment(db.Model, Base):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    comment_author = relationship("User", back_populates="comments")
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")
    text = db.Column(db.Text, nullable=False)


db.create_all()


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.is_anonymous or current_user.is_admin != 1:
            return abort(403)

        return f(*args, **kwargs)
    return decorated_function



@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        email = form.email.data,
        password = generate_password_hash(password=form.password.data, method="pbkdf2:sha256", salt_length=8),
        name = form.name.data


        try:
            email = validate_email(email).email
        except EmailNotValidError:
            flash("Invalid Email Address")
            return redirect(url_for('register'))
        else:
            new_user = User(email, password, name)
            check_if_exist = User.query.filter_by(email=form.email.data).first()
            if check_if_exist is not None:
                flash("You've already signed up with that email, log in instead!")
                return redirect(url_for('login'))
            else:
                db.session.add(new_user)
                db.session.commit()
                login_user(new_user)
                send_email_to_new_user(new_user)
                return redirect(url_for('get_all_posts'))
    return render_template("register.html", form=form)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user_found = User.query.filter_by(email=form.email.data).first()
        if user_found is None:
            flash("This email does not exist, Please Try again.")
            return redirect(url_for('login'))
        elif not check_password_hash(user_found.password, form.password.data):
            flash("Incorrect password, Please Try again")
        else:
            login_user(user_found)
            return redirect(url_for('get_all_posts'))
    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    form = CommentForm()
    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to login or register to comment")
            return redirect(url_for('login'))
        else:
            new_comment = Comment(
                text=form.text.data,
                comment_author=current_user,
                parent_post=requested_post
            )
            db.session.add(new_comment)
            db.session.commit()
            form.text.data = ""
    return render_template("post.html", post=requested_post, form=form, gravatar=gravatar)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        data = request.form
        user_details = f"Name: {data['name']}\n" \
                       f"Email: {data['email']}\n" \
                       f"Phone number: {data['phone']}\n" \
                       f"Message: {data['message']}\n"

        with smtplib.SMTP("smtp.gmail.com") as connection:
            connection.starttls()
            connection.login(user=MY_EMAIL, password=PASSWORD)
            connection.sendmail(from_addr=MY_EMAIL, to_addrs="omrip500@gmail.com",
                                msg=f"Subject: User Deatils\n\n{user_details}")

        return render_template("contact.html", request_type=request.method)

    return render_template("contact.html", request_type=request.method)


@app.route("/new-post", methods=["GET", "POST"])
@admin_required
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y"),
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)



@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_required
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
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

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_required
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))

@app.route("/users")
@admin_required
def users():
    al_users = db.session.query(User).all()
    return render_template("users.html", users=al_users[1::])

@app.route("/set-or-remove-admin/<user_id>/<mode>")
@admin_required
def set_or_remove_admin(user_id, mode):
    user_to_change_method = User.query.get(user_id)
    if mode == "make_admin":
        user_to_change_method.is_admin = 1
    else:
        user_to_change_method.is_admin = None
    db.session.commit()
    return redirect(url_for('users'))


def send_email_to_new_user(user):
    with open("letters/register_letter.txt") as letter:
        new_letter = letter.read()
        new_letter = new_letter.replace("[name]", user.name.capitalize())

    with smtplib.SMTP("smtp.gmail.com") as connection:
        connection.starttls()
        connection.login(user=MY_EMAIL, password=PASSWORD)
        connection.sendmail(from_addr=MY_EMAIL, to_addrs=user.email,
                            msg=f"Subject: Welcome To Our Blog\n\n{new_letter}")




if __name__ == "__main__":
    app.run(debug=True, host="10.0.0.7", port=5000)
