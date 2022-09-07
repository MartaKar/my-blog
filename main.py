import werkzeug
from flask import Flask, render_template, redirect, flash, url_for, abort, request
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, URL, Email
from flask_ckeditor import CKEditor, CKEditorField
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from functools import wraps
from werkzeug.security import generate_password_hash
import datetime





app = Flask(__name__)
app.config['SECRET_KEY'] = "verysecretkey"
ckeditor = CKEditor(app)
Bootstrap(app)


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog_data.db?check_same_thread=False'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)

class User(UserMixin, db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), nullable=False)
    password = db.Column(db.String(250), nullable=False)
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="comment_author")



class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    author = relationship("User", back_populates="posts")
    comments = relationship("Comment", back_populates="parent_post")



class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(250), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    date = db.Column(db.String(250), nullable=False)
    comment_author = relationship("User", back_populates="comments")
    post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))
    parent_post = relationship("BlogPost", back_populates="comments")
    fans = relationship("Fan", back_populates="parent_comment")
    likes = db.Column(db.Integer, nullable=False, default=0)

class Fan(db.Model):
    __tablename__ = "fans"
    id = db.Column(db.Integer, primary_key=True)
    comment_id = db.Column(db.Integer, db.ForeignKey('comments.id'))
    parent_comment = relationship("Comment", back_populates="fans")
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))

db.create_all()

class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")


class CreateCommentForm(FlaskForm):
    body = CKEditorField("Comment", validators=[DataRequired()])
    submit = SubmitField("Submit")

class RegisterForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Sign me up")


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Let me in")

class ContactForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired()])
    body = CKEditorField("Message", validators=[DataRequired()])
    submit = SubmitField("Send")


posts = db.session.query(BlogPost).all()

@app.route("/")
def home():
    descending = BlogPost.query.order_by(BlogPost.id.desc())
    last_item = descending.first()
    return render_template("index.html", all_posts=posts, big_post=last_item, logged_in=current_user.is_authenticated)


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.id == 1:
            return abort(403)
        return f(*args, **kwargs)
    return decorated_function


@app.route("/new", methods=['GET', 'POST'])
@admin_only
def new_post():
    post_form = CreatePostForm()
    if post_form.validate_on_submit():
        add_new_post = BlogPost(
            title=post_form.title.data,
            img_url=post_form.img_url.data,
            subtitle=post_form.subtitle.data,
            date=datetime.datetime.now().strftime("%B %d, %Y"),
            body=post_form.body.data,
            author=current_user
        )
        db.session.add(add_new_post)
        db.session.commit()
        return redirect('/')
    return render_template("create_post.html", form=post_form)


@app.route("/contact")
def contact():
    form = ContactForm()
    return render_template("contact.html", form=form)


@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
def show_post(post_id):
    chosen_post = BlogPost.query.get(post_id)
    all_comments = Comment.query.all()
    form = CreateCommentForm()
    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("Log in or register in order to comment this post")
        new_comment = Comment(
            text=form.body.data,
            comment_author=current_user,
            parent_post=chosen_post,
            date=datetime.datetime.now().strftime("%B %d, %Y"),
        )
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for("show_post", post_id=post_id))
    return render_template("single_post.html", post=chosen_post, form=form, comments=all_comments)



@app.route("/add_like",  methods=['GET','POST'])
def like():
    output = request.get_json()
    # print(output)
    comment_id = output["commentId"]
    # print(type(comment_id))
    author_id = output["authorId"]
    # print(current_user.id)
    user = Fan.query.filter_by(author_id=author_id).first()
    comment_liked = Comment.query.get(comment_id)
    if user:
        fan_to_delete = Fan.query.get(author_id)
        comment_liked.likes -= 1
        db.session.delete(fan_to_delete)
        db.session.commit()

    else:
        new_fan = Fan(
            comment_id=comment_id,
            author_id=author_id
        )
        comment_liked.likes += 1
        db.session.add(new_fan)
        db.session.commit()
    # count = Fan.query.filter_by(comment_id=comment_id).count()
    return {"like_count": comment_liked.likes}






@app.route("/delete/<int:post_id>")
@admin_only
def delete(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect('/')


@app.route("/edit/<int:post_id>", methods=['GET', 'POST'])
@admin_only
def edit(post_id):
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
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("home", post_id=post.id))
    return render_template("create_post.html", form=edit_form)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route("/login", methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = User.query.filter_by(email=email).first()
        if not user:
            print("dupa")
            flash("This email does not exist, please try again")
        elif not werkzeug.security.check_password_hash(user.password, password):
            flash("Wrong password, please try again")
        else:
            login_user(user)
            return redirect(url_for('home'))
    return render_template("login.html", form=form)


@app.route("/logout")
def logout():
    logout_user()
    return redirect('/')



@app.route("/register", methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            flash("Email already in database")
        else:
            new_user = User(
                name=form.name.data,
                email=form.email.data,
                password=werkzeug.security.generate_password_hash(password=form.password.data, method='pbkdf2:sha256',
                                                                  salt_length=8)
            )
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect("/")
    return render_template("register.html", form=form)

if __name__ == '__main__':
    app.run(debug=True)

