from flask import Flask, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar


app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


# -------------------- DB TABLES -------------------- #
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    # the following lines tell the db that this new column BlogPost.author links to User.posts
    author = relationship("User", back_populates="posts")
    comments = relationship("Comment", back_populates="post")
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), nullable=False, unique=True)
    password_hash = db.Column(db.String(250), nullable=False)
    username = db.Column(db.String(250), nullable=False)
    # this next row tells the DB that this table is linked to the BlogPost table
    # and that this "posts" column is connected to the "author" column of that table.
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="commenter")


class Comment(UserMixin, db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(2000), nullable=False, unique=False)
    post = relationship("BlogPost", back_populates="comments")
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    commenter = relationship("User", back_populates="comments")
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
db.create_all()


# -------------------- FLASK LOGIN -------------------- #
login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# -------------------- DB ACCESSORS -------------------- #
def add_user(form: RegisterForm):
    with app.app_context():
        user_email = form["email"]
        user_password = form["password"]
        user_name = form["username"]

        print(f"New user's password: {user_password}")
        # check if the email is already in use
        matching_email = User.query.filter_by(email=user_email).first()
        if matching_email is not None:
            flash("This email address is already associated with a user.")
            return False

        # check if the email is already in use
        matching_username = User.query.filter_by(username=user_name).first()
        if matching_username is not None:
            flash("This username is already associated with a user.")
            return False

        hashed_password = generate_password_hash(user_password)
        print(f"New user's hashed password: {hashed_password}")

        new_user = User(email=user_email, username=user_name, password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return True


def validate_login(form: LoginForm) -> User:
    input_email = form["email"]
    input_password = form["password"]

    # validate email address exists in db
    existing_user = User.query.filter_by(email=input_email).first()
    if existing_user is None:
        flash("No users registered with this email.")
        return None
    else:
        # validate password
        user_hashed_password = existing_user.password_hash
        valid_password = check_password_hash(pwhash=user_hashed_password, password=input_password)
        if valid_password:
            return existing_user
        else:
            flash("Incorrect password.")
            return None


def add_comment(form: CommentForm, post_id: int):
    comment_body = form.text.data
    new_comment = Comment(text=comment_body
                          , post_id=post_id
                          , user_id=current_user.id)
    db.session.add(new_comment)
    db.session.commit()


# -------------------- ROUTES -------------------- #
@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if request.method == "POST" and form.validate_on_submit():
        success = add_user(request.form)
        if success:
            return redirect(url_for("get_all_posts"))
    return render_template("register.html", form=form)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if request.method == "POST" and form.validate_on_submit():
        validated_user = validate_login(request.form)
        if validated_user is not None:
            login_user(validated_user)
            return redirect(url_for("get_all_posts"))
    return render_template("login.html", form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    comment_form = CommentForm()
    requested_post = BlogPost.query.get(post_id)
    if request.method == "POST" and comment_form.validate_on_submit():
        add_comment(comment_form, post_id)
    return render_template("post.html", post=requested_post, comment_form=comment_form)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=["POST", "GET"])
@login_required
def add_new_post():
    form = CreatePostForm()
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
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@login_required
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        # author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        # post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@login_required
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)
