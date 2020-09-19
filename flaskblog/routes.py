import os
import secrets
from PIL import Image
from flask import render_template, abort, url_for, flash, redirect, request
from flaskblog import app, db, bcrypt, mail
from flaskblog.forms import RegistrationForm, RequestResetForm, ResetPasswordForm, LoginForm, UpdateAccountForm, PostForm
from flaskblog.models import User, Post
from flask_login import login_user, current_user, logout_user, login_required
from flask_mail import Message

# def AdminRequired(original_function):
#     def WrapperFunc(*args, **kwargs):
#         if current_user.isadmin or original_function.__name__== url_for :
#             return original_function(*args, **kwargs)
#         else:
#             return abort(401)
#     return WrapperFunc
# ALLOWED_EXTENSIONS = ['']
# def allowed_file(filename):
#     return '.' in filename and \
#            filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS




@app.route('/')


@app.route('/home')
def home():
    page= request.args.get('page', 1, type=int)
    yolla = Post.query.filter_by(isverified=True).order_by(Post.date_posted.desc()).paginate(page=page, per_page=3)
    return render_template('home.html', posts=yolla)


@app.route('/unverified', methods=['GET','POST'])
# @AdminRequired
def unverified():
    page= request.args.get('page', 1, type=int)
    yolla = Post.query.filter_by(isverified = False).order_by(Post.date_posted.desc()).paginate(page=page, per_page=3)
    return render_template('unverified.html', posts=yolla)



@app.route('/about')
def about():
    return render_template('about.html', title='AASD')

@app.route('/register', methods=['GET','POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            user = User(username=form.username.data, email=form.email.data, password=hashed_password)
            db.session.add(user)
            db.session.commit()
            flash('Hesabınız oluşturuldu','success')
            return redirect(url_for('login'))
    return render_template('register.html', title = 'Register', form=form)

@app.route('/login', methods=['GET','POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash('Hatalı Giriş.', 'danger')


    return render_template('login.html', title = 'Login', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


def save_picture(form_picture):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.root_path, 'static/profile_pics' , picture_fn)
    
    output_size = (125, 125)
    i = Image.open(form_picture)
    i.thumbnail(output_size)
    i.save(picture_path)

    return picture_fn
    
def save_file(form_file):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_file.filename)
    file_fn = random_hex + f_ext
    file_path = os.path.join(app.root_path, 'static/files', file_fn)
    form_file.save(file_path)

    return file_fn

@app.route('/account', methods=['GET','POST'])
@login_required
def account():
    form = UpdateAccountForm()
    if form.validate_on_submit():
        if form.picture.data:
            picture_file=save_picture(form.picture.data)
            current_user.image_file = picture_file

        current_user.username = form.username.data
        current_user.email = form.email.data
        db.session.commit()
        flash(form.picture.data.filename, 'success')
        return redirect(url_for('account'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
    image_file = url_for('static', filename='profile_pics/' + current_user.image_file)
    return render_template('account.html', title='Account', image_file = image_file, form=form)


@app.route('/post/new', methods=['GET','POST'])
@login_required
def new_post():
    form = PostForm()
    if form.validate_on_submit():
        if form.dosya.data:
            document_file = save_file(form.dosya.data)
            post = Post(title=form.title.data, content = form.content.data, author = current_user, doc_file = document_file)
        else:
            post = Post(title=form.title.data, content=form.content.data, author=current_user)
        db.session.add(post)
        db.session.commit()
        if current_user.isadmin==True:
            post.isverified = True
            db.session.commit()        
        flash("Gönderi Başarılı" , 'success')
        return redirect(url_for('home'))
    return render_template('create_post.html', title = "New Post", form=form, legend="New Post")


@app.route('/post/<int:post_id>')
def post(post_id):
    post= Post.query.get_or_404(post_id)
    return render_template('post.html', title=post.title, post=post)


@app.route('/post/<int:post_id>/update', methods=['GET','POST'])
@login_required
def update_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user and current_user.isadmin == False:
        abort(403)
    form = PostForm()
    if form.validate_on_submit():
        post.title=form.title.data
        post.content=form.content.data
        db.session.commit()
        flash('Gönderi Güncellendi', 'success')
        return redirect(url_for('post', post_id = post.id))
    elif request.method == 'GET':
        form.title.data = post.title
        form.content.data = post.content
    return render_template('create_post.html', title = "Edit Post", form=form, legend="Update Post")

@app.route('/post/<int:post_id>/delete', methods=['POST'])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user and current_user.isadmin == False:
        abort(403)
    if post.doc_file:
        os.remove(os.path.join(app.root_path, "static/files", post.doc_file))
    db.session.delete(post)
    db.session.commit()
    flash('Gönderi silindi', 'info')
    return redirect(url_for('home'))

@app.route('/post/<int:post_id>/unverify', methods=['POST'])
@login_required
def unverify_post(post_id):
    post = Post.query.get_or_404(post_id)
    if current_user.isadmin == False:
        abort(403)
    db.session.delete(post)
    db.session.commit()
    flash('Gönderi silindi', 'info')
    return redirect(url_for('unverified'))

@app.route('/post/<int:post_id>/verify', methods=['POST','GET'])
@login_required
def verify_post(post_id):
    post = Post.query.get_or_404(post_id)
    if current_user.isadmin == False:
        abort(404)
    post.isverified = True
    db.session.commit()
    return redirect(url_for('unverified'))


@app.route('/user/<string:username>')
def user_posts(username):
    page= request.args.get('page', 1, type=int)
    user= User.query.filter_by(username=username).first_or_404()
    if current_user.is_authenticated:
        if current_user.isadmin == True:
            yolla= Post.query.filter_by(author=user).order_by(Post.date_posted.desc()).paginate(page=page, per_page=5)
        else:
            yolla = Post.query.filter_by(author=user,isverified = True).order_by(Post.date_posted.desc()).paginate(page=page, per_page=5)
    else:
        yolla = Post.query.filter_by(author=user,isverified = True).order_by(Post.date_posted.desc()).paginate(page=page, per_page=5)
    return render_template('user_posts.html', posts=yolla, user=user)

def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message('Şifre sıfırlama isteği', sender='noreply@demo.com', recipients=[user.email])
    msg.body= f''' Şifrenizi sıfırlamak için tıkklayın:
{url_for('reset_token', token=token, _external=True)}


    Bu isteği siz yapmadıysanız lütfen dikkate almayın.
'''
    mail.send(msg)

@app.route('/reset_password', methods=['GET','POST'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form=RequestResetForm()
    if form.validate_on_submit():
        user=User.query.filter_by(email=form.email.data).first()
        send_reset_email(user)
        flash('Mail adresinizi kontrol edin','info')
        return redirect(url_for('login'))
    return render_template('reset_request.html', title='Şifreyi Sıfırla', form=form)

@app.route('/reset_password/<token>', methods=['GET','POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    user = User.verify_reset_token(token)
    if user is None:
        flash('Geçersiz kod', 'warning')
        return redirect(url_for('reset_request'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            user.password = hashed_password
            db.session.commit()
            flash('Şifreniz değiştirildi, giriş yapabilirsiniz.','success')
            return redirect(url_for('login'))
    return render_template('reset_token.html', title = 'Şifreyi sıfırla', form=form)