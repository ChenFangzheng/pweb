from flask import render_template, request, url_for, redirect, flash
from flask_login import login_user, current_user, login_required, logout_user
from . import auth
from .form import LoginForm
from ..models import User


@auth.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me)
            next_url = request.args.get('next')
            if next_url is None or not next_url.startswith('/'):
                next_url = url_for('main.index')
            return redirect(next_url)
        flash('用户名或密码错误！')
    return render_template('auth/login.html', form=form)


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    flash('你已经登出系统！')
    return redirect(url_for('auth.login'))
