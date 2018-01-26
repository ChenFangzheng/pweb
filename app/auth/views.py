from flask import render_template, request, url_for, redirect, flash
from flask_login import login_user, current_user, login_required, logout_user
from . import auth
from .. import db
from .form import LoginForm, AddUserForm
from ..models import User, Role


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


@auth.route('/add_user', methods=['GET', 'POST'])
@login_required
def add_user():
    form = AddUserForm()
    if form.validate_on_submit():
        user = User(username=form.username.data,
                    password=form.password.data,
                    role=Role.query.get(form.role.data),
                    name=form.name.data,
                    email=form.email.data,
                    mobile=form.mobile.data,
                    location=form.location.data,
                    about_me=form.about_me.data)
        db.session.add(user)
        db.session.commit()
        flash('用户%r已经被添加到系统中' % form.username.data)
        return redirect(url_for('auth.add_user'))
    return render_template('auth/add_user.html', form=form)
