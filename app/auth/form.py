from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, SelectField, TextAreaField
from wtforms import ValidationError
from wtforms.validators import DataRequired, Length, Regexp, EqualTo, Email
from ..models import Role, User


class LoginForm(FlaskForm):
    username = StringField('用户名', validators=[DataRequired(), Length(1, 64)])
    password = PasswordField('密码', validators=[DataRequired()])
    remember_me = BooleanField('保持登录')
    submit = SubmitField('登录')


class AddUserForm(FlaskForm):
    username = StringField('用户名', validators=[DataRequired(), Length(1, 64),
                                              Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,
                                                     'Usernames must have only letters, numbers, dots or '
                                                     'underscores')
                                              ])
    password = PasswordField('密码', validators=[DataRequired(), EqualTo('password_repeat', '两次输入密码不一致')])
    password_repeat = PasswordField('密码确认', validators=[DataRequired()])
    name = StringField('用户姓名', validators=[DataRequired(), Length(1, 64)])
    email = StringField('邮箱', validators=[DataRequired(), Length(1, 64), Email()])
    mobile = StringField('电话', validators=[DataRequired()])
    role = SelectField('角色', coerce=int)
    location = StringField('通讯地址', validators=[Length(0, 64)])
    about_me = TextAreaField('自我介绍')
    submit = SubmitField('提交')

    def __init__(self, *args, **kwargs):
        super(AddUserForm, self).__init__(*args, **kwargs)
        self.role.choices = [(role.id, role.name)
                             for role in Role.query.order_by(Role.name).all()]

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('用户名已存在！')
