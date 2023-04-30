from flask_login import LoginManager, login_user, login_required, logout_user
from wtforms import PasswordField, BooleanField, SubmitField, EmailField
from flask_wtf import FlaskForm
from flask import Flask, render_template, redirect
import data.db_session as session
from data.users import User
from wtforms.validators import DataRequired
import datetime

app = Flask(__name__)

app.config['SECRET_KEY'] = 'yandexlyceum_secret_key'
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(days=365)

login_manager = LoginManager()
login_manager.init_app(app)


def adding_for_test():
    user = User()
    user.surname = "Test"
    user.name = "Test"
    user.age = 21
    user.position = "test"
    user.speciality = "test"
    user.address = "module_1"
    user.email = "test@test.org"
    user.password_hash = "test"
    user.set_password("test")

    db_session.add(user)
    db_session.commit()


class LoginForm(FlaskForm):
    email = EmailField('Почта', validators=[DataRequired()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    remember_me = BooleanField('Запомнить меня')
    submit = SubmitField('Войти')


@login_manager.user_loader
def load_user(user_id):
    return db_session.query(User).get(user_id)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = db_session.query(User).filter(User.email == form.email.data).first()

        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember_me.data)
            return redirect("/")

        return render_template('login.html', message="Неправильный логин или пароль", form=form)

    return render_template('login.html', title='Mars One | Авторизация', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect("/")


if __name__ == '__main__':
    session.global_init("db/blogs.db")
    db_session = session.create_session()

    app.run(port=8080, host='127.0.0.1')

