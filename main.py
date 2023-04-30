from flask_login import LoginManager, login_user, login_required, logout_user
from wtforms import PasswordField, BooleanField, SubmitField, EmailField, IntegerField, StringField, DateTimeField
from flask_wtf import FlaskForm
from flask import Flask, render_template, redirect
import data.db_session as session
from data.users import User
from data.jobs import Jobs
from wtforms.validators import DataRequired
import datetime

app = Flask(__name__)

app.config['SECRET_KEY'] = 'yandexlyceum_secret_key'
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(days=365)

login_manager = LoginManager()
login_manager.init_app(app)

account = ''


def test():
    user = User()
    user.surname = "Green"
    user.name = "Ben"
    user.age = 45
    user.position = "Senior"
    user.speciality = "Doc"
    user.address = "module_1"
    user.email = "Ben@mail.com"
    user.password_hash = "ben"
    user.set_password("ben")

    db_session.add(user)
    db_session.commit()


class LoginForm(FlaskForm):
    email = EmailField('Почта', validators=[DataRequired()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    remember_me = BooleanField('Запомнить меня')
    submit = SubmitField('Войти')


class JobForm(FlaskForm):
    id = IntegerField('Team-leader-id', validators=[DataRequired()])

    title = StringField('Title of job', validators=[DataRequired()])

    work_size = IntegerField('Work size (in hours)', validators=[DataRequired()])

    collaborators = StringField("collaborators' ID using ,", validators=[DataRequired()])

    start_date = DateTimeField('Start date', format='%Y-%m-%d %H:%M:%S', default=datetime.datetime.now)

    end_date = DateTimeField('End date', format='%Y-%m-%d %H:%M:%S',
                             default=datetime.datetime(year=2030, month=1, day=1, hour=1, minute=0, second=0))

    done = BooleanField('Is finished?')

    submit = SubmitField('Submit')


@login_manager.user_loader
def load_user(user_id):
    return db_session.query(User).get(user_id)


@app.route("/")
def start():
    global account
    return render_template('base.html', account=account)


@app.route('/login', methods=['GET', 'POST'])
def login():
    global account
    form = LoginForm()

    if form.validate_on_submit():
        user = db_session.query(User).filter(User.email == form.email.data).first()

        if user and user.check_password(form.password.data):
            account = f'{user.name} {user.surname}'
            login_user(user, remember=form.remember_me.data)
            return redirect("/works")

        return render_template('login.html', message="Неверный логин или пароль", form=form)

    return render_template('login.html', title='Mars One | Авторизация', form=form, account='')


@app.route('/logout')
@login_required
def logout():
    global account

    account = ''

    logout_user()
    return redirect("/")


@app.route('/works')
@login_required
def table():
    res = db_session.query(Jobs).all()
    data = []

    for job in res:
        time = f'{round((job.end_date - job.start_date).total_seconds() / 3600)} hours'
        user = db_session.query(User).filter(User.id == job.team_leader).first()
        team_leader = user.name + ' ' + user.surname

        data.append([job.job, team_leader, time, job.collaborators, job.is_finished])

    return render_template('works.html', jobs=data, account=account)


if __name__ == '__main__':
    session.global_init("db/blogs.db")
    db_session = session.create_session()

    app.run(port=8080, host='127.0.0.1')

    test()
