#-*- coding: utf-8 -*-
from functools import wraps
import flask
from flask import request, Response, Flask, render_template, redirect, current_app, session, Markup, url_for
import json
import config
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin,\
    fresh_login_required
from flask_admin import Admin, AdminIndexView
import flask_admin
from flask_admin.contrib import sqla
from passlib.apps import custom_app_context as pwd_context
import ldap3
from flask_wtf import Form
from wtforms import StringField, PasswordField, HiddenField, BooleanField, FieldList, IntegerField, FormField,\
    TextAreaField
import wtforms
from wtforms.validators import DataRequired, Optional
from urlparse import urlparse, urljoin

app = Flask(__name__)

__version__ = "0.0.1 Alpha"

app.config['SQLALCHEMY_DATABASE_URI'] = config.database_uri
app.secret_key = config.secret_key
db = SQLAlchemy(app)


class Pytanie(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    text = db.Column(db.String(1024), unique=True)

    def __str__(self):
        return "%s - %s" % (self.id, self.text[:32])


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(255), unique=True)
    password = db.Column(db.String(255))
    is_active = db.Column(db.Boolean())
    display_name = db.Column(db.String(255))
    comment = db.Column(db.String(255))

    def __init__(self, login="none", password="", roles=[]):
        self.login = login
        self.display_name = login
        self.password = pwd_context.encrypt(password)
        self.is_active = True
        self.roles = roles

    def __str__(self):
        return "%s - %s - $s" % (self.id, self.login, self.display_name)


class Team(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(32))
    points = db.Column(db.Integer)


class DataStore(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    data = db.Column(db.String(1024))


def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and \
           ref_url.netloc == test_url.netloc


def get_redirect_target():
    for target in request.args.get('next'), request.referrer:
        if not target:
            continue
        if is_safe_url(target):
            return target


class RedirectForm(Form):
    next = HiddenField()

    def __init__(self, *args, **kwargs):
        Form.__init__(self, *args, **kwargs)
        if not self.next.data:
            self.next.data = get_redirect_target() or ''

    def redirect(self, endpoint='index', **values):
        if is_safe_url(self.next.data):
            return redirect(self.next.data)
        target = get_redirect_target()
        return redirect(target or url_for(endpoint, **values))


class LoginForm(RedirectForm):
    login = StringField(validators=[DataRequired()])
    password = PasswordField(validators=[DataRequired()])
    remember = BooleanField(default=True)


login_manager = LoginManager(app)
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.needs_refresh_message = (
    u"To protect your account, please reauthenticate to access this page."
)
login_manager.needs_refresh_message_category = "info"


class MyAdminIndexView(AdminIndexView):
    @flask_admin.expose('/')
    @fresh_login_required
    def index(self):
        return super(MyAdminIndexView, self).index()


admin = Admin(app, name='quiz-system', index_view=MyAdminIndexView())


class UserAdmin(sqla.ModelView):
    form_columns = ['login', 'password', 'is_active', 'comment']
    column_exclude_list = ['password']
    column_display_pk = False
    column_searchable_list = ('login', 'display_name')


class PytanieAdmin(sqla.ModelView):
    form_columns = ['id', 'text']


admin.add_view(UserAdmin(User, db.session))
admin.add_view(PytanieAdmin(Pytanie, db.session))
admin.add_view(sqla.ModelView(Team, db.session))
admin.add_view(sqla.ModelView(DataStore, db.session))


def check_ldap_credentials(login, password):
    try:
        conn = ldap3.Connection(ldap3.Server(config.ldap_host, use_ssl=True), "cn=%s, cn=Users, dc=ad, dc=staszic, dc=waw, dc=pl" % login, password,
                                auto_bind=True, raise_exceptions=False) #sprawdzic bezpieczenstwo polaczenia
        ret = conn.search("cn=Users, dc=ad, dc=staszic, dc=waw, dc=pl", "(cn=%s)" % login, attributes=['uidNumber', 'displayName'])
        if not ret:
            return False
        data = conn.entries
        if len(data) == 1:
            ldap_data = dict()
            ldap_data['login'] = login
            ldap_data['uid'] = int(data[0]['uidNumber'][0])
            ldap_data['class_id'] = int(int(str(data[0]['uidNumber'][0])[0:3]))
            ldap_data['display_name'] = str(data[0]['displayName'][0])
            return ldap_data
        else:
            return False
    except KeyError:
        return False
    except IndexError:
        return False
    except ldap3.LDAPBindError:
        return False
    except ldap3.LDAPException as e:
        raise e


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if hasattr(current_user, 'login'):
        form.login.data = current_user.login
    wrong_login = False

    if form.validate_on_submit():
        user = User.query.filter_by(login=form.login.data).first()
        try:
            ldap_user = check_ldap_credentials(form.login.data, form.password.data)
        except:
            ldap_user = None
            print "Błąd połączenie z LDAP!"
        if user is not None and (pwd_context.verify(form.password.data, user.password) or ldap_user):
            if ldap_user:
                if user.display_name != ldap_user['display_name']:
                    user.display_name = ldap_user['display_name']
                    db.session.commit()
            login_user(user, remember=form.remember)
            flask.flash('Logged in successfully.')
            return form.redirect()
        else:
            wrong_login = True

    return render_template('login.html', form=form, wrong_login=wrong_login)

@login_manager.needs_refresh_handler
def refresh():
    return redirect(url_for('login', next=request.url))

@app.errorhandler(403)
def permission_denied_handler(e):
    print (e)
    if current_user.is_authenticated:
        return render_template('permission_denied.html')
    else:
        return redirect(url_for('login', next=request.url))


@app.route("/logout")
@login_required
def logout():
    logout_user()
    for key in ('identity.name', 'identity.auth_type'):
        session.pop(key, None)
    return redirect('/')


def get_or_create(session, model, **kwargs):
    instance = session.query(model).filter_by(**kwargs).first()
    if instance:
        return instance
    else:
        instance = model(**kwargs)
        session.add(instance)
        session.commit()
        return instance


@app.before_first_request
def create_default_user():
    db.create_all()
    admin = get_or_create(db.session, User, login=config.admin_login)
    admin.password = pwd_context.encrypt(config.admin_password)
    admin.is_active = True
    admin.comment = u"admin z config.py, zawsze posiada hasło z config.py"
    datastore = get_or_create(db.session, DataStore, id=1)
    if datastore.data is None:
        datastore.data = "{}"
    store = json.loads(datastore.data)
    if "pytanie" not in datastore.data:
        store["pytanie"] = ""
    if "stawka" not in datastore.data:
        store["stawka"] = 0
    if "num_akt_drozyny" not in datastore.data:
        store["num_akt_drozyny"] = 0
    if "czas_na_pytanie" not in datastore.data:
        store["czas_na_pytanie"] = 10
    datastore.data = json.dumps(store)
    db.session.commit()


def render_template_with_args(template, **kwargs):
    return render_template(template, version=__version__, **kwargs)


class TeamForm(wtforms.Form):
    team_id = IntegerField('id')
    team_name = StringField('name')
    points = IntegerField('points')


class ChangeForm(Form):
    pytanie_id = IntegerField('ID', validators=[Optional()])
    pytanie_text = TextAreaField('TEXT', validators=[Optional()])
    pytanie_czas = IntegerField('Czas')
    stawka = IntegerField('Stawka')
    teams = FieldList(FormField(TeamForm))
    akt_team = IntegerField('Team id')


@app.route('/', methods=['GET', 'POST'])
@login_required
def main():
    form = ChangeForm()

    datastore = DataStore.query.get(1)
    store = json.loads(datastore.data)

    if form.validate_on_submit():
        try:
            if form.pytanie_id.data != 0 and form.pytanie_id.data is not None:
                quest_object = Pytanie.query.get(form.pytanie_id.data)
                if quest_object is not None:
                    form.pytanie_text.data = quest_object.text
        except TypeError:
            pass
        form.pytanie_id.data = 0
        store["pytanie"] = form.pytanie_text.data
        store["stawka"] = form.stawka.data
        store["num_akt_drozyny"] = form.akt_team.data
        store["czas_na_pytanie"] = form.pytanie_czas.data
        for team in form.teams.entries:
            team_object = Team.query.get(team.team_id.data)
            if team_object is not None:
                team_object.points = team.points.data
            else:
                print "team ", team.team_id.data, "not found"
        datastore.data = json.dumps(store)
        db.session.commit()
    else:
        form.pytanie_text.data = store["pytanie"]
        form.pytanie_id.data = None
        form.stawka.data = store["stawka"]
        form.pytanie_czas.data = store["czas_na_pytanie"]
        form.akt_team.data = store["num_akt_drozyny"]
        if len(form.teams.entries) == 0:
            all_teams = Team.query.all()
            for team_object in all_teams:
                team_form = TeamForm()
                team_form.team_id = team_object.id
                team_form.team_name = team_object.name
                team_form.points = team_object.points
                form.teams.append_entry(team_form)

    return render_template('main.html', form=form)


@app.route('/api/get_status')
def api_v1_library():
    store = json.loads(DataStore.query.get(1).data)
    print "store", store
    data = {"stawka": store["stawka"],
            "pytanie": store["pytanie"],
            "num_akt_drozyny": store["num_akt_drozyny"],
            "czas_na_pytanie": store["czas_na_pytanie"],
            "stan_drozyn": []}
    for team in Team.query.all():
        data["stan_drozyn"].append({"nazwa": team.name, "punkty": team.points})
    data["stan_drozyn"].sort(key=lambda team: team["punkty"], reverse=True)
    # TODO sortowanie
    print "data", data
    return json.dumps(data)


if __name__ == '__main__':
    app.debug = True
    app.run(host="0.0.0.0")
