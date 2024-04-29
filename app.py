from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import re

# from flask_testing import TestCase

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.config['SECRET_KEY'] = 'supersecretkey'

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))  # Redirect to index if already logged in

    if request.method == 'POST':
        user = User.query.filter_by(username=request.form.get('username')).first()

        if user and user.check_password(request.form.get('password')):
            login_user(user)
            return redirect(url_for('index'))  # Redirect to index after successful login

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))  # Redirect to index after logout


if __name__ == "__main__":
    db.create_all()
    app.run(debug=True)

"""
# გამოიყენეთ მხოლოდ 3.9 ვერსიაზე ბიბლიოთეკა არ უწყობს ხელს!!!
# Unit Test Section
# class MyTest(TestCase):
#     def create_app(self):
#         app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite://'  # Use in-memory SQLite database for testing.
#         app.config['TESTING'] = True
#         return app
#
#     def setUp(self):
#         # called before every test case
#         self.client = app.test_client()
#         db.create_all()
#         user = User(username="testuser")
#         user.set_password("testpassword")  # or directly, user.password_hash = generate_password_hash("testpassword")
#         db.session.add(user)
#         db.session.commit()
#
#     def tearDown(self):
#         # called after every test case
#         db.session.remove()
#         db.drop_all()
#
#     def test_home_status_code(self):
#         response = self.client.get('/')
#         self.assertEqual(response.status_code, 200)
#
#     def test_login_status_code(self):  # example for login
#         response = self.client.post('/login', data=dict(username="testuser", password="testpassword"),
#                                     follow_redirects=True)
#         self.assertEqual(response.status_code, 200)
#
#     def test_logout_status_code(self):  # example for logout
#         # Logging in first.
#         self.client.post('/login', data=dict(username="testuser", password="testpassword"), follow_redirects=True)
#
#         # Now we can test logging out.
#         response = self.client.get('/logout', follow_redirects=True)
#         self.assertEqual(response.status_code, 200)

#
# if __name__ == '__main__':
#     unittest.main()
"""
