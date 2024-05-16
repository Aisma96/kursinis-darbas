from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, IntegerField, BooleanField
from wtforms.validators import DataRequired, Email, ValidationError


app = Flask(__name__)
app.secret_key = 'secret_key' 
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)

bcrypt = Bcrypt(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(50), unique=True, nullable=False)

class Recipe(db.Model):
    __tablename__ = 'recipes'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    ingredients = db.Column(db.String(500), nullable=False)
    quantities = db.Column(db.String(500), nullable=False)
    description = db.Column(db.Text, nullable=False)
    servings = db.Column(db.Integer, nullable=False)
    cook_time = db.Column(db.Integer, nullable=False)
    instructions = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship('User', lazy=True)

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField("Register")
 
    def validate_email(self, email):
        with app.app_context():
            user = User.query.filter_by(email=email.data).first()
            if user:
                raise ValidationError('This email is already in use')

    def validate_name(self, username):
        with app.app_context():
            user = User.query.filter_by(username=username.data).first()
            if user:
                raise ValidationError('This name is already in use')


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember me')
    submit = SubmitField("Login")

class RecipeForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    ingredients = TextAreaField('Ingredients', validators=[DataRequired()])
    quantities = TextAreaField('Quantities', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[DataRequired()])
    servings = IntegerField('Servings', validators=[DataRequired()])
    cook_time = IntegerField('Cook Time (minutes)', validators=[DataRequired()])
    instructions = TextAreaField('Instructions', validators=[DataRequired()])
    submit = SubmitField('Add Recipe')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegisterForm()
    if form.validate_on_submit():
        password = form.password.data
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('home'))
    return render_template('register.html',  form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            flash('You have been logged in successfully!', 'success')
            login_user(user)
            return redirect(url_for('home'))
        else:
            flash('Login unsuccessful. Please check your email and password.', 'danger')
    return render_template('login.html', form=form)


@app.route('/addrecipe', methods=['GET', 'POST'])
@login_required
def add_recipe():
    form = RecipeForm()
    if form.validate_on_submit():
        ingredients = form.ingredients.data.split('\n')
        quantities = form.quantities.data.split('\n')
        recipe = Recipe(
            name=form.name.data,
            ingredients=', '.join(ingredients),
            quantities=', '.join(quantities),
            description=form.description.data,
            servings=form.servings.data,
            cook_time=form.cook_time.data,
            instructions=form.instructions.data
        )
        db.session.add(recipe)
        db.session.commit()
        return redirect(url_for('recipe_added'))
    return render_template('add_recipe.html', form=form)

@app.route('/recipeadded', methods=['GET', 'POST'])
@login_required
def recipe_added():
    return render_template('recipe_added.html')


@app.route('/blueberry')
def blueberry():
    return render_template('blueberry_donuts.html')



@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
