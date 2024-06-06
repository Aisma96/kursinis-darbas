from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, IntegerField, BooleanField
from wtforms.validators import DataRequired, Email, ValidationError
import sqlite3



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
    description = db.Column(db.Text(500), nullable=False)
    prep_time = db.Column(db.Integer, nullable=False)
    servings = db.Column(db.Integer, nullable=False)
    cook_time = db.Column(db.Integer, nullable=False)
    instructions = db.Column(db.Text(1000), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship('User',backref='recipes', lazy=True)

class RecipeIngredients(db.Model):
    __tablename__ = 'ingredients'
    id = db.Column(db.Integer, primary_key=True)
    ingredients = db.Column(db.String, nullable=False)
    quantities = db.Column(db.Integer, nullable=False)
    recipe_id = db.Column(db.Integer, db.ForeignKey('recipes.id'))
    recipe = db.relationship('Recipe', backref='ingredients', lazy=True)

class Products(db.Model):
    __tablename__ = 'products_nutritions'
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(100), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    calories = db.Column(db.Float, nullable=False)
    protein = db.Column(db.Float, nullable=False)
    carbohydrates = db.Column(db.Float, nullable=False)
    fat = db.Column(db.Float, nullable=False)

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
    description = TextAreaField('Description', validators=[DataRequired()])
    prep_time = IntegerField('Preparation time (minutes)', validators=[DataRequired()])
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
    product_names= Products.query.all()
    list_of_names = [item.name for item in product_names]   
    ingredients = []
    total_nutrition = {
        'Calories': 0,
        'Protein': 0,
        'Carbohydrate': 0,
        'Fat': 0
    }
    if request.method == 'POST':
        for x in range(50):
            product_key = f'list_of_products_{x}'
            quantity_key = f'quantities_{x}'

            if product_key in request.form and quantity_key in request.form:
                product = request.form[product_key]
                quantity = request.form[quantity_key]

                if product and quantity:
                    try:
                        quantities = quantity.replace(',', '.')
                        product = Products.query.filter_by(name=product).first()
                        if product:
                            calories = product.calories.replace(',', '.')
                            protein = product.protein.replace(',', '.')
                            carbohydrate = product.carbohydrates.replace(',', '.')
                            fat = product.fat.replace(',', '.')
                            
                            total_nutrition['Calories'] += calories * quantities / 100
                            total_nutrition['Protein'] += protein * quantities / 100
                            total_nutrition['Carbohydrate'] += carbohydrate * quantities / 100
                            total_nutrition['Fat'] += fat * quantities / 100
                        ingredients.append({'product': product, 'quantity': quantity})
                    except ValueError:
                        flash("Please enter a valid quantity for all ingredients.")
                        return render_template(
                            'add_recipe.html',
                            form=form,
                            list_of_products=list_of_names,
                            ingredients=ingredients,
                            total_nutrition=total_nutrition
                        )

    if form.validate_on_submit():
        recipe = Recipe(
            name=form.name.data,
            description=form.description.data,
            prep_time=form.prep_time.data,
            servings=form.servings.data,
            cook_time=form.cook_time.data,
            instructions=form.instructions.data,
            user = current_user
        )
        db.session.add(recipe)
        db.session.commit()
        for ingredient in ingredients:
            recipe_ingredient = RecipeIngredients(
            ingredients=ingredient['product'],
            quantities=ingredient['quantity'],
            recipe_id=recipe.id
            )
            db.session.add(recipe_ingredient)
        db.session.commit()

        return redirect(url_for('view_recipe', recipe_id=recipe.id))
    return render_template('add_recipe.html', form=form, list_of_products=list_of_names,ingredients=ingredients,
                           total_nutrition=total_nutrition)

@app.route('/recipeadded', methods=['GET', 'POST'])
@login_required
def recipe_added():
    return render_template('recipe_added.html')


@app.route('/recipes/<int:recipe_id>', methods=['GET'])
@login_required
def view_recipe(recipe_id):
    recipe = Recipe.query.get_or_404(recipe_id)
    ingredients = RecipeIngredients.query.filter_by(recipe_id=recipe_id).all()
    return render_template('view_recipe.html', recipe=recipe, ingredients=ingredients)

@app.route('/my_recipes', methods=['GET'])
@login_required
def my_recipes():
    recipes = Recipe.query.filter_by(user_id=current_user.id).all()
    return render_template('my_recipes.html', recipes=recipes)


# @app.route('/allrecipes', methods=['GET'])
# @login_required
# def all_recipes():
#     all_recipes = Recipe.query.filter_by(user_id=User.id)
#     all_ingredients = RecipeIngredients.query.filter_by(user_id=Recipe.id)
#     return render_template('my_recipes.html', all_recipes=all_recipes, all_ingredients=all_ingredients)


@app.route('/blueberry')
def blueberry():
    return render_template('blueberry-donuts.html')

@app.route('/pudding')
def pudding():
    return render_template('chia-pudding.html')

@app.route('/overnigntoats')
def overnignt_oats():
    return render_template('overnignt-oats.html')

@app.route('/pancakes')
def pancakes():
    return render_template('cottage-cancakes.html')


@app.route('/unfinishedrecipes')
def unfinished_recipes():
    return render_template('unfinished-recipes.html')

@app.route('/editrecipe')
def edit_recipe():
    return render_template('edit_recipe.html')




@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
