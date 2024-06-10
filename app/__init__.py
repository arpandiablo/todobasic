from flask import Flask, render_template
from flask_jwt_extended import JWTManager
from .models import db
from .routes import auth_bp, bcrypt

def create_app():
    app = Flask(__name__, static_folder='../static', template_folder='../templates')

    # Configure database
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Configure JWT
    app.config['JWT_SECRET_KEY'] = 'your_secret_key'  # Change this to a random secret key

    # Initialize extensions
    db.init_app(app)
    bcrypt.init_app(app)
    jwt = JWTManager(app)

    # Register blueprints
    app.register_blueprint(auth_bp, url_prefix='/auth')

    with app.app_context():
        db.create_all()  # Create database tables

    # Serve the HTML templates
    @app.route('/')
    def serve_index():
        return render_template('index.html')

    @app.route('/todos')
    def serve_todos():
        return render_template('todo.html')

    return app
