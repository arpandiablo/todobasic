Flask is a python web framework that allows to build lightweight web applications quickly and easily with Flask librariries.

---------------init.py---------------------------

Flask Initialization: Creates a new Flask application instance.

Configuration: Configures the app with database and JWT settings.

Extensions: 

SQLAlchemy: ORM for database interactions.
Bcrypt: Password hashing.
JWTManager: JWT authentication.
Migrate: Database migrations.
Blueprint Registration: Registers the auth_bp blueprint for authentication routes.

---------------------------------------------------
----------------models.py--------------------------

User Model: Represents a user with fields for ID, username, and hashed password. Has a relationship with the Todo model.
Todo Model: Represents a to-do task with fields for ID, task description, and a foreign key linking to a user.

-----------------------------------------------------