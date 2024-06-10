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
------------------routes.py-------------------------

Blueprint & API Initialization: Creates a blueprint for authentication routes and initializes Flask-RESTx API.
User and Todo Models: Defines models for user registration/login and to-do tasks using Flask-RESTx.
JWT Authorization: Configures JWT for secure API requests.

API Endpoints:
Register: Registers a new user with a hashed password.
Login: Authenticates a user and returns a JWT token.
To-Do Operations: Provides CRUD operations for managing to-do tasks, secured with JWT.

-----------------------------------------------------
--------------------index.html----------------------

JSON (JavaScript Object Notation) is a standardized format for representing structured data. It has become ubiquitous for data exchange between systems due to its simplicity and widespread adoption.

HTML Structure: Defines the structure of the registration and login forms.
CSS Link: Links to a CSS file for styling.
JavaScript: Handles form submissions:
Registration: Sends a POST request to the /auth/register endpoint.
Login: Sends a POST request to the /auth/login endpoint. Stores the JWT token in localStorage on successful login and redirects to todo.html.

------------------------------------------------------
----------------todo.html----------------------------

HTML Structure: Defines the structure for displaying and adding to-do tasks.
JavaScript: Handles to-do task management:
Load Tasks: Fetches and displays tasks from the /auth/todos endpoint.
Add Task: Sends a POST request to add a new task.
Edit Task: Prompts the user for a new task description and sends a PUT request to update the task.
Delete Task: Sends a DELETE request to remove a task.
