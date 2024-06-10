from flask import Blueprint, request, jsonify
from flask_restx import Api, Resource, fields
from .models import db, User, Todo
from flask_bcrypt import Bcrypt
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity

###############
# from werkzeug.security import generate_password_hash, check_password_hash
# from app.models import User, db
###############

auth_bp = Blueprint('auth_bp', __name__)
api = Api(auth_bp, doc='/docs', title='To-Do API', description='A simple To-Do API', security='Bearer Auth')
bcrypt = Bcrypt()

ns = api.namespace('auth', description='Authentication operations')

user_model = api.model('User', {
    'username': fields.String(required=True, description='The user username'),
    'password': fields.String(required=True, description='The user password')
})

todo_model = api.model('Todo', {
    'id': fields.Integer(readOnly=True, description='The task unique identifier'),
    'task': fields.String(required=True, description='The task details')
})

api.authorizations = {
    'Bearer Auth': {
        'type': 'apiKey',
        'name': 'Authorization',
        'in': 'header'
    }
}

@ns.route('/register')
class Register(Resource):
    @api.expect(user_model)
    @api.response(201, 'User created successfully')
    @api.response(409, 'User already exists')
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        user = User.query.filter_by(username=username).first()
        if user:
            return {'msg': 'User already exists'}, 409

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return {'msg': 'User created successfully'}, 201

@ns.route('/login')
class Login(Resource):
    @api.expect(user_model)
    @api.response(200, 'Login successful')
    @api.response(401, 'Invalid credentials')
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password, password):
            access_token = create_access_token(identity=user.id)
            return {'access_token': access_token}, 200

        return {'msg': 'Invalid credentials'}, 401

@ns.route('/todos')
class TodoList(Resource):
    @jwt_required()
    @api.marshal_list_with(todo_model)
    def get(self):
        current_user_id = get_jwt_identity()
        todos = Todo.query.filter_by(user_id=current_user_id).all()
        return todos

    @jwt_required()
    @api.expect(todo_model)
    @api.response(201, 'Task added successfully')
    def post(self):
        current_user_id = get_jwt_identity()
        data = request.get_json()
        new_task = Todo(task=data['task'], user_id=current_user_id)
        db.session.add(new_task)
        db.session.commit()
        return {'msg': 'Task added successfully'}, 201

@ns.route('/todos/<int:id>')
class TodoResource(Resource):
    @jwt_required()
    @api.response(404, 'Task not found')
    @api.response(200, 'Task updated successfully')
    @api.expect(todo_model)
    def put(self, id):
        current_user_id = get_jwt_identity()
        todo = Todo.query.filter_by(id=id, user_id=current_user_id).first()
        if not todo:
            return {'msg': 'Task not found'}, 404

        data = request.get_json()
        todo.task = data['task']
        db.session.commit()
        return {'msg': 'Task updated successfully'}, 200

    @jwt_required()
    @api.response(404, 'Task not found')
    @api.response(200, 'Task deleted successfully')
    def delete(self, id):
        current_user_id = get_jwt_identity()
        todo = Todo.query.filter_by(id=id, user_id=current_user_id).first()
        if not todo:
            return {'msg': 'Task not found'}, 404

        db.session.delete(todo)
        db.session.commit()
        return {'msg': 'Task deleted successfully'}, 200


#############################################################

@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    user = User.query.filter_by(username=username).first()
    if user:
        return jsonify({'msg': 'User already exists'}), 409

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(username=username, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'msg': 'User created successfully'}), 201

@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    user = User.query.filter_by(username=username).first()

    if user and bcrypt.check_password_hash(user.password, password):
        access_token = create_access_token(identity=user.id)
        return jsonify({'access_token': access_token}), 200

    return jsonify({'msg': 'Invalid credentials'}), 401

@auth_bp.route('/todos', methods=['GET', 'POST'])
@jwt_required()
def handle_todos():
    current_user_id = get_jwt_identity()
    if request.method == 'POST':
        data = request.get_json()
        new_task = Todo(task=data['task'], user_id=current_user_id)
        db.session.add(new_task)
        db.session.commit()
        return jsonify({'msg': 'Task added successfully'}), 201
    else:
        todos = Todo.query.filter_by(user_id=current_user_id).all()
        return jsonify([{'id': todo.id, 'task': todo.task} for todo in todos]), 200

@auth_bp.route('/todos/<int:id>', methods=['PUT', 'DELETE'])
@jwt_required()
def modify_task(id):
    current_user_id = get_jwt_identity()
    todo = Todo.query.filter_by(id=id, user_id=current_user_id).first()
    if not todo:
        return jsonify({'msg': 'Task not found'}), 404

    if request.method == 'PUT':
        data = request.get_json()
        todo.task = data['task']
        db.session.commit()
        return jsonify({'msg': 'Task updated successfully'}), 200
    elif request.method == 'DELETE':
        db.session.delete(todo)
        db.session.commit()
        return jsonify({'msg': 'Task deleted successfully'}), 200   
#####################################################################