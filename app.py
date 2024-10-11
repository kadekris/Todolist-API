from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///todo.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'hflghbgulihnhni' 
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)

db = SQLAlchemy(app)
jwt = JWTManager(app)

# Model Role
class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False, unique=True)

# Model User
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=False)
    role = db.relationship('Role', backref=db.backref('users', lazy=True))

# Model Todo
class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    completed = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now)

# Inisialisasi database
def init_db():
    with app.app_context():
        db.create_all()
        # Tambahkan role admin dan guest jika belum ada
        if not Role.query.filter_by(name='admin').first():
            admin_role = Role(name='admin')
            db.session.add(admin_role)
        if not Role.query.filter_by(name='guest').first():
            guest_role = Role(name='guest')
            db.session.add(guest_role)
        db.session.commit()

init_db()

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()

    # Check if the username already exists
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'message': 'Username already exists'}), 400

    # Get role (default to 'guest' if not specified)
    role_name = data.get('role', 'guest')
    
    role = Role.query.filter_by(name=role_name).first()

    if not role:
        return jsonify({'message': 'Role not found'}), 400

    # Hash the password using pbkdf2:sha256
    hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
    new_user = User(username=data['username'], password=hashed_password, role_id=role.id)

    # Add user to the database
    db.session.add(new_user)
    try:
        db.session.commit()
        return jsonify({'message': 'User registered successfully'}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Error registering user', 'error': str(e)}), 500


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    if user and check_password_hash(user.password, data['password']):
        access_token = create_access_token(identity=user.id)
        return jsonify(access_token=access_token), 200
    return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/todos', methods=['POST'])
@jwt_required()
def create_todo():
    data = request.get_json()
    user_id = get_jwt_identity()
    new_todo = Todo(title=data['title'], user_id=user_id)
    db.session.add(new_todo)
    db.session.commit()
    return jsonify({'id': new_todo.id, 'title': new_todo.title, 'completed': new_todo.completed}), 201

@app.route('/todos', methods=['GET'])
@jwt_required()
def get_todos():
    user_id = get_jwt_identity()
    current_user = db.session.get(User, user_id)

    
    # Jika user adalah admin, ambil semua todo
    if current_user.role.name == 'admin':
        todos = Todo.query.all()
    else:
        # Jika user adalah guest, ambil hanya todo milik mereka
        todos = Todo.query.filter_by(user_id=user_id).all()
        
    return jsonify([{'id': todo.id, 'title': todo.title, 'completed': todo.completed} for todo in todos]), 200

@app.route('/todos/<int:todo_id>', methods=['PUT'])
@jwt_required()
def update_todo(todo_id):
    user_id = get_jwt_identity()
    current_user = db.session.get(User, user_id)

     
    # Hanya admin yang dapat mengubah Todo
    if current_user.role.name != 'admin':
        return jsonify({'message': 'Unauthorized'}), 403

    todo = Todo.query.filter_by(id=todo_id).first()
    if not todo:
        return jsonify({'message': 'Todo not found'}), 404
    data = request.get_json()
    todo.title = data.get('title', todo.title)
    todo.completed = data.get('completed', todo.completed)
    db.session.commit()
    return jsonify({'id': todo.id, 'title': todo.title, 'completed': todo.completed}), 200

@app.route('/todos/<int:todo_id>', methods=['DELETE'])
@jwt_required()
def delete_todo(todo_id):
    user_id = get_jwt_identity()
    current_user = db.session.get(User, user_id)

    
    # Hanya admin yang dapat menghapus Todo
    if current_user.role.name != 'admin':
        return jsonify({'message': 'Unauthorized'}), 403

    todo = Todo.query.filter_by(id=todo_id).first()
    if not todo:
        return jsonify({'message': 'Todo not found'}), 404
    db.session.delete(todo)
    db.session.commit()
    return jsonify({'message': 'Todo deleted'}), 200

@app.route('/reset', methods=['DELETE'])
def reset_database():
    db.drop_all() 
    db.create_all()  
    return jsonify({'message': 'Reset database berhasil'}), 200


if __name__ == '__main__':
    app.run(debug=True)
