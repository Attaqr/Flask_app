from flask import Flask, render_template, request, abort, redirect, session
import bcrypt
import re
import sqlite3
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

class AccountManagement:
    def __init__(self):
        self.whitelist = r'^[a-zA-Z0-9]+$'
        self.counter = 0
        self.conn = sqlite3.connect('app.db', check_same_thread=False)
        self.cursor = self.conn.cursor()
        self.cursor.execute('CREATE TABLE IF NOT EXISTS Users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)')
        self.conn.commit()

    def insert_user(self, Rusername, Rpassword):
        self.cursor.execute('SELECT MAX(id) FROM Users')
        result = self.cursor.fetchone()
        if result[0] is not None:
            self.counter = result[0] + 1
        else:
            self.counter = 1
        self.cursor.execute('SELECT username FROM Users WHERE username=?', (Rusername,))
        result2 = self.cursor.fetchone()
        if result2 is not None:
    
            abort(401, 'Username not available')
        else:
            calc_id = self.counter
            salt = bcrypt.gensalt()
            Rhashed_password = bcrypt.hashpw(Rpassword.encode('utf-8'), salt)
            self.cursor.execute('INSERT INTO Users (id, username, password) VALUES (?, ?, ?)', (calc_id, Rusername, Rhashed_password))
            self.conn.commit()

    def auth_user(self, username, password):
        self.cursor.execute('SELECT password FROM Users WHERE username = ?', (username,))
        result = self.cursor.fetchone()
        if result is not None:
            hashed_passwd = result[0]
            return bcrypt.checkpw(password.encode('utf-8'), hashed_passwd)
        return False
    
    def get_user_id(self, username):
        self.cursor.execute('SELECT id FROM Users WHERE username = ?', (username,))
        result = self.cursor.fetchone()
        return result

account_management_obj = AccountManagement()

class Todo:
    def __init__(self):
        self.conn = sqlite3.connect('app.db', check_same_thread=False)
        self.cursor = self.conn.cursor()
        self.cursor.execute('CREATE TABLE IF NOT EXISTS Todo (id INTEGER REFERENCES Users(id), Task TEXT)')
        self.conn.commit()
    
    def add_task(self, username, task):
        self.cursor.execute('SELECT id FROM Users WHERE username = ?', (username,))
        result = self.cursor.fetchone()
        user_id = result[0] if result is not None else None

        if user_id is not None:
            self.cursor.execute('INSERT INTO Todo (id, Task) VALUES (?, ?)', (user_id, task))
            self.conn.commit()


Todo_obj = Todo()

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        Rusername = request.form.get('username')
        Rpassword = request.form.get('password')
        if not re.match(account_management_obj.whitelist, Rusername) or not re.match(account_management_obj.whitelist, Rpassword):
            abort(401, 'Error: Injection attack detected')
        account_management_obj.insert_user(Rusername, Rpassword)

        return redirect('/login')
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not re.match(account_management_obj.whitelist, username) or not re.match(account_management_obj.whitelist, password):
            abort(401, 'Error: Injection attack detected')
        
        call = account_management_obj.auth_user(username, password)
        if not call:
            abort(401, 'Invalid credentials')
        else:
            session['username'] = username  # Store username in session
            return redirect('/user')
    
    return render_template('login.html')

@app.route('/user', methods=['GET'])
def user():
    if 'username' in session:
        username = session['username']

        user_id = account_management_obj.get_user_id(username)
        if user_id is not None:
            Todo_obj.cursor.execute('SELECT Task FROM Todo WHERE id = ?', (user_id))
            tasks = Todo_obj.cursor.fetchall()
        else:
            tasks = []

        return render_template('user.html', username=username, tasks=tasks)
    else:
        return redirect('/login')

@app.route('/logout')
def logout():
    session.pop('username', None)  
    return render_template('logout.html')

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/add', methods=['POST'])
def add():
    if 'username' in session:
        username = session['username']
        task = request.form.get('task')
        Todo_obj.add_task(username, task)  # Call the add_task method of the new instance
        return redirect('/user')
    else:
        return 'Not authenticated'

@app.route('/delete', methods=['POST'])
def delete():
    if 'username' in session:
        username = session['username']
        user_id = account_management_obj.get_user_id(username)
        if user_id is not None:
            task_id = request.form.get('task_id')
            if task_id:
                Todo_obj.cursor.execute('DELETE FROM Todo WHERE id = ? AND Task = ?', (user_id[0], task_id))
                Todo_obj.conn.commit()
                return redirect('/user')
    return abort(401, 'Unauthorized')











if __name__ == '__main__':
    app.run()
