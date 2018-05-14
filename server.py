from flask import Flask, render_template, redirect, request, session, flash
from flask_bcrypt import Bcrypt
from mysqlconnection import connectToMySQL
import re
app = Flask(__name__)
app.secret_key = "98hf8egiuewbiewu9fbue9"
mysql = connectToMySQL('wall-db')
bcrypt = Bcrypt(app)
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
print('\n= = = = = server start = = = = =')


@app.route('/')
def index():
    return render_template('index.html')


# ####################### LOG IN ##############################
@app.route('/login', methods=['post'])
def login():
    debugHelp("LOGIN")

    # Email Validation && add to flash
    if len(request.form['email']) < 1:
        flash("Email cannot be blank!", "email_login")
    elif not EMAIL_REGEX.match(request.form['email']):
        flash("Invalid Email Address!", "email_login")

    # Query for user by email
    data = {
        "email": request.form['email']
    }
    query = "SELECT * FROM users WHERE email=%(email)s;"
    login_check = mysql.query_db(query, data)
    
    # Validate if user exists && if DB_hashed_password == user password hashed
    if login_check and bcrypt.check_password_hash(login_check[0]['password'], request.form['password']):
        # user exists here and password matches
        # session all user info that we want to reuse
        session['user_id'] = login_check[0]['id']
        session['first_name'] = login_check[0]['first_name']
        return redirect('/wall')
    else:
        # if user does not exist, or if user exists but password does not match
        # add flash message
        flash("Invalid Credentials", "email_login")
        # redirect to root
        return redirect("/")


# ####################### REGISTER #########################
@app.route('/register', methods=['post'])
def register():
    debugHelp("REGISTER")
    # first name validation
    if len(request.form['first_name']) < 1:
        flash('First name cannot be empty', 'first_name')
    if request.form['first_name'].isalpha() == False:
        flash('First name must have letters only', 'first_name')
    if len(request.form['first_name']) < 3:
        flash('First name must have at least 3+ letters!', 'first_name')
    # last name validation
    if request.form['last_name'].isalpha() == False:
        flash('LAST name must have letters only', 'last_name')
    if len(request.form['last_name']) < 1:
        flash('LAST name cannot be empty', 'last_name')
    if len(request.form['last_name']) < 3:
        flash('LAST name must have at least 3+ letters!', 'last_name')
    # email validation
    if len(request.form['email']) < 1:
        flash("Email cannot be blank!", 'email')
    elif not EMAIL_REGEX.match(request.form['email']):
        flash("Invalid Email Address!", 'email')
    # password validation
    if len(request.form['password']) < 1:
        flash("password cannot be blank", 'password')
    if len(request.form['password']) < 6:
        flash('password must have AT LEAST 6 characters', 'password')
    # password confirm validation
    if request.form['password'] != request.form['password_confirm']:
        flash('passwords must match!', 'password_confirm')

    #db checks existing email
    data = {
        "email": request.form['email']
    }
    query = "SELECT email FROM users WHERE email=%(email)s;"
    result = mysql.query_db(query, data)
    # if the db responds with a result then email aready exists in db, stop user from registering
    if (result):
        flash('cannot use this email', 'email')

    # final checks
    if '_flashes' in session.keys():
        return redirect("/")
    else:
        # if there are no flash errors query to insert user to db and session name
        pw_hash = bcrypt.generate_password_hash(request.form['password']) 
        data = {
            "first_name": request.form['first_name'],
            "last_name": request.form['last_name'],
            "email": request.form['email'],
            "password": pw_hash,
        }
        query = "INSERT INTO users(first_name, last_name, email, password, created_at, updated_at) VALUES (%(first_name)s, %(last_name)s, %(email)s, %(password)s, NOW(), NOW());"
        mysql.query_db(query, data)
        session['first_name'] = request.form['first_name']
        # now query to select same user by email to get id and add to session
        data2 = {
            'email': request.form['email']
        }
        query2 = "SELECT id FROM users WHERE email=%(email)s"
        result2 = mysql.query_db(query2, data2)
        session['user_id'] = result2[0]['id']
        return redirect("/wall")


# ##################### WALL ###########################
@app.route('/wall')
def wall():
    debugHelp("WALL")

    # query_messages = "SELECT * FROM messages;"
    query_messages = "SELECT messages.id AS message_id, messages.user_id AS message_user_id, messages.content AS message_content, messages.created_at AS message_created_at, users.first_name AS user_first_name FROM messages LEFT JOIN users ON users.id = messages.user_id;"
    messages = mysql.query_db(query_messages)
    print('\n === messages query ===\n', messages,'\n==== end messages query ====\n')

    query_comments = "SELECT message_id AS comment_message_id, content AS comment_content, created_at AS comment_created_at FROM comments;"
    comments = mysql.query_db(query_comments)
    print('\n === comments query ===\n', comments,'\n==== end comments query ====\n')


    if 'user_id' in session:
        return render_template('wall.html', messages=messages, comments=comments)
    else:
        return redirect('/')


# ##################### POST MESSAGE ######################
@app.route('/message', methods=['post'])
def message():
    debugHelp("message")
    data = {
        "user_id": session['user_id'],
        "content": request.form['content']
    }
    query = "INSERT INTO messages(user_id, content, created_at, updated_at) VALUES(%(user_id)s, %(content)s, NOW(), NOW());"
    mysql.query_db(query, data)
    return "message"


# ##################### COMMENT ########################
@app.route('/comment', methods=['post'])
def comment():
    debugHelp("comment")
    data = {
        "user_id": session['user_id'],
        "message_id": request.form['message_id'],
        "content": request.form['comment']
    }
    query = "INSERT INTO comments(user_id, message_id, content, created_at, updated_at) VALUES(%(user_id)s, %(message_id)s, %(content)s, NOW(), NOW());"
    mysql.query_db(query, data)
    return redirect('/wall')


# ##################### LOG OUT ########################
@app.route('/logout')
def logout():
    debugHelp("LOG OUT")
    session.clear()
    return redirect('/')

# ############################################

def debugHelp(message=""):
    print("\n\n-------", message, "-------")
    print("REQUEST.FORM: ", request.form)
    print('SESSION: ', session)
# ############################################

if __name__ == "__main__":
    app.run(debug=True)