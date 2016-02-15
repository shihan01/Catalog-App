from flask import Flask, render_template, request, redirect, jsonify, url_for, flash
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, User, Category, Star
from flask import session as login_session
import random
import string
import requests
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
import os
from flask import make_response
from werkzeug import secure_filename
from functools import wraps


app = Flask(__name__)

CLIENT_ID = json.loads(open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Category Name Application"

engine = create_engine('sqlite:///categorystarwithuser.db')
Base.metadata.bind = engine

DBsession = sessionmaker(bind=engine)
session = DBsession()

# Create anti-forgery state token
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE = state)

@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code, now compatible with Python3
    request.get_data()
    code = request.data.decode('utf-8')
    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    # Submit request, parse response - Python3 compatible
    h = httplib2.Http()
    response = h.request(url, 'GET')[1]
    str_response = response.decode('utf-8')
    result = json.loads(str_response)

    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    
    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        print login_session.get('gplus_id')
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius:\
                  150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    return output

# User Helper Functions
def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


# DISCONNECT - Revoke a current user's token and reset their login_session
@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnect a connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    if result['status'] == '200':
        # Reset the user's sesson.
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']

        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        redirect(url_for('showCategories'))
        return response
    else:
        # For whatever reason, the given token was invalid.
        response = make_response(
            json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


# JSON APIs to view Category Information
@app.route('/category/<int:category_id>/star/json')
def categoryMenuJSON(category_id):
    category = session.query(Category).filter_by(id=category_id).one()
    stars = session.query(Star).filter_by(category_id=category_id).all()
    res=[]
    for s in stars:
        each = {}
        each['name'] = s.name
        each['category'] = session.query(Category).filter_by(id=category_id).one().name
        each['description'] = s.description
        res.append(each)
    return jsonify(Star=res)


@app.route('/category/<int:category_id>/star/<int:star_id>/json')
def starJSON(category_id, star_id):
    star = session.query(Star).filter_by(id=star_id).one()
    res = []
    each = {}
    each['name'] = star.name
    each['category'] = session.query(Category).filter_by(id=category_id).one().name
    each['description'] = star.description
    res.append(each)
    return jsonify(Star=res)


@app.route('/category/json')
def categoriesJSON():
    categories = session.query(Category).all()
    res = []
    for c in categories:
        each = {}
        each['name'] = c.name
        res.append(each)
    return jsonify(categories=res)


# Checking the user has logged in or not
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in login_session:
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated_function

# Check if a user is authorized to modify the category and stars
def is_authorized(category_user_id, session_user_id):
    # check if authed
    # return script if not
    # return True if yes
    if category_user_id != session_user_id:
        return "<script>function myFunction() {alert('You are not authorized to modify this Category. \
               Please create your own Category.');}</script><body onload='myFunction()''>"
    else:
        return True


# Show all categories
@app.route('/')
@app.route('/category/')
def showCategories():
    if 'username' not in login_session:
        categories = session.query(Category).order_by(asc(Category.name))
        return render_template('publiccategories.html', categories=categories)
    else:
        categories = session.query(Category).filter_by(user_id = login_session['user_id']).order_by(asc(Category.name))
        others = session.query(Category).filter(Category.user_id != login_session['user_id']).order_by(asc(Category.name))
        return render_template('categories.html', categories=categories, others = others)

# Create a new category
@app.route('/category/new/', methods=['GET', 'POST'])
@login_required
def newCategory():
    if request.method == 'POST':
        print login_session['user_id']
        newCategory = Category(name=request.form['name'], user_id=login_session['user_id'])
        session.add(newCategory)
        flash('New Category %s Successfully Created' % newCategory.name)
        session.commit()
        return redirect(url_for('showCategories'))
    else:
        return render_template('newCategory.html')


# Edit a category
@app.route('/category/<int:category_id>/edit/', methods=['GET', 'POST'])
@login_required
def editCategory(category_id):
    editedCategory = session.query(Category).filter_by(id=category_id).one()
    res = is_authorized(editedCategory.user_id, login_session['user_id'])
    if res == True:
        if request.method == 'POST':
            if request.form['name']:
                editedCategory.name = request.form['name']
                flash('Category Successfully Edited %s' % editedCategory.name)
                return redirect(url_for('showCategories'))
        else:
            return render_template('editCategory.html', category=editedCategory)
    else: return res


# Delete a category
@app.route('/category/<int:category_id>/delete/', methods=['GET', 'POST'])
@login_required
def deleteCategory(category_id):
    categoryToDelete = session.query(Category).filter_by(id=category_id).one()
    res = is_authorized(categoryToDelete.user_id, login_session['user_id'])
    if res == True:
        if request.method == 'POST':
            session.delete(categoryToDelete)
            flash('%s Successfully Deleted' % categoryToDelete.name)
            session.commit()
            return redirect(url_for('showCategories', category_id=category_id))
        else:
            return render_template('deleteCategory.html', category=categoryToDelete)
    else:
        return res

# Show a category star
@app.route('/category/<int:category_id>/')
@app.route('/category/<int:category_id>/star/')
def showStar(category_id):
    category = session.query(Category).filter_by(id=category_id).one()
    creator = getUserInfo(category.user_id)
    stars = session.query(Star).filter_by(category_id=category_id).all()
    if 'username' not in login_session or creator.id != login_session['user_id']:
        return render_template('publicstar.html', stars=stars, category=category, creator=creator)
    else:
        return render_template('star.html', stars=stars, category=category, creator=creator)


# Create a new star
@app.route('/category/<int:category_id>/star/new/', methods=['GET', 'POST'])
@login_required
def newStar(category_id):
    category = session.query(Category).filter_by(id=category_id).one()
    res = is_authorized(category.user_id, login_session['user_id'])
    if res == True:
        if request.method == 'POST':
            path =""
            if request.files['image']:
                file = request.files['image']
                filename = secure_filename(file.filename)
                path = url_for('static', filename=filename)
                file.save(os.getcwd()+path)
            newStar = Star(name=request.form['name'], description=request.form['description'], 
                           category_id=category_id, user_id=category.user_id, path=path)
            session.add(newStar)
            session.commit()
            flash('New Star %s Item Successfully Created' % (newStar.name))
            return redirect(url_for('showStar', category_id=category_id))
        else:
            return render_template('newstar.html', category_id=category_id)
    return res

# Edit a star
@app.route('/category/<int:category_id>/star/<int:star_id>/edit', methods=['GET', 'POST'])
@login_required
def editStar(category_id, star_id):
    editedStar = session.query(Star).filter_by(id=star_id).one()
    category = session.query(Category).filter_by(id=category_id).one()
    res = is_authorized(category.user_id, login_session['user_id'])
    if res == True:
        if request.method == 'POST':
            if request.form['name']:
                editedStar.name = request.form.get('name')
            if request.form['description']:
                editedStar.description = request.form.get('description')
            if request.files['image']:
                file = request.files['image']
                filename = secure_filename(file.filename)
                path = url_for('static', filename=filename)
                file.save(os.getcwd()+path)
                editedStar.path = path
            session.add(editedStar)
            session.commit()
            flash('Star Successfully Edited.')
            return redirect(url_for('showStar', category_id=category_id))
        else:
            return render_template('editstar.html', category_id=category_id, star_id=star_id, star=editedStar)
    else:
        return res


# Delete a star
@app.route('/category/<int:category_id>/star/<int:star_id>/delete', methods=['GET', 'POST'])
@login_required
def deleteStar(category_id, star_id):
    category = session.query(Category).filter_by(id=category_id).one()
    starToDelete = session.query(Star).filter_by(id=star_id).one()
    res = is_authorized(category.user_id, login_session['user_id'])
    if res == True:
        if request.method == 'POST':
            session.delete(starToDelete)
            session.commit()
            flash('Star Item Successfully Deleted')
            return redirect(url_for('showStar', category_id=category_id))
        else:
            return render_template('deleteStar.html', star=starToDelete)
    else:
        return res


if __name__ == "__main__":
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host = '0.0.0.0', port = 5000)
