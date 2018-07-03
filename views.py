from models import Base, User, Category, Item
from flask import Flask, render_template, jsonify, request, url_for, \
    session as login_session, abort, g, make_response, flash, redirect
from sqlalchemy.ext.declarative import declarative_base  # noqa
from sqlalchemy.orm import relationship, sessionmaker  # noqa
from sqlalchemy import create_engine, desc, Column, String  # noqa
from oauth2client.client import flow_from_clientsecrets  # noqa
from oauth2client.client import FlowExchangeError  # noqa
import logging  # noqa
import random  # noqa
import string  # noqa
import json  # noqa
import httplib2  # noqa
import requests  # noqa
from flask_httpauth import HTTPBasicAuth  # noqa

# from flask.ext.httpauth import HTTPBasicAuth
auth = HTTPBasicAuth()

logging.basicConfig(level=logging.INFO)


engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Catalog Project"

# Create anti-forgery state token


@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)


@auth.verify_password
def verify_password(username_or_token, password):
    user_id = User.verify_auth_token(username_or_token)
    if user_id:
        user = session.query(User).filter_by(id=user_id).one()
    else:
        user = session.query(User).filter_by(
            username=username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


def createUser(login_session):
    newUser = User(username=login_session['username'], email=login_session[
                   'email'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

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
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

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
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps(
            'Current user is already connected.'),
            200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    # ADD PROVIDER TO LOGIN SESSION
    login_session['provider'] = 'google'

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(data["email"])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += '" style = "width: 300px; height: 300px; border-radius: 150px; \
    -webkit-border-radius: 150px; -moz-border-radius: 150px; ">'
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output


@app.route('/disconnect')
def disconnect():
    access_token = login_session.get('access_token')
    if access_token is None:
        print 'Access Token is None'
        response = make_response(json.dumps(
            'Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    print 'In gdisconnect access token is %s', access_token
    print 'User name is: '
    print login_session['username']
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' \
        % login_session[
            'access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print 'result is '
    print result
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        flash("Logged out successfully")
        return redirect('/', code=302)

    else:
        response = make_response(json.dumps(
            'Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return redirect('/', code=302)


@app.route('/users/<int:id>')
def get_user(id):
    user = session.query(User).filter_by(id=id).one()
    if not user:
        abort(400)
    return jsonify({'username': user.username, 'email': user.email})


@app.route('/', methods=['GET', 'POST'])
def showAllCategory():
    if request.method == 'GET':
        category = session.query(Category).all()
        items = session.query(Item, Category).join(
            Category, Item.category_id == Category.id
        ).order_by(desc(Item.id)).all()
        # if 'username' not in login_session:
        return render_template('publiccategory.html', category=category,
                               items=items, login_session=login_session)
        # else:
        #     return render_template('loggedincategory.html', category=category,
        #                            items=items)
    if request.method == 'POST':
        name = request.json.get('name')
        newItem = Category(cat_name=name)
        session.add(newItem)
        session.commit()
        return jsonify(newItem.serialize)


@app.route('/catalog/<name>/items', methods=['GET'])
def showAllItems(name):
    if request.method == 'GET':
        category = session.query(Category).all()
        this_cat = session.query(Category).filter_by(cat_name=name).one()
        items = session.query(Item).filter_by(category_id=this_cat.id).all()
        items_number = len(items)
        return render_template('categoryItems.html', items=items,
                               category=category, name=name,
                               number=items_number, this_cat=this_cat, login_session=login_session)


@app.route('/item/add/', methods=['GET', 'POST'])
def addItem():
    if request.method == 'GET':
        if 'username' not in login_session:
            flash("You have to log in to perform this action")
            return redirect("/login", code=302)
        category = session.query(Category).all()
        return render_template('addNewItem.html', category=category, login_session=login_session)
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        cat_id = request.form.get('cat_id')
        newItem = Item(item_title=title,
                       item_description=description, category_id=cat_id)
        session.add(newItem)
        session.commit()
        flash("Item Added Successfully")
        return redirect('/', code=302)


@app.route('/catalog/<name>/<item_name>', methods=['GET'])
def showItemDetails(name, item_name):
    if request.method == 'GET':
        item = session.query(Item).filter_by(item_title=item_name).first()
        return render_template('itemDetails.html', item=item, login_session=login_session)
        # else:
        #     return render_template('itemDetailsLogged.html', item=item)


@app.route('/catalog.json', methods=['GET'])
def showAllItemsJson():
    if request.method == 'GET':
        Cat = []
        category = session.query(Category).all()
        for i in category:
            items = session.query(Item).filter_by(category_id=i.id).all()
            items = [x.serialize for x in items]
            Cat.append({'id': i.id, 'name': i.cat_name, 'item': items})
        return jsonify(category=Cat)


@app.route('/catelog/<name>/delete/', methods=['GET', 'POST'])
def deleteItem(name):
    if request.method == 'GET':
        if 'username' not in login_session:
            flash("You have to log in to perform this action")
            return redirect("/login", code=302)
        item = session.query(Item).filter_by(item_title=name).first()
        return render_template('deleteConfirmation.html', item=item)
    if request.method == 'POST':
        item = session.query(Item).filter_by(item_title=name).first()
        session.delete(item)
        session.commit()
        flash("Item Deleted Successfully")
        return redirect('/', code=302)


@app.route('/catelog/<name>/edit/', methods=['GET', 'POST'])
def editItem(name):
    if request.method == 'GET':
        if 'username' not in login_session:
            flash("You have to log in to perform this action")
            return redirect("/login", code=302)
        item = session.query(Item).filter_by(item_title=name).first()
        category = session.query(Category).all()
        return render_template('editItem.html', item=item, category=category)
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        cat_id = request.form.get('cat_id')
        item_id = request.form.get('id')
        item = session.query(Item).filter_by(id=item_id).update(
            {'item_title': title,
                'item_description': description,
                'category_id': cat_id})
        session.commit()
        return redirect('/', code=302)


if __name__ == '__main__':
    # app.secret_key = 'super_secret_key'
    app.debug = True
    app.config['SECRET_KEY'] = ''.join(random.choice(
        string.ascii_uppercase + string.digits) for x in xrange(32))
    app.run(host='0.0.0.0', port=5000)
