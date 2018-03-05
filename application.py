#!/usr/bin/env python

from flask import Flask, render_template, request, redirect, jsonify, url_for
from flask import flash
from sqlalchemy import create_engine, asc, desc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, CatalogItem, User
from flask import session as login_session
import random
import string
from oauth2client.client import flow_from_clientsecrets, FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

app = Flask(__name__)
engine = create_engine('sqlite:///catalog.db')

# Constants
# To run application you need to get your own Fb and Google client ids
CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Catalog"

DBSession = sessionmaker(bind=engine)
session = DBSession()


@app.route('/login')
def showLogin():
    # randomized state variable
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


@app.route('/googleconnect', methods=['POST'])
# Method used for google login
def gconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter'), 401)
        response.header['Content-Type'] = 'application/json'
        return response
    code = request.data
    try:
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(json.dumps(
            'Failed to upgrade authorization code'), 401)
        response.header['Content-Type'] = 'application/json'
        return response
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' %
           access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])

    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 50)
        response.header['Content-Type'] = 'application/json'

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
        print("Token's client ID does not match app's.")
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps(
            'Current user is already connected.'), 200)
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
    output += ''' " style = "width: 300px; height: 300px;border-radius: 150px;
                -webkit-border-radius: 150px;-moz-border-radius: 150px;"> '''
    flash("you are now logged in as %s" % login_session['username'])
    return output


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
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps(
            'Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print("access token received %s " % access_token)

    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = '''https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s''' % (  # noqa
        app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.8/me"
    token = result.split(',')[0].split(':')[1].replace('"', '')

    url = '''https://graph.facebook.com/v2.8/me?access_token=%s&fields=name,id,email''' % token  # noqa
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout
    login_session['access_token'] = token

    # Get user picture
    url = 'https://graph.facebook.com/v2.8/me/picture?access_token=%s&redirect=0&height=200&width=200' % token  # noqa
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id
    # Build response
    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ''' " style = "width: 300px; height: 300px;border-radius:
     150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '''

    flash("Now logged in as %s" % login_session['username'])
    return output


@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (
        facebook_id, access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"


@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            del login_session['access_token']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']

        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('catalog'))
    else:
        flash("You were not logged in to begin with!")
        redirect(url_for('catalog'))


@app.route('/catalog/JSON')
def catalogJSON():
    categories = session.query(Category).order_by(asc(Category.name))
    items = session.query(CatalogItem).order_by(desc(CatalogItem.id)).limit(
        categories.count())
    return jsonify(Categories=[i.serialize for i in categories],
                   Items=[i.serialize for i in items])


@app.route('/')
@app.route('/catalog/')
def catalog():
    categories = session.query(Category).order_by(asc(Category.name))
    items = session.query(CatalogItem).order_by(desc(CatalogItem.id)).limit(
        categories.count())
    itemList = []
    for item in items:
        item.category_name = session.query(Category).filter_by(
            id=item.category_id).one().name
        itemList.append(item)
    # if user is not logged in he gets public page
    if 'username' not in login_session:
        return render_template('publicindex.html', categories=categories,
                               items=itemList)
    else:
        return render_template('index.html', categories=categories,
                               items=itemList)


@app.route('/catalog/add/', methods=['GET', 'POST'])
# adding a catalog item
def addItem():
    if 'username' not in login_session:
        return redirect('/login')
    categories = session.query(Category).all()
    if request.method == 'POST':
        category = session.query(Category).filter_by(
            name=request.form['category']).one()
        category_id = category.id
        user_id = login_session['user_id']
        # price is stored in cents so we need to multiply
        newItem = CatalogItem(name=request.form['name'],
                              description=request.form['description'],
                              price=(float(request.form['price'])*100),
                              category_id=category_id,
                              user_id=user_id)
        session.add(newItem)
        session.commit()
        flash('New Item %s Successfully Created' % newItem.name)
        return redirect(url_for('catalog'))
    else:
        return render_template('additem.html', categories=categories)


@app.route('/catalog/<string:category_name>/Items/JSON')
def categoryListJSON(category_name):
    category = session.query(Category).filter_by(name=category_name).one()
    items = session.query(CatalogItem).filter_by(category_id=category.id)
    return jsonify(Items=[i.serialize for i in items])


@app.route('/catalog/<string:category_name>/Items/')
def categoryList(category_name):
    category = session.query(Category).filter_by(name=category_name).one()
    items = session.query(CatalogItem).filter_by(category_id=category.id)
    return render_template('category.html', category=category, items=items)


@app.route('/catalog/<int:category_id>/<string:item_name>/')
def redirectItem(category_id, item_name):
    category_name = getCategoryNameById(category_id)
    return redirect('/catalog/%s/%s/' % (category_name, item_name))


@app.route('/catalog/<string:category_name>/<string:item_name>/JSON')
def ItemJSON(category_name, item_name):
    category = session.query(Category).filter_by(name=category_name).one()
    item = session.query(CatalogItem).filter_by(name=item_name,
                                                category_id=category.id).one()
    return jsonify(Item=[item.serialize])


@app.route('/catalog/<string:category_name>/<string:item_name>/')
def Item(category_name, item_name):
    category = session.query(Category).filter_by(name=category_name).one()
    item = session.query(CatalogItem).filter_by(name=item_name,
                                                category_id=category.id).one()
    creator = getUserInfo(item.user_id)
    # show public page if not owner
    if 'username' not in login_session or creator.id != login_session[
                                                                    'user_id']:
        return render_template('publicitem.html', item=item, category=category)
    else:
        return render_template('item.html', item=item, category=category)


@app.route('/catalog/<string:category_name>/<string:item_name>/edit',
           methods=['GET', 'POST'])
# Handling of editing items
def editItem(category_name, item_name):
    if 'username' not in login_session:
        return redirect('/login')
    categories = session.query(Category).all()
    category = session.query(Category).filter_by(name=category_name).one()
    editedItem = session.query(CatalogItem).filter_by(
        name=item_name, category_id=category.id).one()
    if request.method == 'POST':
        # edit the item with the fields that have values
        if request.form['name']:
            editedItem.name = request.form['name']
        if request.form['description']:
            editedItem.description = request.form['description']
        if request.form['price']:
            # price is stored in cents so we need to multiply
            editedItem.price = (float(request.form['price'])*100)
        if request.form['category']:
            category = session.query(Category).filter_by(
                name=request.form['category']).one()
            editedItem.category_id = category.id
        session.add(editedItem)
        session.commit()
        flash('Item %s Successfully Edited' % editedItem.name)
        return redirect(url_for('catalog'))
    else:
        # return the template
        return render_template('editItem.html', categories=categories,
                               item=editedItem, itemCategory=category.name)


@app.route('/catalog/<string:category_name>/<string:item_name>/delete',
           methods=['GET', 'POST'])
# Handling of item deletion
def deleteItem(category_name, item_name):
    # Check if user is logged in
    if 'username' not in login_session:
        return redirect('/login')
    category = session.query(Category).filter_by(name=category_name).one()
    item = session.query(CatalogItem).filter_by(
        name=item_name, category_id=category.id).one()
    if request.method == 'POST':
        # delete the item
        session.delete(item)
        session.commit()
        flash('Item %s Successfully Deleted' % item.name)
        return redirect(url_for('catalog'))
    else:
        # return the template
        return render_template(
            'deleteItem.html', item=item, itemCategory=category.name)


# ---Helper Functions---
def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def createUser(login_session):
    newUser = User(name=login_session['username'],
                   email=login_session['email'],
                   picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getCategoryNameById(category_id):
    category = session.query(Category).filter_by(id=category_id).one()
    return category.name

if __name__ == '__main__':
    app.secret_key = 'very_special_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
