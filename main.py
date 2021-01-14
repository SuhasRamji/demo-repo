from flask_restful import Api, Resource, fields, marshal_with, abort
from flask import Flask, request, make_response, jsonify, g, redirect, url_for
from models import *
from users_service import *
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm.exc import UnmappedInstanceError
from errorhandlers import *
import re
import datetime
import jwt
from functools import wraps
import logging


app.debug = True
app.config['SECRET_KEY'] = 'thisisasecretkey'

resource_fields = {

	'id': fields.Integer,
	'name': fields.String,
	'email': fields.String,
	'address': fields.String,
	'mobile': fields.String,
	'organization_id':fields.String
}

res_field_list = {

	"Users" : fields.List(fields.Nested(resource_fields), attribute="items")
}

#Decorator for user logs
def log_decorator(original_function):
	logging.basicConfig(filename='{}.log'.format(original_function.__name__), level=logging.INFO)
	@wraps(original_function)
	def write_logs(*args, **kwargs):
		logging.info(
			'Operation ran on the {} by the user {}'.format(original_function.__name__,args, kwargs)
		)
		return original_function(*args, **kwargs)

	return write_logs


#Decorator for login token generation
def token_required(f):
	@wraps(f)
	def decorated(*args, **kwargs):
		token = None
		public_key = open(r'C:\Users\I354822\PycharmProjects\UserInfo\DB contents\jwt-key.pub').read()



		if 'x-access-token' in request.headers:
			token = request.headers['x-access-token']

		if not token:
			return jsonify({'message':'Token is missing'})

		try:
			data = jwt.decode(token, public_key, algorithms=['RS256'])
			current_user = None
			current_user = Users.query.filter_by(id = data['id']).first()
			print(current_user)
		except:
			#print(str(current_user) + 'This is decoded data')
			return jsonify({'message': 'Token is invalid'})

		return f(current_user, *args, **kwargs)

	return decorated

@app.before_request
#@token_required
def before_request():

	org_id = request.json.get('org_id')
	if org_id:
		g.org_id = org_id


@app.route('/users')
@marshal_with(res_field_list)
@log_decorator
def showusers():
	"""Gives the list of all the users"""
	users_list = ShowAllUsers()
	return users_list

@app.route('/users', methods=['POST'])
@log_decorator
def createUser():

	"""Create the User with the validation of the formats
	    of the email id and mobile number"""

	userdata = request.get_json()

	emailPattern = '^\w+[@][a-z]+.[a-z]{2,3}'
	mobilePattern = '^[0-3]{3}'

	validate_email = re.match(emailPattern, userdata['mail'])
	validate_mobile = re.match(mobilePattern, userdata['mobile'])


	if validate_email:

		if validate_mobile:
			newuser = AddUser(userdata)
			return newuser
		else:
			raise BadRequest("Invalid Mobile number")
	else:
		raise BadRequest("Invalid Email address")


@app.route('/orders',methods=['POST'])
@marshal_with(res_field_list)
def orders():

	user_id = request.json.get('user_id')
	print(user_id)
	user = Users.query.filter_by(id=user_id).first()
	print(user.name, g.org_id)

	o = GetUserItems()

	print(o)


@app.route('/users/<id>', methods = ['DELETE'])
@log_decorator
def deleteUser(current_user, id):
	"""Delete the user with the specific ID"""
	deletedUser = DeleteUser(id)
	return deletedUser

@app.route('/users/<int:mobile>')
@marshal_with(res_field_list)
@log_decorator
def getUser(mobile):
	"""Search the user using the mobile number of the user"""
	MobileUser = SearchUser(mobile)
	return MobileUser

@app.route('/users/<int:id>', methods = ['PUT'])
@log_decorator
def updateUser(current_user, id):
	"""This API endpoint updates the user details given the ID of the user"""
	req = request.get_json()
	updatedUser = UpdateUser(req, id)
	return updatedUser

@app.route('/login',methods=['GET'])

def login():

	private_key = open(r'C:\Users\I354822\PycharmProjects\UserInfo\DB contents\jwt-key').read()

	auth = request.authorization
	print(auth)
	if not auth or not auth.username:
		return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login Required"'})

	user  = Users.query.filter_by(name=auth.username).first()
	print(user)
	if not user:
		return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login Required"'})

	token = jwt.encode({'id':user.id,
	                    'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=60)}, private_key, algorithm='RS256')

	# decod = jwt.decode(token, app.config['SECRET_KEY'])
	# print(decod)
	return jsonify({'token': token.decode('UTF-8')})




#========================================================================================================
#Error handlers
@app.errorhandler(ResourceNotFound)
def resource_not_found(e):
	"""
	Takes the ResourceNotFound from errorhandlers file
	:param e:
	:return:
	"""
	print('Exception:'+str(e))
	return {
		'message': str(e),
		'status_code': 404
	}

@app.errorhandler(500)
def internal_server_error(e):
	return ("Internal Server error. please try after sometime")

@app.errorhandler(BadRequest)
def bad_request(e):
	print('Exception:'+str(e))
	return {
		'message': str(e),
		'status_code' : 400
	}

if __name__ == '__main__':
	app.run()