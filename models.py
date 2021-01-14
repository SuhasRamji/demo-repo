import psycopg2
from flask import Flask,g
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Sequence, create_engine, DateTime
from sqlalchemy.orm import relationship, sessionmaker
from datetime import datetime

app = Flask(__name__)


app.config['SQLALCHEMY_TRACE_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://suhas:qwerty@localhost:5432/newnormal'
db = SQLAlchemy(app)

MY_URI =

class Users(db.Model):

	__tablename__ = 'users'

	id = db.Column(db.INTEGER,Sequence('user_id_seq') , primary_key=True)
	name = db.Column(db.String(25), unique=True, nullable=False)
	mail = db.Column(db.String(25), nullable=True, default = 'No email address')
	mobile = db.Column(db.Integer(), nullable=False)
	address = db.Column(db.String(25), nullable = False)
	organization_id = db.Column(db.String(25), nullable = False)

	user_orders = db.relationship('Order', backref='user', lazy='dynamic')

	def __init__(self, name, mail, mobile, address, organization_id):
		self.name = name
		self.mail = mail
		self.mobile = mobile
		self.address = address
		self.organization_id = organization_id

class Country(db.Model):

	__tablename__ = 'countries'

	id = db.Column(db.INTEGER, Sequence('country_id_seq'), primary_key=True)
	country_name = db.Column(db.String(50), nullable = False)
	country_code = db.Column(db.String(30), nullable = False)
	ISO_code = db.Column(db.String(25), nullable = False)

	def __init__(self, country_name, country_code, ISO_code):
		self.country_name = country_name
		self.country_code = country_code
		self.ISO_code = ISO_code


class State(db.Model):

	__tablename__ = 'indian_states'

	id = db.Column(db.INTEGER, Sequence('state_id_seq'), primary_key=True)
	state_name = db.Column(db.String(50), nullable=False)
	state_code = db.Column(db.String(5), nullable=False)
	country_id = db.Column(db.Integer, db.ForeignKey('countries.id'))
	cities = db.relationship('City', backref='city')

	def __init__(self, state_name, state_code, country_id ):
		self.state_name = state_name
		self.state_code = state_code
		self.country_id = country_id

class City(db.Model):

	__tablename__ = 'city'

	#City -id, Name, pincode, state_id
	id = db.Column(db.INTEGER, Sequence('city_id_seq'), primary_key=True)
	city_name = db.Column(db.String(50), nullable=False)
	pincode = db.Column(db.Integer(), nullable=False)
	state_id = db.Column(db.Integer(), db.ForeignKey('indian_states.id'))
