from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, backref
from sqlalchemy import create_engine

Base = declarative_base()

class User(Base):
	__tablename__ = "user"

	id = Column(Integer, primary_key = True)
	name = Column(String(250), nullable = False)
	email = Column(String(250), nullable = False)
	picture = Column(String(250))

class Category(Base):
	__tablename__ = "category"

	id = Column(Integer, primary_key = True)
	name = Column(String(250), nullable = False)
	user_id = Column(Integer, ForeignKey('user.id'))
	user = relationship(User)

	@property
	def serialize(self):
		""" Return object data in easily serializeable format"""
		return
		{
		   'name': self.name,
		   'id':self.id,
		}

class Star(Base):
	__tablename__ = "star"

	id = Column(Integer, primary_key = True)
	name = Column(String(250), nullable = False)
	description = Column(String(250))
	category_id = Column(Integer, ForeignKey('category.id'))
	category = relationship(Category, backref=backref('stars', uselist=True, cascade='delete,all'))
	path = Column(String(250))
	user_id = Column(Integer, ForeignKey('user.id'))
	user = relationship(User)

	@property
	def serialize(self):
		""" Return object data in easily serializeable format"""
		return
		{
		   'name':self.name,
		   'description' : self.description,
		   'id' : self.id,
		}

engine = create_engine('sqlite:///categorystarwithuser.db')

Base.metadata.create_all(engine)


