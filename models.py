from sqlalchemy import Column,Integer,String,ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine
from passlib.apps import custom_app_context as pwd_context
import random, string
from itsdangerous import(TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired)

Base = declarative_base()

#You will use this secret key to create and verify your tokens
secret_key = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))

class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    username = Column(String(32), index=True)
    password_hash = Column(String(64))
    email = Column(String(100))
    # col = Column('email', String(64))
    # col.create(user, populate_default=True)
   

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)
    #Add a method to generate auth tokens here
    def generate_auth_token(self, expiration=600):
        s = Serializer(secret_key, expires_in = expiration)
        return s.dumps({'id': self.id })
    #Add a method to verify auth tokens here
    @staticmethod
    def verify_auth_token(token):
            s = Serializer(secret_key)
            try:
                data = s.loads(token)
            except SignatureExpired:
                #Valid Token, but expired
                return None
            except BadSignature:
                #Invalid Token
                return None
            user_id = data['id']
            return user_id

class Category(Base):
    __tablename__ = 'category'
    id = Column(Integer, primary_key=True)
    cat_name = Column(String)

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
        'id' : self.id,
        'name' : self.cat_name,

            }


class Item(Base):
    __tablename__ = 'item'
    id = Column(Integer, primary_key=True)
    item_title = Column(String)
    item_description = Column(String)
    category_id = Column(Integer, ForeignKey('category.id'))
    category = relationship(Category)
    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
        'id' : self.id,
        'title' : self.item_title,
        'description' : self.item_description,
        'cat_id' : self.category_id,
            }

engine = create_engine('sqlite:///catalog.db')

Base.metadata.create_all(engine)
    