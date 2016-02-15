from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Category, Base, Star, User

engine = create_engine('sqlite:///categorystarwithuser.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()

# Create dummy user
User1 = User(name="Robo Barista", email="tinnyTim@udacity.com",
             picture='https://pbs.twimg.com/profile_images/2671170543/18debd694829ed78203a5a36dd364160_400x400.png')
session.add(User1)
session.commit()

# star for Music
category1 = Category(user_id=1, name="Pop Music")
session.add(category1)
session.commit()

star1 = Star(user_id=1, name = "Britney Spears", description="The Best performer ever!", 
	         category = category1, path ="/static/1.jpg")
session.add(star1)
session.commit()

# star for Tennis
category2 = Category(user_id=1, name="Tennis")
session.add(category2)
session.commit()

star1 = Star(user_id=1, name = "Novak Djokovic", description="The Best ATP player!", 
	         category = category2, path= "/static/2.jpg")
session.add(star1)
session.commit()

star2 = Star(user_id=1, name = "Maria Sharapova", description="The Best WTA player!", 
	         category = category2, path = "/static/3.jpg")
session.add(star2)
session.commit()
stars = session.query(Star).filter_by(category_id=2).all()




