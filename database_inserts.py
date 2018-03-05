from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Base, CatalogItem, Category

engine = create_engine('sqlite:///catalog.db')

Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

category4 = Category(name="Tennis")
session.add(category4)
session.commit()
category5 = Category(name="Rugby")
session.add(category5)
session.commit()
category6 = Category(name="Winter Sports")
session.add(category6)
session.commit()
category7 = Category(name="Handball")
session.add(category7)
session.commit()
category8 = Category(name="Golf")
session.add(category8)
session.commit()
category9 = Category(name="Volleyball")
session.add(category9)
session.commit()
category10 = Category(name="Other")
session.add(category10)
session.commit()

print "added categories!"
