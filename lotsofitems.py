from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Catalog, Base, CatalogItem, User

engine = create_engine('sqlite:///catalogwithuser.db')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
# A DBSession() instance establishes all conversations with the database
# and represents a "staging zone" for all the objects loaded into the
# database session object. Any change made against the objects in the
# session won't be persisted into the database until you call
# session.commit(). If you're not happy about the changes, you can
# revert all of them back to the last commit by calling
# session.rollback()
session = DBSession()

# Create dummy user
User1 = User(name="Abdallah Nasser", email="Abdallah@udacity.com",
             picture='https://scontent-cai1-1.xx.fbcdn.net/v/t1.0-9/13335831_1152255861487181_2947633699470977384_n.jpg?oh=a51b50fb44fb449885f08b0c200059c9&oe=5A4121C4')
session.add(User1)
session.commit()

# Menu for UrbanBurger
catalog1 = Catalog(user_id=1, name="First category")

session.add(catalog1)
session.commit()

menuItem2 = CatalogItem(user_id=1,
                        name="First category - item 1",
                        description="Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod"
                                    "tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam,"
                                    "quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo"
                                    "consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse"
                                    "cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non"
                                    "proident, sunt in culpa qui officia deserunt mollit anim id est laborum."
                                    "lorem The Boost Mobile Samsung Galaxy J7 features: Android 6.0 Marshmallow OS, ",
                        catalog=catalog1)

session.add(menuItem2)
session.commit()

menuItem1 = CatalogItem(user_id=1,
                        name="First category - item 2",
                        description="Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod"
                                    "tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam,"
                                    "quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo"
                                    "consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse"
                                    "cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non"
                                    "proident, sunt in culpa qui officia deserunt mollit anim id est laborum.",
                        catalog=catalog1)

session.add(menuItem1)
session.commit()
catalog1 = Catalog(user_id=1, name="Second Category")

session.add(catalog1)
session.commit()

menuItem2 = CatalogItem(user_id=1,
                        name="Second category - item 1",
                        description="Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod"
                                    "tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam,"
                                    "quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo"
                                    "consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse"
                                    "cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non"
                                    "proident, sunt in culpa qui officia deserunt mollit anim id est laborum.",
                        catalog=catalog1)

session.add(menuItem2)
session.commit()

menuItem1 = CatalogItem(user_id=1,
                        name="Second category - item 2",
                        description="Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod"
                                    "tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam,"
                                    "quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo"
                                    "consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse"
                                    "cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non"
                                    "proident, sunt in culpa qui officia deserunt mollit anim id est laborum.",
                        catalog=catalog1)

session.add(menuItem1)
session.commit()
print "done adding items!"
