# Catalog-App
Project 3 for Udacity Full-Stack Nanodegree


Description:
Users can create their own categories, and under each categories, user can
creat their favourite stars

To run:

start up vagrant using vagrant up
connect to the vagrant vm using vagrant ssh
go to the catalog directory using cd /vagrant/project3
setup database using python database_setup.py
prepopulate database using python lotof info.py
run the project using python project.py
go to localhost:5000/genres in your browser


Available API endpoints:

/category/json to get all the category name
/category/<int:category_id>/star/json to get all the stars for a given category
/category/<int:category_id>/star/<int:star_id>/json to get all the info about a certain star


There are three tables in database:
1.user: id name email
2.category: id, name, user_id(foreign key) user(relationship)
3.star: id, name, description, picture, user_id(foreign key), user(relationship), category_id(foreign key) category(relationship)

As a user, you can use google account to sign in and you can also create, update and delete your category.And under each category, you can create, update and delete your favourite star.