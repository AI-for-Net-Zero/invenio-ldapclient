#https://stackoverflow.com/questions/61358683/dependency-inversion-in-python

"""
UI:

POST /login 

   {
     username: <user_name>,
     password: <password>
   }

data -> login_form
login_form has validate method

REST:

POST /api/login

   {
     username: <user_name>,
     password: <password>
   }

data -> kwargs (webargs)
"""
