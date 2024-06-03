from flask import Flask
from loginpage import otp_routes
from user import user_routes
from flask_mail import Mail
from flasgger import Swagger
from flask_cors import CORS
from flask_jwt_extended import JWTManager

app=Flask(__name__)
CORS(app, supports_credentials=True)

@app.route('/')
def homepage():
    return "<h1>Welcome</h1>"

app.register_blueprint(otp_routes)
app.register_blueprint(user_routes)

# CORS(app)

app.config['SWAGGER']={
    'title':'Access Management-api',
    'uiversion': 3
}
Swagger(app)

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = 'aapmorblogs@gmail.com'
app.config['MAIL_PASSWORD'] = 'vzyolkoiczhkmixa'

mail=Mail(app)
jwt=JWTManager()
jwt.init_app(app)

if __name__=="__main__":
    app.run(debug=True)