from flask import Flask, jsonify
from flask_restful import Api
from flask_jwt_extended import JWTManager
from marshmallow import ValidationError
from flask_uploads import configure_uploads, patch_request_class
from dotenv import load_dotenv

from db import db
from ma import ma
from oa import oauth
from blocklist import BLOCKLIST
from resources.user import UserRegister, UserLogin, User, TokenRefresh, UserLogout, SetPassword
from resources.item import Item, ItemList
from resources.store import Store, StoreList
from resources.order import Order
from resources.confirmation import Confirmation, ConfirmationByUser
from resources.image import ImageUpload, Image, AvatarUpload, Avatar
from libs.image_helper import IMAGE_SET
from flask_migrate import Migrate
from resources.github_login import GithubLogin, GithubAuthorize


app = Flask(__name__)
load_dotenv(".env", verbose=True)
app.config.from_object("default_config")
app.config.from_envvar(
    "APPLICATION_SETTINGS"
)  # override with config.py (APPLICATION_SETTINGS points to config.py)
patch_request_class(app, 10 * 1024 * 1024)  # restrict max upload image size to 10MB
configure_uploads(app, IMAGE_SET)
# app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL")
# app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
# app.config["PROPAGATE_EXCEPTIONS"] = True
# app.secret_key = os.environ.get(
#     "APP_SECRET_KEY"
# )  # could do app.config['JWT_SECRET_KEY'] if we prefer
api = Api(app)
migrate = Migrate(app, db)


@app.before_first_request
def create_tables():
    db.create_all()
# with app.app_context():
#     db.create_all()


@app.errorhandler(ValidationError)
def handle_marshmallow_validation(err):
    return jsonify(err.messages), 400


jwt = JWTManager(app)


@jwt.additional_claims_loader
def add_claims_to_jwt(
    identity
):  # Remember identity is what we define when creating the access token
    if (
        identity == 1
    ):  # instead of hard-coding, we should read from a file or database to get a list of admins instead
        return {"is_admin": True}
    return {"is_admin": False}


# This method will check if a token is blocklisted, and will be called automatically when blocklist is enabled
@jwt.token_in_blocklist_loader
def check_if_token_in_blocklist(jwt_header, jwt_payload):
    return jwt_payload["jti"] in BLOCKLIST
    # return (
    #     jwt_payload["jti"] in BLOCKLIST
    # )  # Here we blocklist particular JWTs that have been created in the past.


# The following callbacks are used for customizing jwt response/error messages.
# The original ones may not be in a very pretty format (opinionated)
@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify({"message": "The token has expired.", "error": "token_expired"}), 401


@jwt.invalid_token_loader
def invalid_token_callback(
    error
):  # we have to keep the argument here, since it's passed in by the caller internally
    return (
        jsonify(
            {"message": "Signature verification failed.", "error": "invalid_token"}
        ),
        401,
    )


@jwt.unauthorized_loader
def missing_token_callback(error):
    return (
        jsonify(
            {
                "description": "Request does not contain an access token.",
                "error": "authorization_required",
            }
        ),
        401,
    )


@jwt.needs_fresh_token_loader
def token_not_fresh_callback(jwt_header, jwt_payload):
    return (
        jsonify(
            {"description": "The token is not fresh.", "error": "fresh_token_required"}
        ),
        401,
    )


@jwt.revoked_token_loader
def revoked_token_callback(jwt_header, jwt_payload):
    return (
        jsonify(
            {"description": "The token has been revoked.", "error": "token_revoked"}
        ),
        401,
    )


api.add_resource(Store, "/store/<string:name>")
api.add_resource(StoreList, "/stores")
api.add_resource(Item, "/item/<string:name>")
api.add_resource(ItemList, "/items")
api.add_resource(UserRegister, "/register")
api.add_resource(User, "/user/<int:user_id>")
api.add_resource(UserLogin, "/login")
api.add_resource(TokenRefresh, "/refresh")
api.add_resource(UserLogout, "/logout")
api.add_resource(Confirmation, "/user_confirm/<string:confirmation_id>")
api.add_resource(ConfirmationByUser, "/confirmation/user/<int:user_id>")
api.add_resource(ImageUpload, "/upload/image")
api.add_resource(Image, "/image/<string:filename>")
api.add_resource(AvatarUpload, "/upload/avatar")
api.add_resource(Avatar, "/avatar/<int:user_id>")
api.add_resource(GithubLogin, "/login/github")
api.add_resource(GithubAuthorize, "/login/github/authorized", endpoint="github.authorize")
api.add_resource(SetPassword, "/user/password")
api.add_resource(Order, "/order")

if __name__ == "__main__":
    db.init_app(app)
    ma.init_app(app)
    oauth.init_app(app)
    app.run(port=5000)
