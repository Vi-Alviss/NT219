def register_auth_routes(app):
    from .routes import auth_bp
    app.register_blueprint(auth_bp)
