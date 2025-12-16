from pathlib import Path
from flask import Flask
from flask_cors import CORS

from .routes import register_routes
from .services.analyzer import JavaScriptAnalyzer
from .services.result_store import ResultStore


def create_app() -> Flask:
    # Project root: .../js-analyzer-final
    project_root = Path(__file__).resolve().parent.parent.parent
    app = Flask(
        __name__,
        static_folder=str(project_root / "static"),
        template_folder=str(project_root / "templates"),
    )
    CORS(app)

    analyzer = JavaScriptAnalyzer()
    store = ResultStore()
    register_routes(app, analyzer, store)
    return app

