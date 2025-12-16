from __future__ import annotations

import uuid
from pathlib import Path
from typing import Iterable, List
from flask import Blueprint, Flask, jsonify, render_template, request, send_from_directory

from .services.analyzer import JavaScriptAnalyzer
from .services.result_store import ResultStore

MAX_URLS = 50


def register_routes(app: Flask, analyzer: JavaScriptAnalyzer, store: ResultStore) -> None:
    project_root = Path(__file__).resolve().parent.parent.parent
    ui_bp = Blueprint("ui", __name__)
    api_bp = Blueprint("api", __name__)

    @ui_bp.route("/")
    def index():
        return render_template("index.html")

    @api_bp.route("/api/health", methods=["GET"])
    def health():
        return jsonify({"status": "ok"})

    @api_bp.route("/api/analyze", methods=["POST"])
    def analyze():
        try:
            urls = _collect_urls_from_request(request)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

        # Check if URLs are HTML pages and extract JS files
        all_js_urls = []
        original_urls = []
        page_extraction_info = []
        
        for url in urls:
            url = url.strip()
            original_urls.append(url)
            
            # Check if URL looks like an HTML page (not ending with .js)
            if not url.endswith((".js", ".mjs")) and not url.endswith("/"):
                # Try to extract JS files from the page
                js_files = analyzer.extract_js_files_from_page(url)
                if js_files:
                    all_js_urls.extend(js_files)
                    page_extraction_info.append({
                        "page": url,
                        "js_files_count": len(js_files)
                    })
                else:
                    # If no JS files found, treat it as a direct JS file
                    all_js_urls.append(url)
            else:
                # Direct JS file
                all_js_urls.append(url)
        
        # Limit total URLs
        if len(all_js_urls) > MAX_URLS:
            return jsonify({"error": f"Too many URLs found ({len(all_js_urls)}), max {MAX_URLS}"}), 400
        
        if not all_js_urls:
            return jsonify({"error": "No JavaScript files found to analyze"}), 400

        session_id = str(uuid.uuid4())
        store.create_session(session_id, len(all_js_urls), original_urls)
        results = []

        for idx, url in enumerate(all_js_urls, start=1):
            try:
                result = analyzer.analyze(url)
                payload = result.to_dict()
            except Exception as exc:  # pragma: no cover - defensive
                payload = {
                    "url": url,
                    "errors": [f"Analysis failed: {exc}"],
                    "api_keys": [],
                    "credentials": [],
                    "emails": [],
                    "interesting_comments": [],
                    "xss_vulnerabilities": [],
                    "xss_functions": [],
                    "api_endpoints": [],
                    "parameters": [],
                    "paths_directories": [],
                    "file_size": 0,
                    "analysis_timestamp": "",
                }
            payload["file_id"] = idx
            store.add_result(session_id, payload)
            results.append(payload)

        return jsonify({
            "session_id": session_id,
            "total_files": len(results),
            "results": results,
            "extraction_info": page_extraction_info if page_extraction_info else None
        })

    @api_bp.route("/api/results/<session_id>", methods=["GET"])
    def get_results(session_id: str):
        session = store.get(session_id)
        if not session:
            return jsonify({"error": "Session not found"}), 404
        return jsonify(session.to_dict())

    @api_bp.route("/api/file/<session_id>/<int:file_id>", methods=["GET"])
    def get_file(session_id: str, file_id: int):
        session = store.get(session_id)
        if not session:
            return jsonify({"error": "Session not found"}), 404
        file = next((f for f in session.files if f.get("file_id") == file_id), None)
        if not file:
            return jsonify({"error": "File not found"}), 404
        return jsonify(file)

    @api_bp.route("/api/history", methods=["GET"])
    def get_history():
        """Get all scan history sessions."""
        sessions = store.get_all_sessions()
        return jsonify({
            "sessions": [s.to_dict() for s in sessions],
            "total": len(sessions)
        })

    @ui_bp.route("/verify-xss")
    def verify_xss():
        """XSS verification page - renders payload in vulnerable context."""
        from flask import request
        payload = request.args.get('payload', '')
        param = request.args.get('param', 'xss')
        
        # Decode payload
        from urllib.parse import unquote
        try:
            decoded_payload = unquote(payload)
        except Exception:
            decoded_payload = payload
        
        # Create vulnerable HTML page
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>XSS Verification Test</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 50px auto;
            padding: 20px;
            background: #0a0e27;
            color: #e5e7eb;
        }}
        .container {{
            background: rgba(15, 20, 41, 0.9);
            border: 1px solid rgba(246, 130, 31, 0.3);
            border-radius: 14px;
            padding: 20px;
        }}
        .vulnerable-area {{
            background: rgba(239, 68, 68, 0.1);
            border: 2px dashed rgba(239, 68, 68, 0.5);
            padding: 20px;
            margin: 20px 0;
            border-radius: 8px;
        }}
        .payload-info {{
            background: rgba(246, 130, 31, 0.1);
            padding: 15px;
            border-radius: 8px;
            margin: 15px 0;
        }}
        code {{
            background: rgba(0, 0, 0, 0.3);
            padding: 2px 6px;
            border-radius: 4px;
            color: #F6821F;
        }}
        h1 {{ color: #F6821F; }}
        h2 {{ color: #ef4444; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>⚠️ XSS Verification Test Page</h1>
        <div class="payload-info">
            <strong>Parameter:</strong> <code>{param}</code><br>
            <strong>Payload:</strong> <code>{decoded_payload}</code>
        </div>
        
        <h2>Vulnerable Contexts:</h2>
        
        <div class="vulnerable-area">
            <h3>1. innerHTML Assignment:</h3>
            <div id="test1"></div>
            <script>
                document.getElementById('test1').innerHTML = '{decoded_payload.replace("'", "\\'")}';
            </script>
        </div>
        
        <div class="vulnerable-area">
            <h3>2. document.write():</h3>
            <script>
                document.write('{decoded_payload.replace("'", "\\'")}');
            </script>
        </div>
        
        <div class="vulnerable-area">
            <h3>3. Direct Injection:</h3>
            {decoded_payload}
        </div>
        
        <div class="vulnerable-area">
            <h3>4. URL Parameter Display:</h3>
            <p>Parameter value: <span id="param-display"></span></p>
            <script>
                const urlParams = new URLSearchParams(window.location.search);
                const paramValue = urlParams.get('{param}') || '{decoded_payload}';
                document.getElementById('param-display').innerHTML = paramValue;
            </script>
        </div>
        
        <div style="margin-top: 30px; padding: 15px; background: rgba(34, 197, 94, 0.1); border-radius: 8px;">
            <strong>✅ If you see an alert or the payload executed, the XSS vulnerability is confirmed!</strong>
        </div>
    </div>
</body>
</html>"""
        return html

    @api_bp.route("/<path:filename>", methods=["GET"])
    def serve_js(filename: str):
        if filename.startswith(("api/", "static/", "templates/")):
            return jsonify({"error": "Not found"}), 404
        if not filename.endswith(".js"):
            return jsonify({"error": "File not found"}), 404
        try:
            return send_from_directory(project_root, filename, mimetype="application/javascript")
        except FileNotFoundError:
            return jsonify({"error": f"File {filename} not found"}), 404

    app.register_blueprint(ui_bp)
    app.register_blueprint(api_bp)


def _collect_urls_from_request(req) -> List[str]:
    """Normalize URLs from JSON body or uploaded file."""
    urls: List[str] = []
    if req.is_json:
        data = req.get_json() or {}
        urls_input = data.get("urls") or data.get("url")
        if isinstance(urls_input, str):
            urls = [urls_input]
        elif isinstance(urls_input, Iterable):
            urls = list(urls_input)
    elif "file" in req.files:
        file_storage = req.files["file"]
        if not file_storage or not file_storage.filename:
            raise ValueError("No file uploaded")
        content = file_storage.read().decode("utf-8", errors="ignore")
        urls = [line.strip() for line in content.splitlines() if line.strip() and not line.strip().startswith("#")]
    else:
        raise ValueError("No file or JSON data provided")

    urls = [u.strip() for u in urls if isinstance(u, str) and u.strip()]
    if not urls:
        raise ValueError("URL(s) are required")
    if len(urls) > MAX_URLS:
        raise ValueError(f"Too many URLs provided (max {MAX_URLS})")
    return urls

