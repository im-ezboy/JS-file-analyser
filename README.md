# JavaScript Security Analyzer

A comprehensive server-side JavaScript security analyzer that automatically discovers, analyzes, and verifies XSS vulnerabilities in JavaScript files. Built with Flask and featuring a modern dark-themed UI with Cloudflare-inspired orange accents.

## 🚀 Features

### Core Capabilities
- **Automatic JS File Discovery**: Enter a website URL and the analyzer automatically finds all JavaScript files
- **Comprehensive Security Analysis**: Detects API keys, credentials, emails, XSS vulnerabilities, and more
- **WAF Detection**: Automatically detects Web Application Firewalls (Cloudflare, AWS WAF, Akamai, etc.)
- **XSS Exploit Generation**: Automatically generates exploit payloads for detected XSS vulnerabilities
- **XSS Verification**: Built-in verification page to test XSS vulnerabilities with one click
- **Scan History**: View and reload previous scan results
- **Multi-file Support**: Analyze single files, multiple URLs, or upload a file with URLs

### Security Detection
- **API Keys**: AWS, Google, GitHub, Stripe, Slack, Firebase, JWT tokens, and generic API keys
- **Credentials**: Passwords, usernames, database credentials
- **Email Addresses**: Email patterns in code
- **XSS Vulnerabilities**: 
  - innerHTML/outerHTML assignments
  - document.write/writeln
  - eval() with user input
  - React dangerouslySetInnerHTML
  - jQuery .html() and .append()
  - Location manipulation
  - Event handlers
- **API Endpoints**: Extracted API paths and endpoints
- **Parameters**: Function parameters, URL parameters, request parameters
- **Paths/Directories**: File paths and directory references
- **Interesting Comments**: TODO, FIXME, SECURITY warnings, suspicious comments

## 📋 Requirements

- Python 3.8+
- Flask 3.0.3+
- requests 2.32.3+

## 🛠️ Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd js-analyzer-final
   ```

2. **Create a virtual environment** (recommended)
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the application**
   ```bash
   python3 run.py
   ```

5. **Access the web interface**
   ```
   http://localhost:5000
   ```

## 💻 Usage

### Web Interface

1. **New Scan Tab**
   - Enter a website URL (e.g., `https://example.com`) to automatically find all JS files
   - Or enter a direct JavaScript file URL (e.g., `https://example.com/app.js`)
   - Or upload a file containing URLs (one per line)

2. **History Tab**
   - View all previous scans
   - Click on any scan to reload its results

3. **XSS Verification**
   - When XSS vulnerabilities are detected, click "Verify XSS" to test the exploit
   - Copy the payload for manual testing
   - The verification page tests multiple vulnerable contexts

### API Endpoints

#### Analyze JavaScript Files
```http
POST /api/analyze
Content-Type: application/json

{
  "urls": ["https://example.com/app.js"]
}
```

Or upload a file:
```http
POST /api/analyze
Content-Type: multipart/form-data

file: <file containing URLs>
```

#### Get Scan Results
```http
GET /api/results/<session_id>
```

#### Get Scan History
```http
GET /api/history
```

#### Verify XSS
```http
GET /verify-xss?payload=<encoded_payload>&param=<parameter_name>
```

## 🏗️ Project Structure

```
js-analyzer-final/
├── run.py                 # Application entry point
├── requirements.txt       # Python dependencies
├── README.md             # This file
├── src/
│   └── js_analyzer/
│       ├── __init__.py
│       ├── app.py        # Flask app factory
│       ├── routes.py     # API and UI routes
│       ├── models.py     # Data models
│       ├── cli.py        # CLI interface
│       └── services/
│           ├── analyzer.py      # Core analysis logic
│           └── result_store.py  # Result storage
├── templates/
│   └── index.html        # Main UI template
└── static/
    ├── css/
    │   └── style.css     # Styling
    └── js/
        └── app.js        # Frontend logic
```

## 🔍 How It Works

1. **URL Input**: User provides a website URL or direct JS file URL
2. **JS File Discovery**: If a website URL is provided, the analyzer:
   - Fetches the HTML page
   - Extracts all `<script src="...">` tags
   - Collects all JavaScript file URLs
3. **WAF Detection**: Before fetching files, checks for WAF presence
4. **File Analysis**: For each JS file:
   - Downloads the file content
   - Scans for security patterns (API keys, credentials, XSS, etc.)
   - Generates exploit payloads for XSS vulnerabilities
   - Creates verification URLs
5. **Results Display**: Shows findings with severity levels, line numbers, and context

## 🎨 UI Features

- **Dark Theme**: Modern dark UI with Cloudflare-inspired orange accents
- **Tab-based Interface**: Separate tabs for "New Scan" and "History"
- **Real-time Analysis**: Live progress updates during scanning
- **Interactive Results**: Click on findings to view code context
- **XSS Verification**: One-click exploit testing
- **Responsive Design**: Works on desktop and mobile devices

## 🛡️ WAF Detection

The analyzer detects the following WAFs:
- Cloudflare
- AWS WAF
- Akamai
- Imperva (Incapsula)
- Sucuri
- Barracuda
- FortiWeb
- Generic WAF (by response patterns)

**Note**: If a WAF is detected, the scan stops immediately and only shows the WAF warning.

## 🔐 Security Considerations

- **Server-side Processing**: All analysis happens on the server - no client-side execution
- **File Size Limits**: Maximum 10MB per file to prevent resource exhaustion
- **Timeout Protection**: 60-second timeout for file downloads
- **Error Handling**: Graceful error handling with informative messages
- **No Code Execution**: The analyzer only reads and analyzes code - it never executes it

## 📝 Example Output

### XSS Vulnerability Detection
```
Type: innerHTML Assignment
Severity: high
Line: 23
Match: document.getElementById("content").innerHTML = userInput
Exploit Payload: <img src=x onerror=alert('XSS')>
Verify URL: https://example.com/?xss=%3Cimg%20src%3Dx%20onerror%3Dalert%28%27XSS%27%29%3E
```

### API Key Detection
```
Type: AWS Access Key ID
Severity: high
Line: 6
Match: AKIAIOSFODNN7EXAMPLE
```

## 🚧 Limitations

- Maximum 50 URLs per scan
- Maximum 10MB file size
- In-memory storage (sessions lost on restart)
- WAF detection may have false positives/negatives
- XSS verification requires the target site to be accessible

## 📄 License

This project is for authorized security testing and educational purposes only.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## ⚠️ Disclaimer

This tool is intended for authorized security testing only. Unauthorized use against systems you don't own or have permission to test is illegal. The authors are not responsible for any misuse of this software.

## 📞 Support

For issues, questions, or contributions, please open an issue on the repository.

---

**Made with ❤️ for the security community**
