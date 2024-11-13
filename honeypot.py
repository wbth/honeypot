import os
import socket
import threading
from flask import Flask, request, jsonify, session, redirect, abort

# Simulasi Database dan Direktori
USERS = {"admin": "password123", "user": "userpass"}
UPLOAD_DIR = "./uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)
LOG_FILE = "./honeypot.log"
SENSITIVE_CONFIG = {"api_key": "supersecretapikey123", "admin_email": "admin@example.com"}

# Flask Web Server
web_app = Flask(__name__)
web_app.secret_key = "honeypot_secret_key"

def log_attack(attack_type, details):
    """
    Catat serangan ke file log.
    """
    with open(LOG_FILE, "a") as log:
        log.write(f"[{attack_type}] {details}\n")


### 1. SQL Injection (Termasuk Blind SQL Injection)
@web_app.route('/login', methods=['POST'])
def sql_injection():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    log_attack("SQL Injection", f"Attempted login with {username}:{password}")

    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    log_attack("SQL Query", query)

    if "' OR 1=1 --" in username or "' OR 1=1 --" in password:
        return jsonify({"message": "Login bypassed with SQL Injection!", "query": query}), 200

    if "1' AND SLEEP(5) --" in username:
        import time
        time.sleep(5)
        return jsonify({"message": "Blind SQL Injection detected!"}), 200

    if username in USERS and USERS[username] == password:
        return jsonify({"message": "Login successful!"}), 200

    return jsonify({"message": "Invalid credentials", "query": query}), 401


### 2. XSS: DOM, Reflected, Stored
@web_app.route('/comment', methods=['POST'])
def xss():
    comment = request.form.get("comment", "")
    log_attack("XSS", f"Comment posted: {comment}")
    return f"<p>Comment posted: {comment}</p>", 200


@web_app.route('/dom_xss', methods=['GET'])
def dom_xss():
    log_attack("DOM XSS", "Accessed DOM XSS endpoint")
    return """
    <script>
    var comment = window.location.hash.substring(1);
    document.write("<p>Comment: " + comment + "</p>");
    </script>
    """


### 3. File Inclusion
@web_app.route('/include', methods=['GET'])
def file_inclusion():
    filepath = request.args.get("file", "")
    log_attack("File Inclusion", f"Included file: {filepath}")
    try:
        with open(filepath, "r") as file:
            return file.read(), 200
    except FileNotFoundError:
        return "File not found.", 404


### 4. File Upload
@web_app.route('/upload', methods=['POST'])
def file_upload():
    uploaded_file = request.files.get("file")
    if not uploaded_file:
        return "No file uploaded!", 400
    filepath = os.path.join(UPLOAD_DIR, uploaded_file.filename)
    uploaded_file.save(filepath)
    log_attack("File Upload", f"File uploaded: {filepath}")
    return "File uploaded successfully!", 200


### 5. Insecure CAPTCHA
@web_app.route('/captcha', methods=['POST'])
def insecure_captcha():
    answer = request.form.get("captcha", "")
    if answer == "1234":
        log_attack("Insecure CAPTCHA", "Bypassed CAPTCHA")
        return "CAPTCHA solved!", 200
    return "CAPTCHA failed!", 403


### 6. Weak Session IDs
@web_app.route('/login_weak', methods=['POST'])
def weak_session_id():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    if username in USERS and USERS[username] == password:
        session['session_id'] = "123456"
        log_attack("Weak Session IDs", f"Session started for {username}")
        return "Login successful! Weak session ID issued.", 200
    return "Invalid credentials!", 401


### 7. CSP Bypass
@web_app.route('/csp_bypass', methods=['GET'])
def csp_bypass():
    log_attack("CSP Bypass", "Accessed CSP bypass endpoint")
    return """
    <html>
    <head>
        <meta http-equiv="Content-Security-Policy" content="script-src 'unsafe-inline';">
    </head>
    <body>
        <h1>Welcome!</h1>
        <script>alert('CSP Bypass');</script>
    </body>
    </html>
    """


### 8. JavaScript Vulnerabilities
@web_app.route('/js_vuln', methods=['GET'])
def js_vuln():
    log_attack("JavaScript Vulnerability", "Accessed JavaScript vulnerability endpoint")
    return """
    <script>
    var user = {username: "admin", isAdmin: true};
    document.write("User is admin: " + user.isAdmin);
    </script>
    """


### 9. IDOR (Insecure Direct Object References)
FAKE_FILES = {"1": "Confidential Report", "2": "Public Document", "3": "Internal Memo"}
@web_app.route('/files/<file_id>', methods=['GET'])
def idor():
    log_attack("IDOR", f"Accessed file ID: {file_id}")
    if file_id in FAKE_FILES:
        return jsonify({"file_content": FAKE_FILES[file_id]}), 200
    return jsonify({"error": "File not found"}), 404


### 10. FTP Service
def handle_ftp_client(client_socket):
    client_socket.send(b"220 Welcome to the FTP server.\n")
    while True:
        data = client_socket.recv(1024).decode('utf-8').strip()
        log_attack("FTP Attempt", f"Command received: {data}")
        if data.lower() == "quit":
            client_socket.send(b"221 Goodbye.\n")
            break
        client_socket.send(b"502 Command not implemented.\n")
    client_socket.close()

def start_ftp_service(host="0.0.0.0", port=21):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(5)
    print(f"FTP service running on {host}:{port}")
    while True:
        client_socket, addr = server.accept()
        log_attack("FTP Connection", f"Connection from {addr}")
        threading.Thread(target=handle_ftp_client, args=(client_socket,)).start()


### 11. Telnet Service
def handle_telnet_client(client_socket):
    client_socket.send(b"Welcome to Telnet service\n")
    while True:
        data = client_socket.recv(1024).decode('utf-8').strip()
        log_attack("Telnet Attempt", f"Command received: {data}")
        if data.lower() == "exit":
            client_socket.send(b"Goodbye.\n")
            break
        client_socket.send(b"Invalid command.\n")
    client_socket.close()

def start_telnet_service(host="0.0.0.0", port=23):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(5)
    print(f"Telnet service running on {host}:{port}")
    while True:
        client_socket, addr = server.accept()
        log_attack("Telnet Connection", f"Connection from {addr}")
        threading.Thread(target=handle_telnet_client, args=(client_socket,)).start()


### 12. Kernel Exploit Simulation
@web_app.route('/kernel_exploit', methods=['POST'])
def kernel_exploit():
    exploit_code = request.form.get("code", "")
    log_attack("Kernel Exploit", f"Exploit attempted: {exploit_code}")
    if "privilege_escalation" in exploit_code:
        return jsonify({"message": "Kernel exploit detected! System compromised."}), 200
    return jsonify({"message": "No exploit detected."}), 400


### 13. Open HTTP Redirect
@web_app.route('/redirect', methods=['GET'])
def open_redirect():
    url = request.args.get("url", "/")
    log_attack("Open Redirect", f"Redirected to {url}")
    return redirect(url)


### 15. CSRF
@web_app.route('/transfer', methods=['POST'])
def csrf():
    csrf_token = session.get("csrf_token")
    submitted_token = request.form.get("csrf_token")
    amount = request.form.get("amount", "0")
    if not csrf_token or csrf_token != submitted_token:
        log_attack("CSRF", f"Invalid CSRF token. Attempted transfer of {amount}")
        return jsonify({"error": "Invalid CSRF token"}), 403
    log_attack("CSRF", f"Transfer initiated: {amount}")
    return jsonify({"message": f"Transferred {amount} successfully!"}), 200

@web_app.route('/get_csrf_token', methods=['GET'])
def get_csrf_token():
    session['csrf_token'] = "static_token"
    return jsonify({"csrf_token": session['csrf_token']}), 200


### 16. Unvalidated Redirects and Forwards
@web_app.route('/redirect_unsafe', methods=['GET'])
def unvalidated_redirect():
    url = request.args.get("url", "/")
    log_attack("Unvalidated Redirect", f"Redirected to {url}")
    return redirect(url)


### 17. Information Disclosure
@web_app.route('/info', methods=['GET'])
def info_disclosure():
    log_attack("Info Disclosure", "Accessed sensitive metadata")
    return jsonify({
        "system_info": os.uname(),
        "sensitive_config": SENSITIVE_CONFIG
    }), 200


### 18. Security Misconfiguration
@web_app.route('/debug', methods=['GET'])
def security_misconfiguration():
    log_attack("Security Misconfiguration", "Debug mode accessed")
    return abort(500, description="Debug mode is enabled!"), 500


### 19. Improper Error Handling
@web_app.route('/error', methods=['GET'])
def improper_error_handling():
    error = request.args.get("error")
    try:
        if error == "division":
            1 / 0
    except Exception as e:
        log_attack("Improper Error Handling", f"Error triggered: {str(e)}")
        return str(e), 500
    return "No error triggered", 200


### 20. Insecure Deserialization
@web_app.route('/deserialize', methods=['POST'])
def insecure_deserialization():
    import pickle
    serialized_data = request.data
    log_attack("Insecure Deserialization", f"Received data: {serialized_data}")
    try:
        obj = pickle.loads(serialized_data)
        return jsonify({"message": "Deserialization successful", "data": obj}), 200
    except Exception as e:
        return jsonify({"error": "Deserialization failed", "details": str(e)}), 400


### 21. Business Logic Vulnerabilities
@web_app.route('/discount', methods=['POST'])
def business_logic_bypass():
    user_role = request.form.get("role", "user")
    discount = 10 if user_role == "user" else 50
    log_attack("Business Logic Bypass", f"Role: {user_role}, Discount: {discount}")
    return jsonify({"discount": discount}), 200

### SSH Service
def handle_ssh_client(client_socket):
    client_socket.send(b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1\n")
    while True:
        data = client_socket.recv(1024).decode('utf-8').strip()
        log_attack("SSH Attempt", f"Command: {data}")
        if data.lower() in ["exit", "quit"]:
            client_socket.send(b"Goodbye.\n")
            break
        client_socket.send(b"Permission denied.\n")
    client_socket.close()

def start_ssh_service(host="0.0.0.0", port=2222):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(5)
    print(f"SSH service running on {host}:{port}")
    while True:
        client_socket, addr = server.accept()
        log_attack("SSH Connection", f"Connection from {addr}")
        threading.Thread(target=handle_ssh_client, args=(client_socket,)).start()


### Main Honeypot Integration
def start_honeypot():
    threading.Thread(target=start_ssh_service, daemon=True).start()

    web_app.run(host="0.0.0.0", port=5555)


if __name__ == "__main__":
    print("Starting Babarsari43 Honeypot...")
    start_honeypot()
