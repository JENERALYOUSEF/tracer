from flask import Flask, send_from_directory, jsonify, request
import os

app = Flask(__name__)

# Serve static files
@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

@app.route('/<path:path>')
def serve_file(path):
    return send_from_directory('.', path)

# Create challenge directories
CHALLENGE_DIRS = {
    'web': './challenges/web',
    'forensics': './challenges/forensics',
    'osint': './challenges/osint',
    'crypto': './challenges/crypto',
    'steganography': './challenges/steganography',
    'linux': './challenges/linux'
}

# Create directories if they don't exist
for directory in CHALLENGE_DIRS.values():
    os.makedirs(directory, exist_ok=True)

# Example Web Challenge - Hidden Source
@app.route('/challenges/web/hidden-source')
def web_hidden_source():
    return """
    <!-- flag{source_master} -->
    <h1>Find the flag in the source!</h1>
    """

# Example Cookie Challenge
@app.route('/challenges/web/cookie-monster')
def web_cookie_monster():
    response = app.make_response("Check the cookies!")
    response.set_cookie('secret_flag', 'flag{cookie_hunter}')
    return response

# Example Robots Challenge
@app.route('/robots.txt')
def robots_txt():
    return """
    User-agent: *
    Disallow: /secret-area

    # flag{robots_rule}
    """

# Example SQL Injection Challenge
@app.route('/challenges/web/sql-login', methods=['GET', 'POST'])
def sql_login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        # Vulnerable SQL logic (for demonstration)
        if "' OR '1'='1" in username or "' OR '1'='1" in password:
            return jsonify({'success': True, 'flag': 'flag{sql_master}'})
        return jsonify({'success': False})
    
    return """
    <form method="POST">
        <input type="text" name="username" placeholder="Username">
        <input type="password" name="password" placeholder="Password">
        <button type="submit">Login</button>
    </form>
    """

if __name__ == '__main__':
    app.run(debug=True, port=5000)
