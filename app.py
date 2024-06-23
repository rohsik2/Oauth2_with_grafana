from flask import Flask, request, jsonify, session, redirect

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Secret key for session management

@app.route('/oauth/authorize', methods=['GET', 'POST'])
def authorize():
    if request.method == 'GET':
        redirect_uri = request.args.get('redirect_uri')
        state = request.args.get('state')
        session['user'] = 'fake_user'
        code = generate_authorization_code(session['user'])
        print(redirect(f"{redirect_uri}?code={code}&state={state}"))
        return redirect(f"{redirect_uri}?code={code}&state={state}")


    elif request.method == 'POST':
        if 'login' in request.form:
            # 로그인 양식 처리
            username = request.form['username']
            password = request.form['password']
            if validate_user(username, password):
                session['user'] = username
                return jsonify({"status": "success", "message": "Login successful. Consent required."})
            else:
                return jsonify({"status": "error", "message": "Invalid credentials"}), 401
        
        elif 'consent' in request.form:
            # 동의 양식 처리
            if 'user' in session:
                # 권한 부여 코드 생성 및 반환
                code = generate_authorization_code(session['user'])
                return jsonify({"status": "success", "code": code, "message": "Authorization code generated."})
            else:
                return jsonify({"status": "error", "message": "User not logged in"}), 401

def validate_user(username, password):
    # 사용자 자격 증명 검증 (실제 검증 로직으로 대체)
    return username == 'test' and password == 'test'

def generate_authorization_code(user):
    # 권한 부여 코드 생성 (실제 코드 생성 로직으로 대체)
    return 'auth_code_with_length_twenty'

@app.route('/oauth/token', methods=['POST'])
def token():
    print("tried to get toekn")
    grant_type = request.form.get('grant_type')
    code = request.form.get('code')
    if grant_type == 'authorization_code' and code == 'auth_code':
        # 하드코딩된 액세스 토큰 및 리프레시 토큰 반환
        return jsonify({
            "access_token": "hardcoded_access_token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "hardcoded_refresh_token",
            "scope": "read write"
        })
    else:
        return jsonify({"error": "invalid_grant"}), 400
    

@app.route('/oauth/userinfo', methods=['GET', 'POST'])
def userinfo():
    # For demonstration purposes, we are returning hardcoded minimal user information.
    # In a real application, this data would be retrieved from a database.
    user_info = {
        "sub": "248289761001",
        "name": "Jane Doe",
        "email": "janedoe@example.com"
    }

    return jsonify(user_info)

if __name__ == '__main__':
    app.run(debug=True, port=5050)