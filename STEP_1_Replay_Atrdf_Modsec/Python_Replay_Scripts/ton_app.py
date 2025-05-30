from flask import Flask, request

app = Flask(__name__)

@app.route('/', defaults={'subpath': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
@app.route('/<path:subpath>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
def catch_all(subpath):
    print("Path:", subpath)
    print("Args:", dict(request.args))
    print("Body:", request.get_data())
    print("Cookies:", request.cookies)
    return "OK", 200

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000)

