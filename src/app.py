from flask import Flask, request, Response
from flask_cors import CORS
print("Importing randomforest into flask...")

import randomforest
print("Randomforest imported.")

app = Flask(__name__)
CORS(app)

received_email_data = None

@app.route('/')
def checkemail():
    global received_email_data
    if received_email_data == None:
        print("Ready to check.")
        return "Ready to check"
    print("Getting phishing data...")
    try:
        result = randomforest.check_phishing(received_email_data)
    except Exception as e:
        print(f"Found missing data: {e}")
        return "This could be a phishing email. Please be cautious."
    return result


@app.route('/receive_email', methods=['POST'])
def receive_email():
    global received_email_data
    email_data = request.json
    print("Email data received...")
    received_email_data = email_data
    checkemail()
    return Response("Success", content_type="text/plain")

if __name__ == '__main__':
    app.run(debug=True)