from flask import Flask, request, Response
from flask_cors import CORS
print("Importing randomforest into flask...")

import randomforest
print("Randomforest imported.")

app = Flask(__name__)
CORS(app)

@app.route('/check_email', methods=['POST'])
def check_email():
    email_data = request.json
    if not email_data or 'email_contents' not in email_data:
        return "No email content provided.", 400
        
    print("Getting phishing data...")
    try:
        result = randomforest.check_phishing(email_data)
    except Exception as e:
        print(f"Found missing data: {e}")
        return "This could be a phishing email. Please be cautious."
    return result

@app.route('/check_url', methods=['POST'])
def check_url():
    data = request.json
    if not data or 'url' not in data:
        return "No URL provided.", 400
    
    try:
        # This will require a new function in randomforest.py
        result = randomforest.check_phishing_url(data['url'])
    except Exception as e:
        print(f"Error checking URL: {e}")
        return "Could not process the URL."
    return result

if __name__ == '__main__':
    app.run()