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

if __name__ == '__main__':
    app.run()



"""
    # Check if the email has zero links and zero attachments
    if randomforest.has_zero_links_and_attachments(email_content):
        print("This email has NO links and appears to be safe.")
        return "This email has zero links and zero attachments. It appears to be safe."
    else:
        print("This email contains links. Checking for phishing.")
        return "This email has links and/ or attachments."
        #checkemail()
"""