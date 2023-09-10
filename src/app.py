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
        print("Test")
        result = randomforest.check_phishing(received_email_data)
        #result = randomforest.has_zero_links_and_attachments(received_email_data)
    except Exception as e:
        print(f"Found missing data: {e}")
        return "This could be a phishing email. Please be cautious."
    return result


@app.route('/receive_email', methods=['POST'])
def receive_email():
    global received_email_data
    email_data = request.json
    print("Email data received...")
    #print(email_data)
    received_email_data = email_data

        # Extract the email content from the dictionary
    email_content = received_email_data.get('email_contents', '')  # Replace 'email_contents' with the actual key

    return Response("Success", content_type="text/plain")

if __name__ == '__main__':
    app.run(debug=True)



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