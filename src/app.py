from flask import Flask, request, jsonify
import randomforest

app = Flask(__name__)

@app.route('/predict_phishing', methods=['POST'])
def predict_phishing():
    email_content = request.json['email_content']
    
    # Preprocess and predict using the RandomForest model
    preprocessed_email_content = randomforest.preprocess_email_content(email_content)

    email_features = randomforest.transform_email_to_features(preprocessed_email_content)

    phishing_prediction = randomforest.rf.predict(email_features)
    
    return jsonify({"prediction": float(phishing_prediction)})

if __name__ == '__main__':
    app.run(debug=True)
