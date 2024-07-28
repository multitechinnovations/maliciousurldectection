from flask import Flask, request, jsonify, render_template
import pickle
from model import train_and_save_model, preprocess_url

app = Flask(__name__)

# Call the training function when the app starts
train_and_save_model()

# Load the trained XGBoost model
with open("model.pkl", "rb") as model_file:
    model = pickle.load(model_file)

# Load the scaler
with open("scaler.pkl", "rb") as scaler_file:
    scaler = pickle.load(scaler_file)

# Load the label encoder
with open("label_encoder.pkl", "rb") as label_encoder_file:
    label_encoder = pickle.load(label_encoder_file)

# Define the endpoint for making predictions
@app.route('/predict', methods=['POST'])
def predict():
    try:
        # Get form data from the request
        url = request.form['url']

        # Preprocess the URL features
        url_features = preprocess_url(url)

        # Scale the features
        scaled_features = scaler.transform([url_features])

        # Make the prediction
        prediction = model.predict(scaled_features)[0]

        # Decode the prediction label
        predicted_label = label_encoder.inverse_transform([prediction])[0]

        # Return the prediction as JSON
        result = {'prediction': predicted_label}
        return render_template('index.html', prediction_text=result['prediction'])

    except Exception as e:
        return jsonify({'error': str(e)})

# Route for rendering the HTML page
@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
