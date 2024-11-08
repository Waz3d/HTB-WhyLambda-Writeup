from flask import Flask, send_from_directory, jsonify, request, Response
from flask_cors import CORS
import os
import string
import random
import json
import random
from tensorflow import keras
from keras.datasets import mnist
from keras.utils.np_utils import to_categorical
from keras.models import Sequential
from keras.layers.core import Dense, Dropout, Activation


# Initialize Flask app
app = Flask(__name__)

# Enable CORS for all origins (Access-Control-Allow-Origin: *)
#This is necessary to allow the server to download our attack_model.h5
CORS(app, supports_credentials=True)

def message(content: str):
    return jsonify({"message": content})
    

def test_model(path):
    m = keras.models.load_model(path)
    #metrics = m.evaluate(X_test, Y_test)
    return message("ok")    

@app.route('/my_file', methods=['GET'])
def serve_file():
    filename = 'attack_model.h5'

    if os.path.exists(os.path.join(".", filename)):
        
        response = send_from_directory(".", filename, as_attachment=True, mimetype='application/octet-stream')
        response.headers['Content-Disposition'] = 'attachment; filename=model.h5'
        return response
    else:
        return jsonify({'error': 'File not found'}), 404

@app.route('/', methods=['GET'])
def read_flag():
    # Get the 'flag' query parameter from the request
    flag = request.args.get('flag')
    
    # Print the value of 'flag' to the console
    if flag:
        print(f"Flag parameter received: {flag}")
    else:
        print("No flag parameter received.")
    
    # Return the 'flag' value in the response
    return jsonify({
        "message": "Flag received",
        "flag": flag
    })
# Start the Flask server
if __name__ == '__main__':
    app.run(debug=True, port=3333)
