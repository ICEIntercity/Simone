from flask import Flask
from link import NeuralNetwork as NN
from link import analysis
from link import link
import numpy as np
import sys
import logging
import definitions

app = Flask(__name__)

log = logging.getLogger("simone_core")
log.setLevel(logging.DEBUG)

fh = logging.FileHandler(definitions.LOG_PATH)
fh.setLevel(logging.DEBUG)

ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)

formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)
ch.setFormatter(formatter)

log.addHandler(fh)
log.addHandler(ch)


@app.route('/')
def hello_world():
    np.set_printoptions(threshold=np.inf)
    nn = NN.NeuralNetwork()

    # TODO: Git Gud w/ python
    # TODO: learn 2 unit test (you n00b)
    test_data = link.build_input("http://132.148.30.34/cifrao.html")
    google_data = link.build_input("https://www.google.com/")

    test_result = nn.predict(test_data)
    google_result = nn.predict(google_data)

    print(test_result)
    print(google_result)

    return str(test_result[0][0])


if __name__ == '__main__':
    app.run()
