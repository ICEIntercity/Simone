from flask import Flask
from flask import request
from link import NeuralNetwork as NN
from link import analysis
import urllib.parse as urlparse
from link import link
from link import virustotal
from flask import jsonify
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


@app.route('/', methods=['GET', 'OPTIONS'])
def perform_analysis():
    np.set_printoptions(threshold=np.inf)
    nn = NN.NeuralNetwork()

    target_param = request.args.get('link')

    if target_param is None:
        return "'link' parameter must not be empty", 400

    target = urlparse.unquote(target_param)

    if link.validate_url(target):
        data = link.build_input(target)
    else:
        return "incorrect parameter format or invalid URL specified.", 400

    result = nn.classify(data)
    vt = virustotal.lookup(target)

    print(result)

    response = None

    if not vt:
        response = jsonify(
            classification=result[0],
            numeric=str(result[1])
        )
    else:
        response = jsonify(
            classification=result[0],
            numeric=str(result[1]),
            vt_link=vt[0],
            vt_positives=vt[1],
            vt_total=vt[2]
        )

    response.headers.add('Access-Control-Allow-Origin', '*')
    return response


if __name__ == '__main__':
    app.run()
