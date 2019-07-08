from flask import Flask
from link import link as LinkAI
from link import analysis
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
    link = LinkAI.Link()


    test_ip = analysis.detect_ip("http://192.168.1.1/something.php")
    test_redirect = analysis.check_short_url('https://tinyurl.com/y6ypdyg')


    # TODO: Git Gud w/ python
    # TODO: learn 2 unit test (you n00b)
    test_data = np.array(([[1 , -1, 1, 1, 1, -1, -1, 0, 1, 1, -1, 1, 1, 0, -1, -1, -1, -1, 0, 1, 1, 1, 1, -1, 1, 1, -1, 1, 1, -1],
                           [1, 1, 1, 1, 1, -1, -1, 1, 1, 1, 1, -1, -1, 0, -1, -1, -1, -1, 0, 1, 1, 1, 1, 1, -1, -1, 1, 1, -1, -1]]))

    print(test_data.shape)

    test_result = link.model.predict(x=test_data, batch_size=None, verbose=1)
    print(test_result)
    return "It works!"


if __name__ == '__main__':
    app.run()
