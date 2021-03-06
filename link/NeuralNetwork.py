from __future__ import absolute_import, division, print_function, unicode_literals

import tensorflow as tf
import numpy as np
from tensorflow import keras
import pandas as pd
import os.path as path
import traceback
import logging
import config
import definitions
import enum

class NeuralNetwork:
    log = None
    model = None

    def __init__(self, force_rebuild=False):
        self.log = logging.getLogger('simone_core')
        self.log.info('Instantiating Link NN...')
        self.log.info('TensorFlow version: ' + tf.version.VERSION + ' (Keras ' + tf.keras.__version__ + ')a ')

        if path.isfile(path.join(definitions.ROOT_DIR, config.nn['modelFile'])) and not force_rebuild:
            self.log.debug('Found persistence file, loading model...')
            self.__load()
        else:
            self.log.debug('No persistence file found, creating a new model...')
            self.__create()

    def __load(self):
        new_model = keras.Sequential()
        new_model.add(keras.layers.Input(shape=(21,)))
        new_model.add(keras.layers.Dense(100, activation=keras.activations.relu))
        new_model.add(keras.layers.Dense(70, activation=keras.activations.relu))
        new_model.add(keras.layers.Dense(45, activation=keras.activations.relu))
        new_model.add(keras.layers.Dropout(0.2))
        new_model.add(keras.layers.Dense(20, activation=keras.activations.relu))
        new_model.add(keras.layers.Dropout(0.2))
        new_model.add(keras.layers.Dense(10, activation=keras.activations.sigmoid))
        new_model.add(keras.layers.Dropout(0.2))
        new_model.add(keras.layers.Dense(1, activation=keras.activations.sigmoid))

        # new_model.summary()

        self.model = new_model
        self.model.compile(optimizer=tf.train.AdamOptimizer(0.002),
                           loss=keras.losses.binary_crossentropy,
                           metrics=['mae', 'accuracy'])

        try:
            self.model = tf.keras.models.load_model(path.join(definitions.ROOT_DIR, config.nn['modelFile']))
            self.log.debug('Successfully loaded model.')
        except Exception:
            self.log.error('Exception while loading model file. Operation could not be completed: '
                           + traceback.format_exc())

    def __create(self):
        new_model = keras.Sequential()
        new_model.add(keras.layers.Input(shape=(21,)))
        new_model.add(keras.layers.Dense(100, activation=keras.activations.relu, input_shape=(21,)))
        new_model.add(keras.layers.Dense(70, activation=keras.activations.relu))
        new_model.add(keras.layers.Dense(45, activation=keras.activations.relu))
        new_model.add(keras.layers.Dropout(0.2))
        new_model.add(keras.layers.Dense(20, activation=keras.activations.relu))
        new_model.add(keras.layers.Dropout(0.2))
        new_model.add(keras.layers.Dense(10, activation=keras.activations.sigmoid))
        new_model.add(keras.layers.Dropout(0.2))
        new_model.add(keras.layers.Dense(1, activation=keras.activations.sigmoid))

        # Debug output - uncomment for extra information
        # new_model.summary()
        self.log.debug(new_model.summary())

        self.model = new_model
        self.model.compile(optimizer=tf.keras.optimizers.Adam(),
                           loss=keras.losses.binary_crossentropy,
                           metrics=['mae', 'accuracy'])
        self.train(config.nn['dataFile'])
        self.__persist()

    def __persist(self):
        try:
            self.model.save(path.join(definitions.ROOT_DIR, config.nn['modelFile']))
            self.log.debug('Model saved successfully: ' + config.nn['modelFile'])
        except Exception:
            self.log.error('CRITICAL: Could not export model (File: ' + config.nn['modelFile'] + ')')

    def train(self, training_file):

        training_data = pd.read_csv(training_file, sep=',', error_bad_lines=False)

        print(training_data)

        train_x = training_data.drop(columns=['Result', 'id'])  # Training input
        train_y = training_data[['Result']]  # Training output
        train_y = train_y.replace(-1, 0)

        self.model.fit(x=train_x, y=train_y, epochs=100, batch_size=32, verbose=2, validation_split=0.1)

    def classify(self, input_data) -> tuple:
        num_result = self.model.predict(x=input_data, batch_size=None, verbose=1)

        if num_result < 0.3:
            return "Phishing", num_result[0][0]
        else:
            if num_result > 0.7:
                return "Clean", num_result[0][0]
            else:
                return "Unknown", num_result[0][0]

