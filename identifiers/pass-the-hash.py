import sys
import os

import numpy as np
np.random.seed(3)
from keras.models import load_model
from keras import backend
import tensorflow as tf
from keras.backend.tensorflow_backend import set_session

# gpu configuration
config = tf.ConfigProto()
config.gpu_options.per_process_gpu_memory_fraction = 0.625
set_session(tf.Session(config=config))

try:
    model=load_model(".\\trained-models\\classifier-10")
except FileNotFoundError as err:
    print(err)
    print("model loading failed")
    exit(1)

# TODO: load new input

# TODO: get new predictions