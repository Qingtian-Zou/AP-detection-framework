import sys
import os

import numpy as np
np.random.seed(3)
from keras.layers import LSTM, Dense
from keras.models import Sequential
from sklearn.utils import shuffle
from keras import backend
import tensorflow as tf
from keras.backend.tensorflow_backend import set_session

def f1(y_true, y_pred):
    def recall(y_true, y_pred):
        """Recall metric.

        Only computes a batch-wise average of recall.

        Computes the recall, a metric for multi-label classification of
        how many relevant items are selected.
        """
        true_positives = backend.sum(backend.round(backend.clip(y_true * y_pred, 0, 1)))
        possible_positives = backend.sum(backend.round(backend.clip(y_true, 0, 1)))
        recall = true_positives / (possible_positives + backend.epsilon())
        return recall

    def precision(y_true, y_pred):
        """Precision metric.

        Only computes a batch-wise average of precision.

        Computes the precision, a metric for multi-label classification of
        how many selected items are relevant.
        """
        true_positives = backend.sum(backend.round(backend.clip(y_true * y_pred, 0, 1)))
        predicted_positives = backend.sum(backend.round(backend.clip(y_pred, 0, 1)))
        precision = true_positives / (predicted_positives + backend.epsilon())
        return precision
    precision = precision(y_true, y_pred)
    recall = recall(y_true, y_pred)
    return 2*((precision*recall)/(precision+recall+backend.epsilon()))


def perf_measure(y_actual, y_pred):
    TP = 0
    FP = 0
    TN = 0
    FN = 0
    for i in range(len(y_pred)):
        if y_actual[i] == y_pred[i] == 1:
            TP += 1
        if y_pred[i] == 1 and y_actual[i] != y_pred[i]:
            FP += 1
        if y_actual[i] == y_pred[i] == 0:
            TN += 1
        if y_pred[i] == 0 and y_actual[i] != y_pred[i]:
            FN += 1

    return(TP, FP, TN, FN)


def prep(xList, yList, window_size, window_step):
    X = []
    Y = []
    for i in range(len(xList)):
        line = xList[i]
        n = len(line)

        # truncate
        # X.append(line[0:windows_size])
        # Y.append(yList[i])

        # segment
        for j in range(0, n-window_size+1, window_step):
            if j+window_size <= len(line):
                X.append(line[j:j+window_size])
            else:
                X.append(line[n-window_size:n])
            Y.append(yList[i])

    X = np.array(X)
    Y = np.array(Y)
    return X, Y

# gpu configuration
config = tf.ConfigProto()
config.gpu_options.per_process_gpu_memory_fraction = 0.625
set_session(tf.Session(config=config))

# parameters
n_epoch = 3
n_batch = 50
window_step = 1
output_shape = 1  # total number of classes

packets_mal = np.load(
    'unique-types-sequence_fuzz-malicious.npy')
packets_mal = np.array(list(set(packets_mal.tolist())))
y_mal = np.ones((packets_mal.shape[0], 1))

packets_ben = np.load('unique-types-sequence_fuzz-normal.npy')
packets_ben = np.array(list(set(packets_ben.tolist())))
y_ben = np.zeros((packets_ben.shape[0], 1))

fi = open(".\\trained-models\\training.log", 'w')
fiout = fi
oldStdOut = sys.stdout
sys.stdout = fi
k = 0

hidden_LSTM_range = range(10, 31, 10)
n_hidden_range = range(5, 16, 5)
window_size_range = range(4, 17, 4)
window_step_range = [1, 2, 4, 6]

for hidden_LSTM in hidden_LSTM_range:
    for n_hidden in n_hidden_range:
        for window_size in window_size_range:
            for window_step in window_step_range:
                # find and remove double dipping
                same=[]
                X_mal_tmp, Y_mal_tmp=prep(packets_mal,y_mal,window_size,window_step)
                X_ben_tmp, Y_ben_tmp=prep(packets_ben,y_ben,window_size,window_step)
                X_mal_tmp=X_mal_tmp.tolist()
                X_ben_tmp=X_ben_tmp.tolist()
                i=0
                while(i<len(X_mal_tmp)):
                    if X_mal_tmp[i] in X_ben_tmp:
                        tmp=X_mal_tmp[i]
                        try:
                            while(True):
                                index_x=X_mal_tmp.index(tmp)
                                del(X_mal_tmp[index_x])
                        except ValueError:
                            try:
                                while(True):
                                    index_x=X_ben_tmp.index(tmp)
                                    del(X_ben_tmp[index_x])
                            except ValueError:
                                pass
                    else:
                        i+=1

                # find and remove duplicates
                tmp=[]
                for ele in X_mal_tmp:
                    tmp.append(tuple(ele))
                X_mal_tmp=list(set(tmp))
                Y_mal_tmp=np.ones(shape=(len(X_mal_tmp),1))

                tmp=[]
                for ele in X_ben_tmp:
                    tmp.append(tuple(ele))
                X_ben_tmp=list(set(tmp))
                Y_ben_tmp=np.zeros(shape=(len(X_ben_tmp),1))

                print("********************************")
                print("number of benign samples: %d"%len(X_ben_tmp))
                print("number of malicious samples: %d"%len(X_mal_tmp))

                X = np.array(X_mal_tmp+X_ben_tmp)
                Y = np.array(Y_mal_tmp.tolist()+Y_ben_tmp.tolist())
                X, Y = shuffle(X, Y, random_state=1)

                n_data = len(X)
                X_train, X_test = X[:n_data//5*4], X[n_data//5*4:]
                Y_train, Y_test = Y[:n_data//5*4], Y[n_data//5*4:]
                X_train = X_train.reshape(
                    X_train.shape[0], X_train.shape[1], 1)
                X_test = X_test.reshape(X_test.shape[0], X_test.shape[1], 1)

                # log training info
                fi.writelines([
                    "*********************************************************************************************************************************************\r",
                    "model parameter set "+str(k)+"\r",
                    "batch size: "+str(n_batch)+"\r",
                    "window size: "+str(window_size)+"\r",
                    "window step: "+str(window_step)+"\r",
                    "\r"
                ])  # "\n" is automatically append to the end of each line

                # NN: 4-fold cross validation
                acc = []
                TPs = []
                FPs = []
                TNs = []
                FNs = []
                for i in range(4):
                    print("################################################################################################################################", end="\r\n")
                    print("fold "+str(i+1)+"/"+str(4), end="\r\n")
                    tmp_train_x = X_train.tolist()
                    tmp_train_y = Y_train.tolist()
                    start = i*len(X_train)//4
                    end = (i+1)*len(X_train)//4
                    del(tmp_train_x[start:end])
                    del(tmp_train_y[start:end])
                    tmp_train_x = np.array(tmp_train_x)
                    tmp_train_y = np.array(tmp_train_y)
                    tmp_val_x = X_train[start:end]
                    tmp_val_y = Y_train[start:end]
                    model = Sequential()
                    model.add(LSTM(hidden_LSTM, input_shape=(
                        X_train.shape[1], X_train.shape[2])))
                    model.add(Dense(n_hidden, activation='relu'))
                    model.add(Dense(output_shape, activation='sigmoid'))
                    model.compile(loss='binary_crossentropy',
                                  optimizer='adam', metrics=[f1])
                    print(model.summary())
                    model.fit(tmp_train_x, tmp_train_y, validation_data=(
                        tmp_val_x, tmp_val_y), epochs=n_epoch, batch_size=n_batch)
                    scores = model.evaluate(
                        X_test, Y_test, batch_size=n_batch, verbose=0)
                    Y_predict = model.predict_classes(X_test)
                    Mat = perf_measure(Y_test, Y_predict)
                    acc.append(scores[1])
                    print("Model f1 score: %.3f" % (scores[1]*100))
                    print(Mat)
                    try:
                        model.save(".\\trained-models\\pth\\classifier-"+str(k)+"-"+str(i))
                    except FileNotFoundError as err:
                        os.mkdir(".\\trained-models\\pth")
                        model.save(".\\trained-models\\pth\\classifier-"+str(k)+"-"+str(i))
                    TPs.append(Mat[0])
                    FPs.append(Mat[1])
                    TNs.append(Mat[2])
                    FNs.append(Mat[3])

                # save the last model
                print("######################################################################################################", end="\r\n")
                print("all folds done", end="\r\n")
                print("average f1 score: %.3f" %
                      (100*sum(acc)/len(acc)), end="\r\n")
                print("average confusion matrix (TP,FP,TN.FN): (%.2f, %.2f, %.2f, %.2f)" % (
                    (sum(TPs)/len(TPs)), (sum(FPs)/len(FPs)), (sum(TNs)/len(TNs)), (sum(FNs)/len(FNs))))
                print("average false positive rate: %.3f%%" %
                      (100*sum(FPs)/(sum(FPs)+sum(TNs))))
                print("average false negative rate: %.3f%%" %
                      (100*sum(FNs)/(sum(FNs)+sum(TPs))))
                k += 1
                sys.stdout = oldStdOut
                print("Completed %d/%d" % (k, len(hidden_LSTM_range) *
                                           len(n_hidden_range)*len(window_size_range)*len(window_step_range)))
                sys.stdout = fiout

sys.stdout = oldStdOut
fi.close()
