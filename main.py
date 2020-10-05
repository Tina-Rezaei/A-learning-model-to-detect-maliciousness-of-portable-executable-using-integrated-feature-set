import random
from sklearn.neighbors import KNeighborsClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn import tree
from sklearn import svm
from sklearn.model_selection import cross_validate
import numpy as np
import time
import click
import feature_extraction

start_time = time.time()
X = []
Y = []

def store_features(path):
    # saving final extracted features for probabilistic future use
    file = open(path, 'w')
    for i, x in enumerate(X):
        for item in x:
            file.write('{},'.format(str(item)))
        file.write(str(Y[i][0]) + '\n')
    file.close()


def load_features(path):
    X = []
    Y = []
    file = open(path, 'r')
    lines = file.readlines()
    for i, line in enumerate(lines):
        X.append([float(x) for x in line.split(',')[0:-1]])
        Y.append(int(line.split(',')[-1]))
    file.close()

    return X, Y


def load_data(malwarepath, benignpath, benignheaderfieldspath, malwareheaderfieldspath, malwaresectionnamespath,
              benignsectionnamespath):
    file = open(malwareheaderfieldspath, 'r')
    malware_header_fields = file.readlines()
    file.close()

    file = open(malwaresectionnamespath, 'r')
    malware_section_names = file.readlines()
    file.close()

    file = open(benignheaderfieldspath, 'r')
    benign_header_fields = file.readlines()
    file.close()

    file = open(benignsectionnamespath, 'r')
    benign_section_names = file.readlines()
    file.close()

    return malwarepath, benignpath, benign_header_fields, malware_header_fields, benign_section_names, malware_section_names

def log(message):
    print(message)


def final_features_extraction(path, header_fields, section_names, label):
    for i, row in enumerate(header_fields):

        final_features = []
        Y.append([label])
        row = row.split('\t,')
        sample_name = row[-1].strip('\n')

        # derived features
        entropies = feature_extraction.entropy(sample_name, path)
        final_features.append(entropies[0])
        final_features.append(entropies[1])
        final_features.append(entropies[2])

        sectionnames = section_names[i]
        sectionnames = sectionnames.split(',')
        sectionnames.remove(sectionnames[-1])
        section_name_features = feature_extraction.section_name_checker(sectionnames)
        final_features.append(section_name_features[0])
        final_features.append(section_name_features[1])

        final_features.append(feature_extraction.compilation_time(row[21]))

        final_features.append(feature_extraction.extract_file_size(sample_name, path))

        final_features.append(feature_extraction.extract_file_info(sample_name, path))

        final_features.append(feature_extraction.Image_Base_checker(row[34]))

        final_features.append(feature_extraction.sectionalignment_checker(int(row[35]), int(row[36])))

        final_features.append(feature_extraction.filealignment_checker(int(row[35]), int(row[36])))

        final_features.append(feature_extraction.sizeofimage_checker(int(row[44]), int(row[35])))

        final_features.append(feature_extraction.size_of_header_checker(sample_name, path))

        # Expanded features
        zerofill = bin(int(row[25]))[2:].zfill(16)
        characteristics = zerofill[0:6] + zerofill[7:]
        for c in characteristics:
            final_features.append(c)

        Dllzerofill = bin(int(row[48]))[2:].zfill(16)
        dllcharacteristics = Dllzerofill[5:]
        for d in dllcharacteristics:
            final_features.append(d)

        # raw features
        final_features.append(row[0])
        final_features.append(row[1])
        final_features.append(row[2])
        final_features.append(row[3])
        final_features.append(row[4])
        final_features.append(row[5])
        final_features.append(row[19])
        final_features.append(row[26])
        final_features.append(row[27])
        final_features.append(row[28])
        final_features.append(row[29])
        final_features.append(row[30])
        final_features.append(row[31])
        final_features.append(row[32])
        final_features.append(row[33])
        final_features.append(row[34])
        final_features.append(row[35])
        final_features.append(row[36])
        final_features.append(row[37])
        final_features.append(row[38])
        final_features.append(row[39])
        final_features.append(row[40])
        final_features.append(row[41])
        final_features.append(row[42])
        final_features.append(row[43])
        final_features.append(row[44])
        final_features.append(row[45])
        final_features.append(row[46])

        X.append(final_features)

    return X, Y


def learning(X, Y):
    algorithms = {
        "RandomForest": RandomForestClassifier(),
        "SVM": svm.SVC(),
        "Knn": KNeighborsClassifier(n_neighbors=5),
        "DecisionTree": tree.DecisionTreeClassifier(),
    }

    for algo in algorithms:
        start_time = time.time()
        clf = algorithms[algo]
        scores = cross_validate(clf, X, Y, cv=10, scoring=('accuracy', 'f1', 'recall', 'precision'))
        for score_name in ['test_accuracy', 'test_precision', 'test_recall', 'test_f1']:
            print('{} : {}'.format(score_name, np.mean(scores[score_name])))
        end_time = time.time()
        execution_time = end_time - start_time
        print('{} execution time {}'.format(algo, execution_time))


@click.command()
@click.option("--malwarepath", required=True, help="path of malware samples")
@click.option("--benignpath", required=True, help="path of benign samples")
@click.option("--benignheaderfieldspath", required=True, help="path of stored header fields file for benign samples")
@click.option("--malwareheaderfieldspath", required=True, help="path of stored header fields file for malware samples")
@click.option("--malwaresectionnamespath", required=True, help="path of stored header fields file for malware samples")
@click.option("--benignsectionnamespath", required=True, help="path of stored header fields file for malware samples")
def main(malwarepath, benignpath, benignheaderfieldspath, malwareheaderfieldspath, malwaresectionnamespath,
         benignsectionnamespath):

    malware_path, benign_path, benign_header_fields, malware_header_fields, benign_section_names, malware_section_names = \
        load_data(malwarepath, benignpath, benignheaderfieldspath, malwareheaderfieldspath, malwaresectionnamespath,
                  benignsectionnamespath)
    log("processing malwares for extracting features")
    X, Y = final_features_extraction(malware_path, malware_header_fields, malware_section_names, 1)

    log("processing benign samples for extracting features")
    X, Y = final_features_extraction(benign_path, benign_header_fields, benign_section_names, 0)

    global start_time
    end_time = time.time()
    feature_extraction_time = end_time - start_time
    print('feature extraction time {}'.format(feature_extraction_time))

    # saving final extracted features for probabilistic future use
    store_features('final_features.txt')

    # extracted features loading
    X, Y = load_features('final_features.txt')

    # shuffle
    start_time = time.time()
    features_label = list(zip(X, Y))
    random.shuffle(features_label)
    X, Y = zip(*features_label)

    # learning
    learning(X, Y)


if __name__ == '__main__':
    main()
