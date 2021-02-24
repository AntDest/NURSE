import os
import pandas as pd
import pickle
from src.utils.utils_file import file_join, FILE_CHUNK_SIZE
from src.utils.features import *


class DomainClassifier():
    classifier = None
    source_file = None

    def __init__(self, source="classifier"):
        self.get_classifier_from_file(source)

        with open(self.source_file, 'rb') as fin:
            self.classifier = pickle.load(fin)

    def delete_file(self):
        os.remove("classifier.save")

    def get_classifier_from_file(self, source):
        if os.path.isdir(source):
            file_join(source, "classifier.save", FILE_CHUNK_SIZE)
            self.source_file = "classifier.save"
        else:
            self.source_file = source
    

    def compute_features(self, domain):
        # map the features names to the functions
        df_features = pd.DataFrame()
        df_features["domain"] = [domain]
        for feature in feature_function_list:
            if feature == "3gram_avg":
                # compute the 3 grams
                df_features['3gram_avg'], df_features['3gram_std'] = \
                        zip(*df_features['domain'].map(lambda x:feature_ngrams_distribution(ignore_TLD(x), 3)))
            elif feature == "3gram_std": 
                continue # already computed in avg_3gram
            else:
                feature_function = feature_function_list[feature]
                df_features[feature] = df_features['domain'].apply(lambda x: feature_function(x))

        df_features = df_features.astype(features_types)
        df_features = df_features.drop(["domain"], axis=1)

        return df_features.to_numpy()
    



