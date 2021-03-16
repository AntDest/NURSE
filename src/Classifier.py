import os
import pickle
import pandas as pd
import numpy as np
import sklearn.feature_extraction
from src.utils.utils_file import file_join, FILE_CHUNK_SIZE
from src.utils.features import *
from src.utils.utils_variables import ENGLISH_WORDS

class DomainClassifier():
    classifier = None
    source_file = None

    def __init__(self, source="classifier"):
        self.get_classifier_from_file(source)

        with open(self.source_file, 'rb') as fin:
            self.classifier = pickle.load(fin)

        # Define the ngram counter
        # look for ngrams between 3 and 5 characters
        _english_ngrams_min_size = 3
        _english_ngrams_max_size = 5
        # min_df drops ngrams with frequency less than a threshold,
        # can affect precision, and speed up a bit the computation for the scores
        _ngram_freq_threshold = 1e-5
        self.english_counter = sklearn.feature_extraction.text.CountVectorizer(
            analyzer='char',
            ngram_range=(_english_ngrams_min_size, _english_ngrams_max_size),
            min_df=_ngram_freq_threshold
        )
        # Compute the ngrams counts over the English dictionary
        english_counts_matrix = self.english_counter.fit_transform(ENGLISH_WORDS)
        english_counts = english_counts_matrix.sum(axis=0).getA1()
        self.english_counts = np.log10(english_counts)




    def delete_file(self):
        if os.path.exists(self.source_file):
            os.remove(self.source_file)

    def get_classifier_from_file(self, source):
        if os.path.isdir(source):
            file_join(source, "classifier.save", FILE_CHUNK_SIZE)
            self.source_file = "classifier.save"
        else:
            self.source_file = source


    def compute_english_score(self, domain):
        return feature_english_score(domain, self.english_counter, self.english_counts)

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
            elif feature == "english_score":
                df_features["english_score"] = self.compute_english_score(ignore_TLD(domain))
            else:
                feature_function = feature_function_list[feature]
                df_features[feature] = df_features['domain'].apply(feature_function)

        df_features = df_features.astype(features_types)
        df_features = df_features.drop(["domain"], axis=1)

        return df_features.to_numpy()
