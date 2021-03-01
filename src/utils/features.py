from collections import Counter
import wordninja
import math
from src.utils.utils_variables import ENGLISH_WORDS, IANA_TLD_LIST, LETTERS, CONSONANTS, VOWELS, DIGITS, VALID_CHARS
import numpy as np

# FEATURES IMPLEMENTATIONS


def ignore_TLD(domain):
    """Returns the domain without its TLD if the TLD is in the IANA list of TLDs
      example.com -> example
      google.nl -> google
      example.aba -> example.aba (not in IANA list)
      test -> test (no TLD)
    """
    if "." not in domain:
        # no TLD in domain, return the domain as it is
        return domain
    else:
        tld = domain.split(".")[-1]
        if tld in IANA_TLD_LIST:
            return ".".join(domain.split(".")[:-1])
        else:
            return domain


def feature_TLD_id(domain):
    """returns the index of the TLD if it is in IANA list, -1 if it is not"""
    if "." not in domain:
        # domain has no TLD
        return False
    else:
        tld = domain.split(".")[-1]
        try:
            return IANA_TLD_LIST.index(tld)
        except ValueError:
            return -1


def ngram_counts(d, n):
    """returns the counts of n_grams with non-zero counts in a numpy array"""
    # all_n_grams = list(itertools.product(VALID_CHARS, repeat=n))
    domain_ngrams = [d[i:i+n] for i in range(len(d)-n+1)]
    counts = list(Counter(domain_ngrams).values())
    c = np.array(counts)
    return c


def feature_ngrams_distribution(domain, n):
    """returns the mean, median and std of ngrams distribution"""
    d = ignore_TLD(domain)

    total_ngrams = len(VALID_CHARS) ** n
    l = len(d)
    total_ngrams_in_domain = 1
    for i in range(n):
        total_ngrams_in_domain *= (l - i)
    c = np.array(ngram_counts(d, n))
    # normalize to reduce correlation with length
    distribution = c / total_ngrams_in_domain
    # the ngram_counts only returns the non-zero frequencies
    # add zeros to consider all the ngrams, even the ones that were not observed
    # we try to avoid building the complete numpy array since it is quite big:
    # distribution = np.concatenate((c, np.zeros(total_ngrams - len(c))))
    # therefore we use pooled mean and std computation,
    # for std see https://stats.stackexchange.com/questions/55999/is-it-possible-to-find-the-combined-standard-deviation

    n1 = len(distribution)
    n2 = total_ngrams - n1
    if n1 == 0:
        return 0, 0
    s1_mean = np.mean(distribution)
    s2_mean = 0
    s_mean = (n1 * s1_mean + n2 * s2_mean) / (n1 + n2)

    s1_std = np.std(distribution)
    s2_std = 0
    s_std = math.sqrt((n1 * s1_std**2 + n2 * s2_std**2 + n1 *
                       (s1_mean - s_mean)**2 + n2*(s2_mean - s_mean)**2) / (n1 + n2))
    return s_mean, s_std




def feature_english_score(domain, english_counter, english_counts):
    d = ignore_TLD(domain)
    score = english_counts * english_counter.transform([d]).T
    return score


def feature_word_count(domain):
    d = ignore_TLD(domain)
    words = wordninja.split(d)
    return len(words)


def feature_domain_length(domain):
    return len(domain)


def feature_subdomain_count(domain):
    d = ignore_TLD(domain)
    return d.count(".") + 1


def feature_subdomain_length_mean(domain):
    d = ignore_TLD(domain)
    n_letters = len(d) - d.count(".")
    return n_letters / (d.count(".") + 1)


def feature_consonant_ratio(domain):
    """count consonant ration: consonants/alphanumeric"""
    d = ignore_TLD(domain)
    count_alnum = 0
    count_cons = 0
    ratio = 0
    for c in d:
        if c.isalnum():
            count_alnum += 1
            if c in CONSONANTS:
                count_cons += 1
    if count_alnum > 0:
        ratio = count_cons / count_alnum
    return ratio


def feature_consecutive_consonants_ratio(domain):
    """
    count consonants in blocks of 2 or more, returns ratio: consecutive_consonants/alphanumeric
      bcdf -> 4/4
      bcda -> 3/4
      bcad -> 2/4
      bcadf -> 4/5
      bababa -> 0/6
    """
    d = ignore_TLD(domain)
    previous_is_consonant = False
    counter_alnum = 0
    counter_cons = 0
    counter_block = 0
    ratio = 0
    for c in d:
        if c.isalnum():
            counter_alnum += 1
        if c in CONSONANTS:
            # add the consonant to the block size
            counter_block += 1
        else:
            # end of the block, check its size and add it to the count if > 1
            if counter_block > 1:
                counter_cons += counter_block
            # reset block size
            counter_block = 0
    # add the last block to the counter
    if counter_block > 1:
        counter_cons += counter_block
    # compute ratio
    if counter_alnum > 0:
        ratio = counter_cons / counter_alnum
    return ratio


def feature_repeated_ratio(domain):
    """
    calculate the Ratio of characters appearing more than once in a subdomain
    """
    d = ignore_TLD(domain)
    d = d.replace(".", "")
    number_repeated = 0
    dict_chars = dict.fromkeys(d, 0)
    for c in d:
        dict_chars[c] += 1
    for item in dict_chars:
        if dict_chars[item] > 1:
            number_repeated += 1
    ratio = number_repeated / len(dict_chars)
    return ratio


def feature_entropy(domain):
    d = ignore_TLD(domain)
    counts = Counter(d)
    d_length = len(d)
    return -sum(count / d_length * math.log(count/d_length, 2) for count in counts.values())


def feature_digit_ratio(domain):
    """count digit ratio: digit/alphanumeric"""
    d = ignore_TLD(domain)
    count_alnum = 0
    count_digit = 0
    ratio = 0
    for c in d:
        if c.isalnum():
            count_alnum += 1
            if c.isnumeric():
                count_digit += 1
    if count_alnum > 0:
        ratio = count_digit / count_alnum
    return ratio
# end of features


feature_function_list = {
    "TLD_id": feature_TLD_id,
    "length": feature_domain_length,
    "sub_count": feature_subdomain_count,
    "sub_length": feature_subdomain_length_mean,
    "entropy": feature_entropy,
    "c_ratio": feature_consonant_ratio,
    "cc_ratio": feature_consecutive_consonants_ratio,
    "d_ratio": feature_digit_ratio,
    "repetition_ratio": feature_repeated_ratio,
    "word_count": feature_word_count,   # put first as slower than the others
    "3gram_avg": None,  # none since the feature computation will be done in another way
    "3gram_std": None,
    "english_score": None # computed in the classifier
}

features_types = {
    "TLD_id": "uint8",
    "length": "uint8",
    "sub_count": "uint8",
    "sub_length": "float",
    "entropy": "float",
    "c_ratio": "float",
    "cc_ratio": "float",
    "d_ratio": "float",
    "repetition_ratio": "float",
    "word_count": "uint8",   # put first as slower than the others
    "3gram_avg": "float",  # none since the feature computation will be done in another way
    "3gram_std": "float",
    "english_score": "float"
    # "registered": feature_is_registered, # too long to compute
}
