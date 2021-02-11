DNS_RECORD_TYPE = {
    1: "A",
    28: "AAAA",
    2: "NS",
    5: "CNAME",
    12: "PTR",
    33: "SRV",
    16: "TXT",
    43: "DS",
    48: "DNSKEY",
    13: "HINFO"
}

file = "data/english_words.txt"
with open(file, "r") as f_in:
  ENGLISH_WORDS = f_in.read().splitlines()
ENGLISH_WORDS = [w.lower() for w in ENGLISH_WORDS]

file = "data/IANA_TLD.txt"
with open(file, "r") as f_in:
  IANA_TLD_LIST = f_in.read().splitlines()[1:]
IANA_TLD_LIST = [tld.lower() for tld in IANA_TLD_LIST]

LETTERS = [chr(i) for i in range(97,123)]
DIGITS = [chr(i) for i in range(48,58)]
VOWELS = [c for c in "aeiou"]
CONSONANTS = [c for c in LETTERS if c not in VOWELS]
VALID_CHARS = LETTERS + DIGITS + ["-", "."]