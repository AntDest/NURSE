from src.utils.utils_variables import VALID_CHARS

def humanbytes(B):
   'Return the given bytes as a human friendly KB, MB, GB, or TB string'
   #from https://stackoverflow.com/questions/12523586/python-format-size-application-converting-b-to-kb-mb-gb-tb/63839503
   B = float(B)
   KB = float(1024)
   MB = float(KB ** 2) # 1,048,576
   GB = float(KB ** 3) # 1,073,741,824
   TB = float(KB ** 4) # 1,099,511,627,776

   if B < KB:
      return '{0} B'.format(B)
   elif KB <= B < MB:
      return '{0:.2f} KB'.format(B/KB)
   elif MB <= B < GB:
      return '{0:.2f} MB'.format(B/MB)
   elif GB <= B < TB:
      return '{0:.2f} GB'.format(B/GB)
   elif TB <= B:
      return '{0:.2f} TB'.format(B/TB)

def validate_domain_string(text):
   """checks that the text corresponds to a valid domain: only contains [0-9][a-z] and dots and dashes"""
   for c in text:
      if c not in VALID_CHARS:
         return False
   return True