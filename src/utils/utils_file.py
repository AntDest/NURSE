import os

FILE_CHUNK_SIZE = 50000000

def file_split(source, dest_folder, write_size):
    """
    Splits a file into smaller chunks and to join chunks into a file
    This is used to upload large pickled files on the repository while compying with the maximum file size
    Code taken from this article:
    https://stonesoupprogramming.com/2017/09/16/python-split-and-join-file/
        source: the file name
        dest_folder: the folder in which the chunks will be placed
        write_size: the max size of the chunks (in bytes)
    """
    # Make a destination folder if it doesn't exist yet
    if not os.path.exists(dest_folder):
        os.mkdir(dest_folder)
    else:
        # Otherwise clean out all files in the destination folder
        for file in os.listdir(dest_folder):
            os.remove(os.path.join(dest_folder, file))
 
    partnum = 0
    # Open the source file in binary mode
    input_file = open(source, 'rb')
    while True:
        # Read a portion of the input file
        chunk = input_file.read(write_size)
 
        # End the loop if we have hit EOF
        if not chunk:
            break
 
        # Increment partnum
        partnum += 1
 
        # Create a new file name
        filename = os.path.join(dest_folder, ('part%004d' % partnum))
        # Create a destination file
        dest_file = open(filename, 'wb')
 
        # Write to this portion of the destination file
        dest_file.write(chunk)
 
        # Explicitly close 
        dest_file.close()
     
    # Explicitly close
    input_file.close()
     
    # Return the number of files created by the split
    return partnum
 
 
def file_join(source_dir, dest_file, read_size):
    """Joins a file originally split with file_split function"""
    # Create a new destination file
    import logging
    output_file = open(dest_file, 'wb')
     
    # Get a list of the file parts
    parts = os.listdir(source_dir)
     
    # Sort them by name (remember that the order num is part of the file name)
    parts.sort()
 
    # Go through each portion one by one
    for file in parts:
         
        # Assemble the full path to the file
        path = os.path.join(source_dir, file)
         
        # Open the part
        input_file = open(path, 'rb')
         
        while True:
            # Read all bytes of the part
            read_bytes = input_file.read(read_size)
             
            # Break out of loop if we are at end of file
            if not read_bytes:
                break
                 
            # Write the bytes to the output file
            output_file.write(read_bytes)
             
        # Close the input file
        input_file.close()
         
    # Close the output file
    output_file.close()

if __name__ == "__main__":
    if os.path.exists("classifier.save"):
        file_split("classifier.save", "classifier", FILE_CHUNK_SIZE)