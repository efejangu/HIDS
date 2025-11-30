import hashlib

def _hash_file(file_path):
    algo = hashlib.sha256()
    try:
        #reads the bytes of the file and generates a sha256 hash
        path_to_file = path
        with open(path_to_file, "rb") as target_file:
            algo.update(target_file.read())
        return algo.digest()
    except FileNotFoundError:
        print("error generating hash, file not found.")