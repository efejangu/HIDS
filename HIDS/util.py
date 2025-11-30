import hashlib

def hash_file(file_path):
    try:
        with open(file_path, "rb") as file:
            file_hash = hashlib.sha256()
            while True:
                file_bytes = file.read()
                if not file_bytes:
                    break  # End of file
                file_hash.update(file_bytes)              
        return file_hash.hexdigest()
    except FileNotFoundError:
        print("file not found")
