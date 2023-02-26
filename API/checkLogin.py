import sys

def check_file_for_string(file, username, password):
    with open(file, 'r') as file:
        content = file.read()
        if (username + " " + password) in content:
            print("True")
        else:
            print("False")

check_file_for_string(sys.argv[1], sys.argv[2], sys.argv[3])
