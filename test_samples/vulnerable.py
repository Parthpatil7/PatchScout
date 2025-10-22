# Sample vulnerable Python code for testing PatchScout

import pickle
import subprocess
import os

# Code injection vulnerabilities
def process_user_input(user_code):
    # Dangerous: eval with user input
    result = eval(user_code)
    return result

def execute_command(cmd):
    # Dangerous: exec with user input
    exec(cmd)

# SQL Injection pattern
def get_user(username):
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    return query

# Command injection
def run_system_command(filename):
    os.system(f"cat {filename}")
    subprocess.call("ls " + filename, shell=True)

# Hardcoded credentials
API_KEY = "sk-abc123def456789"
PASSWORD = "SuperSecret123"

# Insecure deserialization
def load_data(serialized_data):
    data = pickle.loads(serialized_data)
    return data

# Weak cryptography
import hashlib
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()
