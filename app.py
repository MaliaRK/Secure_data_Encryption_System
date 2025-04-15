import streamlit as st
import hashlib
from cryptography.fernet import Fernet
import json
import os
import time

# File paths
lockout_file = "lockout_info.json"
user_db_file = "user.json"
secure_data_file = "secured_data.json"
key_file = "secret.key"

# Security settings
max_attempts = 3
lockout_time = 60  # seconds

st.set_page_config(page_title="Encrypted System", page_icon="🔒")

st.title("🔒 Secure Data Encryption System")

# Initialize session state
if "secure_data" not in st.session_state:
    st.session_state.secure_data = {}

# Key management functions
def load_or_generate_key():
    if os.path.exists(key_file):
        with open(key_file, "rb") as f:
            return f.read()
    else:
        key = Fernet.generate_key()
        with open(key_file, "wb") as f:
            f.write(key)
        return key

# Initialize key
if "key" not in st.session_state:
    st.session_state.key = load_or_generate_key()

def hash_pass_key(pass_key, salt=b'static_salt', iterations=100000):
    return hashlib.pbkdf2_hmac('sha256', pass_key.encode(), salt, iterations).hex()

def encrypt_data(user_data, key):
    fernet = Fernet(key)
    return fernet.encrypt(user_data.encode())

def decrypt_data(encrypted_data, key):
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_data).decode()

menu = ["Home", "Save Data", "Retrieve Data"]
choice = st.sidebar.selectbox("Menu", menu)

if choice == "Home":
    st.write("Secure and retrieve your data using this encrypted system..!")
    st.subheader("Create your account")
    username = st.text_input("User Name: ")
    password = st.text_input("Password: ", type="password")
    confirm_password = st.text_input("Confirm Password: ", type="password")
    
    if st.button('Create'):
        if password == confirm_password:
            # Save user credentials (in a real app, you'd hash the password)
            if os.path.exists(user_db_file):
                with open(user_db_file, 'r') as f:
                    users = json.load(f)
            else:
                users = {}
            
            users[username] = hash_pass_key(password)
            
            with open(user_db_file, 'w') as f:
                json.dump(users, f)
            
            st.success("Account created successfully.")
        else:
            st.error("Passwords do not match.")

elif choice == "Save Data":
    user_name = st.text_input("Enter user name: ")
    pass_key = st.text_input("Enter a pass key: ", type="password")
    data_name = st.text_input("Enter a data name: ")
    user_data = st.text_input("Enter your data to store: ")
  
    if st.button("Save"):
        if user_name and pass_key and data_name and user_data:
            hashed_key = hash_pass_key(pass_key)
            encrypted_data = encrypt_data(user_data, st.session_state.key)

            if os.path.exists(secure_data_file):
                with open(secure_data_file, 'r') as f:
                    all_data = json.load(f)
            else:
                all_data = {}

            all_data[data_name] = {
                'encrypted_text': encrypted_data.hex(),  # Store as hex string
                'pass_key': hashed_key,
                'user_name': user_name,
            }

            with open(secure_data_file, 'w') as f:
                json.dump(all_data, f)

            st.success("Data encrypted and saved successfully.")
        else: 
            st.warning("Please fill all fields.")

elif choice == "Retrieve Data":
    if os.path.exists(secure_data_file):
        with open(secure_data_file, 'r') as f:
            secure_data = json.load(f)
    else:
        secure_data = {}

    data_name = st.text_input("Enter your data name: ")
    entered_passkey = st.text_input("Enter your pass key: ", type="password")

    if st.button("Retrieve"):
        if os.path.exists(lockout_file):
            with open(lockout_file, 'r') as f:
                lockout_data = json.load(f)
        else:
            lockout_data = {}

        user_attempts = lockout_data.get(data_name, {"attempts": 0, "lockout_time": 0})
        current_time = time.time()

        if user_attempts["attempts"] >= max_attempts:
            if current_time - user_attempts["lockout_time"] < lockout_time:
                remaining_time = int(lockout_time - (current_time - user_attempts["lockout_time"]))
                st.error(f"Too many failed attempts. Please wait {remaining_time} seconds and try again.")
                st.stop()
            else:
                user_attempts = {"attempts": 0, "lockout_time": 0}

        if data_name in secure_data:
            entered_hashed_key = hash_pass_key(entered_passkey)
            stored_info = secure_data[data_name]

            if entered_hashed_key == stored_info['pass_key']:
                lockout_data[data_name] = {"attempts": 0, "lockout_time": 0}
                with open(lockout_file, 'w') as f:
                    json.dump(lockout_data, f)

                try:
                    decrypted_data = decrypt_data(bytes.fromhex(stored_info['encrypted_text']), st.session_state.key)
                    st.success("Your data was decrypted successfully!")
                    st.code(decrypted_data, language='text')
                except:
                    st.error("Failed to decrypt data. The encryption key may have changed.")
            else:
                user_attempts["attempts"] += 1
                if user_attempts["attempts"] >= max_attempts:
                    user_attempts["lockout_time"] = current_time
                    st.error("Too many failed attempts. Your account has been temporarily locked.")
                else:
                    st.error(f"Invalid pass key! Attempt {user_attempts['attempts']} of {max_attempts}")
                
                lockout_data[data_name] = user_attempts
                with open(lockout_file, 'w') as f:
                    json.dump(lockout_data, f)
        else:
            st.error("Data not found.")
            