import streamlit as st
import hashlib
from cryptography.fernet import Fernet
import json
import os
import time

lockout_file = "lockout_info.json"
secure_data_file = "secured_data.json"
key_file = "secret.key"

max_attempts = 3
lockout_time = 60  # seconds

st.set_page_config(page_title="Encrypted System", page_icon="🔒")

st.title("🔒 Secure Data Encryption System")

if "secure_data" not in st.session_state:
    st.session_state.secure_data = {}

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

if 'current_page' not in st.session_state:
    st.session_state.current_page = 'Home'

if 'logged_in_user' not in st.session_state:
    st.session_state.logged_in_user = None

menu = ["Home", "Login", "Save Data", "Retrieve Data"]
choice = st.sidebar.selectbox("Menu", menu)

if st.session_state.current_page == 'Login':
    choice = "Login"

if choice == "Home":
    st.write("Secure and retrieve your data using this encrypted system..!")
    st.subheader("Create your account")
    username = st.text_input("User Name: ")
    password = st.text_input("Password: ", type="password")
    confirm_password = st.text_input("Confirm Password: ", type="password")
    
    if st.button('Create'):
        if password == confirm_password:
            if os.path.exists(secure_data_file):
                with open(secure_data_file, 'r') as f:
                    users = json.load(f)
            else:
                users = {}
            
            users[username] = {
                'password': hash_pass_key(password),
                'encrypted_text': '',
                'pass_key': '',
                'attempts': 0,
                'lockout_time': 0,
            }

            with open(secure_data_file, 'w') as f:
                json.dump(users, f)
            
            st.success("Account created successfully.")
        else:
            st.error("Passwords do not match.")

    elif st.button('Login'):
        st.session_state.current_page = 'Login'

elif choice == "Login":
    login_user = st.text_input("User Name: ")
    login_pass = st.text_input("Password: ", type="password")

    if st.button("Login"):
        try:
            with open(secure_data_file, 'r') as f:
                user_data = json.load(f)

        except FileNotFoundError as e:
            user_data = {}   

        if login_user and login_pass:
            if login_user not in user_data:
                st.error("Account not found")
            else:
                user_info = user_data[login_user]
                stored_hash = user_info['password']
                entered_hash = hash_pass_key(login_pass)
            
                if entered_hash == stored_hash:
                    st.session_state.logged_in_user = login_user
                    st.success("Login successfully!")
                else:
                    st.error("Incorrect password")

elif choice == "Save Data":
    if  not st.session_state.get('logged_in_user'):
        st.error("Please login first!")
        st.stop()

    user_name = st.session_state.logged_in_user
    user_data = st.text_area("Enter your data to store: ")
    pass_key = st.text_input("Enter a pass key: ", type="password")

    if st.button("Save"):
        if user_data and pass_key:
            hashed_key = hash_pass_key(pass_key)
            encrypted_data = encrypt_data(user_data, st.session_state.key)

            if os.path.exists(secure_data_file):
                with open(secure_data_file, 'r') as f:
                    all_data = json.load(f)
            else:
                all_data = {}

            all_data[user_name].update({
                'encrypted_text': encrypted_data.hex(),
                'pass_key': hashed_key,
            })

            with open(secure_data_file, 'w') as f:
                json.dump(all_data, f)

            st.success("Data encrypted and saved successfully.")
        else: 
            st.warning("Please fill all fields.")

elif choice == "Retrieve Data":
    if not st.session_state.get('logged_in_user'):
        st.error("Please login first!")
        st.stop()
    
    username = st.session_state.logged_in_user
    
    if os.path.exists(secure_data_file):
        with open(secure_data_file, 'r') as f:
            secure_data = json.load(f)
    else:
        secure_data = {}
    
    if username not in secure_data:
        st.error("User account not found!")
        st.stop()
    
    user_data = secure_data[username]
    entered_passkey = st.text_input("Enter your pass key: ", type="password")
    
    if st.button("Retrieve"):
        if not entered_passkey:
            st.warning("Please enter pass key")
            st.stop()
            
        current_time = time.time()

        if user_data['attempts'] >= max_attempts:
            time_elapsed = current_time - user_data['lockout_time']
            
            if time_elapsed < lockout_time:
                remaining_time = int(lockout_time - time_elapsed)

                countdown_placeholder = st.empty()
                for i in range(remaining_time, 0, -1):
                    countdown_placeholder.error(f"Account locked. Please wait {i} seconds...")
                    time.sleep(1)
                countdown_placeholder.empty()

                user_data['attempts'] = 0
                user_data['lockout_time'] = 0
                with open(secure_data_file, 'w') as f:
                    json.dump(secure_data, f)
            else:
                user_data['attempts'] = 0
                user_data['lockout_time'] = 0

        entered_hash = hash_pass_key(entered_passkey)
        if entered_hash == user_data['pass_key']:
            try:
                if not user_data['encrypted_text']:
                    st.warning("No data stored for this user")
                else:
                    decrypted = decrypt_data(
                        bytes.fromhex(user_data['encrypted_text']), 
                        st.session_state.key
                    )
                    st.success("Data decrypted successfully!")
                    st.code(decrypted, language='text')
                
                user_data['attempts'] = 0
                user_data['lockout_time'] = 0
                
            except Exception as e:
                st.error(f"Decryption failed: {str(e)}")
        else:
            user_data['attempts'] += 1
            if user_data['attempts'] >= max_attempts:
                user_data['lockout_time'] = current_time
                st.error("Too many attempts! Account locked temporarily.")
            else:
                st.error(f"Invalid passkey! Attempt {user_data['attempts']} of {max_attempts}")

        with open(secure_data_file, 'w') as f:
            json.dump(secure_data, f)
