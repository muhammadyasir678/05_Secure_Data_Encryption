import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# 🔐 Generate encryption key (would be stored securely in production)
KEY = Fernet.generate_key()
cipher = Fernet(KEY)

# 🧠 Session-based in-memory storage
if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}  # Format: {encrypted_text: {"encrypted_text": ..., "passkey": hashed_passkey}}

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "authorized" not in st.session_state:
    st.session_state.authorized = True  # Controls lockout after 3 failed attempts

# 🔁 Utility: Hash the passkey using SHA-256
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# 🔒 Encrypt plain text
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

# 🔓 Decrypt encrypted text with correct passkey
def decrypt_data(encrypted_text, passkey):
    hashed_passkey = hash_passkey(passkey)
    for key, value in st.session_state.stored_data.items():
        if key == encrypted_text and value["passkey"] == hashed_passkey:
            st.session_state.failed_attempts = 0
            return cipher.decrypt(encrypted_text.encode()).decode()
    
    st.session_state.failed_attempts += 1
    return None

# 🌐 Streamlit UI
st.title("🔒 Secure Data Encryption System")

menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

# 🏠 Home Page
if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("This app helps you **securely store and retrieve sensitive information** using encryption and passkeys.")

# 💾 Store Data Page
elif choice == "Store Data":
    st.subheader("📂 Store Data")
    user_data = st.text_area("Enter the data to store securely:")
    passkey = st.text_input("Enter a secret passkey:", type="password")

    if st.button("Encrypt & Store"):
        if user_data and passkey:
            encrypted_text = encrypt_data(user_data)
            hashed_passkey = hash_passkey(passkey)
            st.session_state.stored_data[encrypted_text] = {
                "encrypted_text": encrypted_text,
                "passkey": hashed_passkey
            }
            st.success("✅ Data encrypted and stored successfully!")
            st.code(encrypted_text, language="text")
        else:
            st.error("⚠️ Please enter both the data and the passkey.")

# 🔍 Retrieve Data Page
elif choice == "Retrieve Data":
    if not st.session_state.authorized:
        st.warning("🔒 Too many failed attempts. Please reauthorize on the Login page.")
        st.stop()

    st.subheader("🔍 Retrieve Data")
    encrypted_text = st.text_area("Enter your encrypted text:")
    passkey = st.text_input("Enter your secret passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_text and passkey:
            decrypted = decrypt_data(encrypted_text, passkey)
            if decrypted:
                st.success("✅ Data decrypted successfully!")
                st.code(decrypted, language="text")
            else:
                remaining = 3 - st.session_state.failed_attempts
                st.error(f"❌ Incorrect passkey. Attempts left: {remaining}")
                if st.session_state.failed_attempts >= 3:
                    st.session_state.authorized = False
                    st.warning("🔐 Too many failed attempts. Please login to continue.")
                    st.experimental_rerun()
        else:
            st.error("⚠️ Both fields are required!")

# 🔑 Login / Reauthorization Page
elif choice == "Login":
    st.subheader("🔑 Reauthorization Required")
    login_pass = st.text_input("Enter the master password:", type="password")

    if st.button("Login"):
        if login_pass == "admin123":  # Hardcoded demo login
            st.session_state.failed_attempts = 0
            st.session_state.authorized = True
            st.success("✅ Reauthorized! You can now retrieve your data.")
            st.experimental_rerun()
        else:
            st.error("❌ Incorrect master password.")