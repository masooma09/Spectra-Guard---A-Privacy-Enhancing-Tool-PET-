import os  # work with files and folders
import csv  # read/write CSV files
import random  # pick random values
import numpy as np  # do math with lists
import tenseal as ts  # lock (encrypt) numbers for math
from cryptography.fernet import Fernet  # lock (encrypt) messages
from faker import Faker  # make fake names and data
import requests  # get info from websites
import time  # add wait time
from stem import Signal  # send new identity to Tor
from stem.control import Controller  # control Tor browser
from duckduckgo_search import DDGS  # search on DuckDuckGo
from bs4 import BeautifulSoup  # read website content
import socket  # connect computers
import threading  # do many things at once
from google.oauth2.credentials import Credentials  # save Google login
from google_auth_oauthlib.flow import InstalledAppFlow  # Google sign-in
from googleapiclient.discovery import build  # use Google services
from googleapiclient.http import MediaFileUpload  # upload file to Google
from google.auth.transport.requests import Request  # refresh login
import urllib.parse  # handle web addresses
import re  # find text with patterns
import webbrowser  # open website
import hashlib  # make data into a code
import json  # read/write JSON files



# Configuration: Shared encryption key
KEY_PATH = "shared_key.key"
if os.path.exists(KEY_PATH):
    with open(KEY_PATH, "rb") as f:
        SHARED_KEY = f.read()
else:
    SHARED_KEY = Fernet.generate_key()
    with open(KEY_PATH, "wb") as f:
        f.write(SHARED_KEY)
cipher = Fernet(SHARED_KEY)

CHAT_LOG_FILE = "chat_log.txt"

def log_chat(role, encrypted, decrypted):
    with open(CHAT_LOG_FILE, "a") as f:
        f.write(f"[{role}] Encrypted: {encrypted}\n[{role}] Decrypted: {decrypted}\n\n")

# ----------------------- IP MASKING -----------------------
def is_tor_connected():
    try:
        session = requests.Session()
        session.proxies = {
            'http': 'socks5://127.0.0.1:9050',
            'https': 'socks5://127.0.0.1:9050'
        }
        time.sleep(5)
        with Controller.from_port(port=9051) as controller:
            controller.authenticate()
            controller.signal(Signal.NEWNYM)
            print("Requesting a new Tor identity...")
        response = session.get('https://check.torproject.org/', timeout=10)
        ip_check = session.get('http://httpbin.org/ip', timeout=10).json()["origin"]
        if "Congratulations" in response.text:
            print(f"New IP: {ip_check}")
            return True, ip_check
        return False, "Not routed through Tor"
    except Exception as e:
        return False, str(e)

def is_vpn_connected():
    try:
        response = requests.get("http://httpbin.org/ip", timeout=10)
        return True, response.json()["origin"]
    except Exception as e:
        return False, str(e)

def simulate_ip_masking():
    print("\n[1] IP Masking (Tor or VPN)")
    connected, result = is_tor_connected()
    if connected:
        print(f"\u2705 Tor connected successfully. IP: {result}")
        return 'tor', result
    else:
        print("\u274C Tor not connected: " + result)
        user_choice = input("Would you like to try connecting through VPN? (y/n): ")
        if user_choice.lower() == 'y':
            print("Trying VPN...")
            vpn_connected, vpn_ip = is_vpn_connected()
            if vpn_connected:
                print(f"\u2705 VPN connected. IP: {vpn_ip}")
                return 'vpn', vpn_ip
            else:
                print(f"\u274C VPN connection failed: {vpn_ip}")
        else:
            print("VPN will not be attempted. Please check your Tor connection.")
    return None, None
# ---- Fetch Detailed Result Function ----
def fetch_detailed_result(url, session):
    try:
        # Sending request to the selected URL through the session (Tor/VPN)
        response = session.get(url)
        response.raise_for_status()  # Check if the request was successful (status 200)

        # If the status code is 404, return an appropriate message
        if response.status_code == 404:
            return "❌ Error: The page was not found (404). Please check the URL."

        # Parse the page content
        soup = BeautifulSoup(response.text, 'html.parser')

        # Extracting some sample content (e.g., first 500 characters of the page)
        page_content = soup.get_text()
        preview = page_content[:500]  # Preview of first 500 characters
        return preview

    except requests.exceptions.RequestException as e:
        return f"❌ Error fetching detailed result: {e}"

# ----------------------- SECURE BROWSING -----------------------

def secure_search(masking_type, masking_ip):
    print("\n[2] Secure Browsing (DuckDuckGo)")

    query = input("Enter search query: ")
    session = requests.Session()

    # Set proxy for Tor or VPN
    if masking_type == 'tor':
        session.proxies = {
            'http': 'socks5h://127.0.0.1:9050',
            'https': 'socks5h://127.0.0.1:9050'
        }
        # Check if Tor is connected by verifying that the IP is routed through Tor
        try:
            tor_check_url = 'https://check.torproject.org'
            response = session.get(tor_check_url)
            if "Congratulations" not in response.text:
                print("❌ Tor is not connected properly.")
                return  # Exit the function if Tor is not connected
            print("✅ Tor is connected properly.")
        except requests.exceptions.RequestException as e:
            print(f"❌ Error checking Tor connection: {e}")
            return

    elif masking_type == 'vpn':
        session.proxies = {
            'http': f'http://{masking_ip}',
            'https': f'https://{masking_ip}'
        }

    # URL encoding of the query
    encoded_query = urllib.parse.quote(query)
    search_url = f"https://duckduckgo.com/html/?q={encoded_query}"
    print(f"Fetching search results from: {search_url}")  # Debugging: Check URL

    try:
        response = session.get(search_url)
        response.raise_for_status()  # Check if the request was successful (status code 200)

        # Check if 403 Forbidden error occurs
        if response.status_code == 403:
            print("❌ 403 Forbidden: Access Denied. DuckDuckGo is blocking your request.")
            return  # Exit the function if there's a 403 error

        soup = BeautifulSoup(response.text, 'html.parser')

        results = soup.find_all('a', {'class': 'result__a'})

        if not results:
            print("❌ No results found.")
            return

        print("\nTop search results:")
        links = []
        for i, result in enumerate(results, start=1):
            title = result.get_text()
            raw_url = result.get('href')

            # Extract real URL from DuckDuckGo redirect
            match = re.search(r'uddg=([^&]+)', raw_url)
            if match:
                decoded_url = urllib.parse.unquote(match.group(1))
                print(f"Result {i}: Title: {title}, URL: {decoded_url}")
                links.append(decoded_url)

        if not links:
            print("❌ No valid results with URLs found.")
            return

        # User selects one to explore
        try:
            choice = int(input("\nWhich result would you like to explore further? (Enter the number): "))
            if 1 <= choice <= len(links):
                selected_url = links[choice - 1]
                print(f"\nFetching detailed information from: {selected_url}")
                detailed_result = fetch_detailed_result(selected_url, session)
                print("\nDetailed Result Preview:")
                print(detailed_result)
            else:
                print("❌ Invalid choice. Please choose a number from the list.")
        except ValueError:
            print("❌ Invalid input. Please enter a number.")

    except requests.exceptions.RequestException as e:
        print(f"❌ Error occurred while fetching results: {e}")



# ----------------------- DATA ANONYMIZATION -----------------------


def anonymize_user_data():
    fake = Faker()
    
    # Guide the user about privacy level (epsilon)
    
    print("Data Anonymization\n")
    print("The privacy level is controlled by the epsilon value. The higher the epsilon, the less noise is added, and vice versa.")
    print("Remember: The more noise (lower epsilon), the stronger the privacy protection.")
    print("For strong privacy protection, use a lower epsilon value (e.g., 0.5).")
    print("For less protection (but more accuracy), use a higher epsilon (e.g., 1.0 or 2.0).\n")

    # Ask for privacy level (epsilon) input
    epsilon = float(input("\nSet privacy level (epsilon, e.g. 1.0): "))
    
    # Validate epsilon value
    if epsilon <= 0:
        print("Epsilon must be greater than 0. Please enter a valid value.")
        return
    
    print("\nData anonymization in progress...")

    # Open file for writing anonymized data
    with open('anonymized_data.csv', 'a', newline='') as file:
        writer = csv.writer(file)
        # Writing the header if the file is empty
        file.seek(0, 2)  # Move the cursor to the end of the file
        if file.tell() == 0:
            writer.writerow(['Real Name', 'Anonymized Name', 'Original Value', 'Noisy Value'])
        
        while True:
            # Taking input for the real name and sensitive data (numeric)
            real_name = input("\nEnter real name (or 'quit' to exit): ")
            if real_name.lower() == 'quit':
                print("Exiting the tool. Thank you!")
                break
            
            # Get sensitive numeric data (like salary, value, etc.)
            try:
                sensitive_data = float(input("Enter sensitive numeric data (e.g. salary): "))
            except ValueError:
                print("Invalid input. Please enter a valid numeric value.")
                continue
            
            # Generate a pseudonym for the real name using Faker
            anonymized_name = fake.name()  # You can also modify this to get different fake data
            
            # Differential Privacy (DP) noise calculation
            noise = np.random.laplace(0, 1/epsilon)  # Adjust the scale of noise based on epsilon
            
            # Apply DP noise to the sensitive data
            noisy_value = sensitive_data + noise

            # Write the anonymized data to the CSV file
            writer.writerow([real_name, anonymized_name, sensitive_data, noisy_value])
            
            # Inform the user that the data was saved
            print(f"Anonymized data for {real_name} has been saved to the file.")

    # Final message to let the user know the process is complete
    print("\nAll anonymized data has been successfully saved to 'anonymized_data.csv'.")


# ----------------------- SECURE CLOUD STORAGE -----------------------
def string_to_ascii_list(s): 
    return [ord(c) for c in s]

def ascii_list_to_string(lst): 
    return ''.join([chr(i) for i in lst])

def secure_cloud_storage(): 
    print("\n[4] Secure Cloud Storage")

    # Setup TenSEAL context for BFV scheme
    context = ts.context(
        ts.SCHEME_TYPE.BFV,
        poly_modulus_degree=8192,
        plain_modulus=1032193
    )
    context.generate_galois_keys()
    context.generate_relin_keys()

    # Retain secret key for decryption
    secret_context = context.copy()
    secret_key = secret_context.secret_key()

    # Make public context for encryption & saving
    context.make_context_public()

    while True:
        user_data = input("Enter data to encrypt and store (or 'quit' to exit): ")
        if user_data.lower() == 'quit':
            break

        # Convert input string to ASCII list
        ascii_data = string_to_ascii_list(user_data)

        # Encrypt the data using BFV vector with public context
        encrypted_vec = ts.bfv_vector(context, ascii_data)

        # Save encrypted data to a binary file
        os.makedirs("cloud", exist_ok=True)
        file_path = "cloud/encrypted_data.bin"
        with open(file_path, "wb") as f:
            f.write(encrypted_vec.serialize())  # Remove save_public_context
        print("✅ Encrypted data saved locally at:", file_path)

        # Upload to Google Drive
        service = authenticate_google_drive()
        file_metadata = {'name': 'encrypted_data.bin'}
        media = MediaFileUpload(file_path, mimetype='application/octet-stream')
        uploaded_file = service.files().create(body=file_metadata, media_body=media, fields='id').execute()
        print(f"⬆ Uploaded to Google Drive with file ID: {uploaded_file.get('id')}")

        # Perform homomorphic computation: multiply by 2 (ensure this is valid with your setup)
        encrypted_result = encrypted_vec * 2  # Make sure this operation is supported by TenSEAL
        print("✅ Encrypted result of multiplication (still encrypted).")

        # Decrypt the result using the secret context
        encrypted_result.link_context(secret_context)  # Re-link context for decryption
        decrypted_data = encrypted_result.decrypt()

        # Reverse computation: divide by 2
        original_ascii = [val // 2 for val in decrypted_data]
        decrypted_string = ascii_list_to_string(original_ascii)

        #print(f"📝 Decrypted string after homomorphic ops: {decrypted_string}")

        # Ask user if they want to save decrypted result
        save_choice = input("Do you want to save the decrypted ASCII values to a file? (y/n): ").strip().lower()
        if save_choice == 'y':
            decrypted_file_path = "cloud/decrypted_data.txt"
            with open(decrypted_file_path, 'w') as f:
                f.write(f"Decrypted ASCII values: {original_ascii}\n")
                f.write(f"Decrypted string: {decrypted_string}\n")
            print(f"✅ Decrypted ASCII values saved to: {decrypted_file_path}")
        else:
            print("ℹ️ Decrypted data was not saved.")



# ----------------------- ENCRYPTED CHAT -----------------------
def handle_client(conn):
    print("\n🔐 Type 'end' at any time to terminate the session.")
    while True:
        data = conn.recv(4096)
        if not data:
            break
        try:
            # Decrypt the received message
            msg = cipher.decrypt(data).decode()
            print(f"Client: {msg}")
            log_chat("Client", data, msg)
            
            if msg.lower() == "end":
                print("❌ Client ended the session.")
                break
            
            # Get user input and encrypt the reply
            reply = input("You: ").strip()
            conn.sendall(cipher.encrypt(reply.encode()))
            
            if reply.lower() == "end":
                print("✅ You ended the session.")
                break
        except Exception as e:
            print(f"Decryption failed: {e}")
            break
    conn.close()

def start_server():
    host, port = '127.0.0.1', 65432
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        print("[Server] Waiting for client to connect...")
        conn, _ = s.accept()
        print("🔗 Client connected! You can now chat securely.")
        handle_client(conn)

def start_client():
    host, port = '127.0.0.1', 65432
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((host, port))
            print("[Client] Connected to server.")
            print("🔐 Type 'end' at any time to terminate the session.")
            while True:
                # Get user input and encrypt the message
                msg = input("You: ").strip()
                encrypted_msg = cipher.encrypt(msg.encode())
                s.sendall(encrypted_msg)
                
                if msg.lower() == "end":
                    print("✅ You ended the session.")
                    break
                
                # Receive and decrypt the server's response
                data = s.recv(4096)
                decrypted = cipher.decrypt(data).decode()
                print("Server:", decrypted)
                log_chat("Server", data, decrypted)
                
                if decrypted.lower() == "end":
                    print("❌ Server ended the session.")
                    break
        except Exception as e:
            print(f"Connection error: {e}")


            
def authenticate_google_drive():
    SCOPES = ['https://www.googleapis.com/auth/drive.file']
    creds = None

    token_path = "token.json"
    creds_path = os.path.expanduser("~/Downloads/credentials.json")  # Adjust path if needed

    if os.path.exists(token_path):
        creds = Credentials.from_authorized_user_file(token_path, SCOPES)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(creds_path, SCOPES)
            creds = flow.run_local_server(port=0)
        with open(token_path, 'w') as token:
            token.write(creds.to_json())

    service = build('drive', 'v3', credentials=creds)
    return service

#---------------user must register----------------

USER_DB = "users.json"

def load_users():
    if os.path.exists(USER_DB):
        with open(USER_DB, 'r') as f:
            return json.load(f)
    return {}

def save_users(users):
    with open(USER_DB, 'w') as f:
        json.dump(users, f)

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def register_user():
    users = load_users()
    username = input("Choose a username: ").strip()
    
    if username in users:
        print("❌ Username already exists.")
        return
    
    password = input("Choose a password: ").strip()
    hashed_pw = hash_password(password)
    
    # Assign a unique user ID
    user_id = len(users) + 1  # This gives sequential IDs: 1, 2, 3, ...
    
    users[username] = {
        "id": user_id,
        "password": hashed_pw
    }
    
    save_users(users)
    print(f"✅ Registered successfully! Your user ID is {user_id}")


def login_user():
    users = load_users()
    
    if not users:
        print("❌ No users registered. Please register first.")
        return None

    attempts = 3
    while attempts > 0:
        try:
            user_id = int(input("Enter your User ID: ").strip())
        except ValueError:
            print("❌ Invalid ID format.")
            continue
        
        username = input("Username: ").strip()
        password = input("Password: ").strip()

        # Find matching user
        for uname, info in users.items():
            if info['id'] == user_id and uname == username and info['password'] == hash_password(password):
                print(f"✅ Login successful. Welcome, {username}!")
                return user_id, username

        attempts -= 1
        print(f"❌ Invalid credentials. Attempts remaining: {attempts}")
    
    print("🔒 Too many failed attempts. Returning to main menu.")
    return None


# ----------------------- MAIN -----------------------
def main():
    masking_type, masking_ip = None, None
    authenticated_user = None
    while True:
        print("""
    SPECTRA GUARD - Privacy Enhancing Tool
    ----------------------------------------
    1. IP Masking (Tor/VPN)
    2. Secure Browsing (DuckDuckGo)
    3. Data Anonymization (k-anonymity & DP)
    4. Secure Cloud Storage (FHE)
    5. Encrypted Chat (E2E Real-time)
    6. Register
    7. Login
    8. Exit
        """)
        choice = input("Choose option: ")
        if choice == "1":
            masking_type, masking_ip = simulate_ip_masking()
        elif choice == "2":
            if masking_type and masking_ip:
                secure_search(masking_type, masking_ip)
            else:
                print("Please enable IP Masking (Tor/VPN) first.")
        elif choice == "3":
            anonymize_user_data()
        elif choice == "4":
            if authenticated_user:
                secure_cloud_storage()
            else:
                print("🔒 Please login to access Secure Cloud Storage.")
        elif choice == "5":
            if authenticated_user:
                role = input("1. Server or 2. Client? ")
                if role == "1":
                    start_server()
                elif role == "2":
                    start_client()
            else:
                print("🔒 Please login to use Encrypted Chat.")
        elif choice == "6":
            register_user()
        elif choice == "7":
            user = login_user()
            if user:
                authenticated_user = user
        elif choice == "8":
            break
        else:
            print("Invalid input.")
if __name__ == "__main__":
    main()
