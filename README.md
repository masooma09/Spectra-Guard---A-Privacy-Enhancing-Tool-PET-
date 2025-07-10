# 🛡️ Spectra Guard – Privacy-Enhancing Tool (PET)

A privacy-focused Python tool that empowers users to browse securely, communicate privately, and protect sensitive data using modern encryption and anonymization techniques. Spectra Guard integrates IP masking (Tor/VPN), anonymous browsing, encrypted messaging, data anonymization, and secure cloud storage using Fully Homomorphic Encryption (FHE).

---

## 👥 Team Members

- Masooma Hassan  
- Umer Ahmed 

---

## 🧠 Overview

Spectra Guard was developed to address growing privacy concerns in the digital world. It enables users to mask their identity, search securely, store encrypted data in the cloud, and communicate in real-time using end-to-end encryption.

Key features include Tor-based routing, DuckDuckGo privacy search, k-anonymity with differential privacy, Google Drive uploads via encrypted FHE, and encrypted chat using Fernet keys — all from a single, terminal-based interface.

---

## 🚀 Features

- 🔐 **IP Masking (Tor/VPN):** Route your traffic through Tor or fallback to VPN
- 🔍 **Secure Browsing:** Perform anonymous searches using DuckDuckGo via Tor/VPN
- 🧬 **Data Anonymization:** Add Laplace noise + pseudonymization to sensitive data
- ☁️ **Secure Cloud Storage:** Encrypt data using TenSEAL (FHE) and upload to Google Drive
- 💬 **Encrypted Chat:** Real-time end-to-end messaging using Fernet + sockets
- 🔐 **User Auth:** Register/Login with secure SHA-256 password hashing

---

## 📂 Folder Structure

-cloud.py --this is the main file, no other files are required. Code will automatically create required files once it is run.

# ▶️ How to Run

1. Install dependencies:
```bash
pip install -r requirements.txt
```
2. Run the program:
```bash
python cloud.py
```
🔐 Usage Flow

Register/Login to access secure features

Choose from:

IP Masking (Tor/VPN)

Secure Browsing (DuckDuckGo + IP masking)

Data Anonymization (k-anonymity + differential privacy)

Secure Cloud Storage (FHE + Google Drive)

Encrypted Chat (Fernet E2E)

Files like shared_key.key, users.json, and token.json are generated automatically.

---

📌 Requirements

Python: 3.8+

Tor: Must be installed and running on port 9050

VPN: Optional but supported

Internet: Required for DuckDuckGo and Google Drive API

Google API Setup:

Enable the Google Drive API on Google Cloud Console

Download credentials.json and place it in your ~/Downloads/ directory
---
🙌 Acknowledgements

Thanks to our instructor and team for their continuous support and guidance. This project allowed us to explore practical privacy-enhancing technologies and understand how modern cryptography and network privacy tools work in real applications.



Need help or want the project video?
Feel free to reach out via email: masoomahassan87@gmail.com
