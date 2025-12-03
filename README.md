# Secure File Manager

This project is a Python-based secure file management system.  
It focuses on securely storing files using encryption and controlling access to them.

## Features

- User registration and login with password hashing
- Two-factor authentication (2FA) using TOTP (Google Authenticator)
- Encrypted file storage using Fernet (AES)
- Per-user file access (each user sees only their own files)
- Basic threat detection:
  - Blocks dangerous extensions (.exe, .bat, .js, etc.)
  - Blocks files containing suspicious keyword "virus"
  - File size limit (16 MB)
  - Security event logging to `security.log`

## How to run

1. Install Python 3.
2. Install dependencies:
   ```bash
   python -m pip install flask flask_sqlalchemy cryptography pyotp


   ## Installation and Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/ARYANBHARDWAJ0166/secure-file-manager.git
   cd secure-file-manager



   ## Usage

- Start the application:
  ```bash
  python app.py   # or the main file of your project




  ## Security Features

- **Encrypted storage**: Files are encrypted before being written to disk.
- **Decryption on access**: Files are decrypted only when they are read or downloaded.
- **Ignored local data**: The `instance/` folder and logs are ignored by Git to avoid committing secrets.
- **File type restrictions**: Only allowed file types can be uploaded (to reduce risk).
- **Security logging**: Basic logging for important actions (uploads/downloads) to `security.log`.



# TODO

- Add user authentication and per-user file access control.
- Improve error handling and validation for file uploads.
- Add more detailed security logging (IP address, user ID).
- Write unit tests for encryption and decryption functions.