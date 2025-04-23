import logging
import os
import sqlite3
import json
import uvicorn
import base64
from datetime import datetime
from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
# For asymmetric and symmetric encryption
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# -----------------------------------------------------------------------------
# Logging Configuration
# -----------------------------------------------------------------------------
log_file = "app.log"
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.FileHandler(log_file, mode='a')]
)

# -----------------------------------------------------------------------------
# Class: Measurement
# Responsibility: Represent the measurement input string.
# -----------------------------------------------------------------------------
class Measurement:
    # Represents a measurement input string.
    def __init__(self, raw_value: str):
        self.raw_value = raw_value

    # Validate the measurement string.
    def is_valid(self) -> bool:
        return self.raw_value is not None and len(self.raw_value) > 0

    # Get the raw value of the measurement string.
    def get_value_as_str(self) -> str:
        return self.raw_value

# -----------------------------------------------------------------------------
# Class: MeasurementService
# Responsibility: Process a Measurement – convert using the encoding logic.
# -----------------------------------------------------------------------------
class MeasurementService:
    @staticmethod
    # Convert a character to its numeric value ('_' returns 0).
    def char_value(char: str) -> int:
        if char == '_':
            return 0
        return ord(char) - ord('a') + 1

    # Process the measurement string and convert it to a list of integers.
    def process_measurement(self, measurement: Measurement) -> list:
        user_string = measurement.get_value_as_str()
        logging.debug(f"[Service] Processing measurement: {user_string}")
        result = []
        # Check if the string is empty or None.
        i = 0
        while i < len(user_string):
            # Process indicator.
            if user_string[i] == 'z' and (i + 1) < len(user_string):
                indicator_val = 26 + self.char_value(user_string[i + 1])
                i += 2
            else:
                indicator_val = self.char_value(user_string[i])
                i += 1

            # If the indicator value is zero, add package with 0 value.
            if indicator_val == 0:
                result.append(0)
                continue

            # Ensure there are sufficient measurement characters.
            if i >= len(user_string):
                break

            units_processed = 0
            sum_val = 0
            first_unit_was_z = False
            # Process the measurement characters.
            while units_processed < indicator_val and i < len(user_string):
                # Check for 'z' and process accordingly.
                if user_string[i] == 'z' and (i + 1) < len(user_string):
                    unit_val = 26 + self.char_value(user_string[i + 1])
                    if units_processed == 0:
                        first_unit_was_z = True
                    i += 2
                # Process other characters.
                else:
                    unit_val = self.char_value(user_string[i])
                    i += 1
                sum_val += unit_val
                units_processed += 1

            # Check if the number of units processed matches the indicator value.
            if units_processed == indicator_val:
                if indicator_val == 1 and first_unit_was_z:
                    sum_val += 1
                result.append(sum_val)
            # If the number of units processed is less than the indicator value, add 0.
            else:
                break

        logging.debug(f"[Service] Finished processing. Result: {result}")
        return result

# -----------------------------------------------------------------------------
# Class: SecureHistoryStorage
# Responsibility: Securely store and retrieve history in an encrypted local file.
# -----------------------------------------------------------------------------
class SecureHistoryStorage:
    # Securely store and retrieve history in an encrypted local file.
    def __init__(self,
                 # File names for encrypted history and keys.
                 enc_file: str = "secure_history.enc",
                 private_key_file: str = "private_key.pem",
                 public_key_file: str = "public_key.pem"):
        # Initialize the file names and keys.
        self.enc_file = enc_file
        self.private_key_file = private_key_file
        self.public_key_file = public_key_file
        self.history = []  # in-memory history list
        self._load_or_generate_keys()
        self._load_history()

    # Load or generate RSA keys for encryption/decryption.
    def _load_or_generate_keys(self):
        # Check if the key files exist; if not, generate new keys.
        if os.path.exists(self.private_key_file) and os.path.exists(self.public_key_file):
            with open(self.private_key_file, "rb") as key_file:
                # Load the private key from the file.
                self.private_key = serialization.load_pem_private_key(key_file.read(), password=None)
            with open(self.public_key_file, "rb") as key_file:
                self.public_key = serialization.load_pem_public_key(key_file.read())
        else:
            # Generate new RSA keys.
            self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            self.public_key = self.private_key.public_key()
            # Save the keys to files.
            with open(self.private_key_file, "wb") as key_file:
                key_file.write(self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            # Save the public key to a file. 
            with open(self.public_key_file, "wb") as key_file:
                key_file.write(self.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))
    # Load the history from the encrypted file.
    def _encrypt_data(self, data: bytes) -> bytes:
        # Hybrid encryption using AES and RSA: Generate a random AES key and IV.
        aes_key = os.urandom(32)  # AES-256 key.
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        # PKCS7 padding.
        pad_length = 16 - (len(data) % 16)
        padded_data = data + bytes([pad_length] * pad_length)
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        # Encrypt the AES key using the RSA public key.
        encrypted_key = self.public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        # Encode the encrypted key, IV, and ciphertext in base64 for storage.
        payload = {
            "encrypted_key": base64.b64encode(encrypted_key).decode('utf-8'),
            "iv": base64.b64encode(iv).decode('utf-8'),
            "ciphertext": base64.b64encode(ciphertext).decode('utf-8')
        }
        return json.dumps(payload).encode('utf-8')
    
    # Decrypt the data using the RSA private key and AES.
    def _decrypt_data(self, enc_data: bytes) -> bytes:
        payload = json.loads(enc_data.decode('utf-8'))
        encrypted_key = base64.b64decode(payload["encrypted_key"])
        iv = base64.b64decode(payload["iv"])
        ciphertext = base64.b64decode(payload["ciphertext"])
        # Decrypt the AES key using the RSA private key.
        aes_key = self.private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        # Decrypt the AES ciphertext using the decrypted AES key and IV.
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        # Create a decryptor and decrypt the data.
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        pad_length = padded_data[-1]
        data = padded_data[:-pad_length]
        return data

    # Load the history from the encrypted file.
    def _load_history(self):
        if os.path.exists(self.enc_file):
            # Read the encrypted file and decrypt it.
            with open(self.enc_file, "rb") as f:
                enc_data = f.read()
                try:
                    decrypted = self._decrypt_data(enc_data)
                    self.history = json.loads(decrypted.decode('utf-8'))
                except Exception as e:
                    logging.error(f"Failed to decrypt history: {e}")
                    self.history = []
        # If the file does not exist, initialize an empty history.
        else:
            self.history = []

    # Add a new entry to the history and save it securely.
    def add_history(self, input_str: str, result: list):
        # Check if the input string is valid.
        entry = {
            "input": input_str,
            "result": result,
            "timestamp": datetime.now().isoformat()
        }
        self.history.append(entry)
        # Immediately update the encrypted storage when a new entry is added.
        self.save_history()

    # Get the current history.
    def get_history(self) -> list:
        return self.history

    ## Save the history to the encrypted file.
    def save_history(self):
        data = json.dumps(self.history).encode('utf-8')
        enc = self._encrypt_data(data)
        with open(self.enc_file, "wb") as f:
            f.write(enc)
        logging.info("Secure history saved to disk.")

# -----------------------------------------------------------------------------
# API Endpoints Setup (Controller)
# Responsibility: Expose the /convert, /secure-history endpoints.
# -----------------------------------------------------------------------------
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Adjust this in production to restrict allowed origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

secure_history_storage = SecureHistoryStorage()
measurement_service = MeasurementService()

@app.get("/convert")
# /convert endpoint to process measurement strings.
def convert_measurements(convert_measurements: str = Query(..., alias="convert-measurements")):
    # Validate the input measurement string.
    logging.info(f"[API] Received /convert request with input: {convert_measurements}")
    # Create a Measurement object and validate it.
    measurement = Measurement(convert_measurements)
    if not measurement.is_valid():
        return {"error": "Invalid measurement string."}
    # Process the measurement string using the MeasurementService.
    result = measurement_service.process_measurement(measurement)
    secure_history_storage.add_history(measurement.get_value_as_str(), result)
    logging.info(f"[API] Processed and added secure history entry: {result}")
    return {"result": result}

@app.get("/secure-history")
# /secure-history endpoint to retrieve the secure history.
def get_secure_history():
    # Retrieve the secure history from storage.
    logging.info("[API] Received /secure-history request")
    # Check if the history is empty.
    return {"secure_history": secure_history_storage.get_history()}

# -----------------------------------------------------------------------------
# Shutdown Event: Save secure history before shutting down.
# -----------------------------------------------------------------------------
@app.on_event("shutdown")
def shutdown_event():
    secure_history_storage.save_history()

# -----------------------------------------------------------------------------
# Server Startup
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    port = 8888
    logging.info(f"[API] Starting FastAPI server on port: {port}")
    uvicorn.run(app, host="0.0.0.0", port=port)