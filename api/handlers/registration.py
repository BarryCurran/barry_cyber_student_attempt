from json import dumps
from logging import info
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from tornado.escape import json_decode
from tornado.gen import coroutine
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from .base import BaseHandler
import hashlib, os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class RegistrationHandler(BaseHandler):

    @coroutine
    def hash_password(self, password):
        """
        This function hashes the password using the Python Scrypt (RFC 7914) cryptographic algorithm. The function
        generates a salt for the object and stores it in a variable object salt. This salt value is also returned so
        that it can be used to recreate the password hash during login. The Scrypt algorithm uses the 16-bit random
        generated number as a salt, iterations count (n) of 2 ** 14 (16384), length of 32 bytes (256-bits), a block size
        of 8 (r) and a parallelism factor of 1 (p). This algorithm is then used to derive the hash or key of the object
        which is used as an argument when calling the function. The hash is then stored as a string to the variable key
        and is returned. A salted hashing algorithm for protecting passwords is critical to protect against hash
        cracking attacks or rainbow table attacks. It ensures that every user password hash is unique even if the same
        password is used.
        """
        password_salt = os.urandom(16)
        kdf = Scrypt(salt=password_salt, length=32, n=2 ** 14, r=8, p=1)
        password_bytes = bytes(password, "utf-8")
        password_object = kdf.derive(password_bytes)
        key = str(password_object)
        return key, password_salt

    @coroutine
    def hash_email(self, email):
        """
        This function hashes the email using the sha256 hashing algorithm. The email hash is used for indexing during
        login and other functions. As the email must be unique for each user salting is not required. The email will
        also be stored in encrypted format for use elsewhere in the application. The purpose of the non-salted hash is
        to index the user during registration and ensure another user does not already have an account with the email
        address.
        """
        m = hashlib.sha256()
        email_bytes = bytes(email, "utf-8")
        m.update(email_bytes)
        emailsha256 = m.digest()
        emailsha256decoded = emailsha256.hex()
        return emailsha256decoded

    @coroutine
    def encrypt_object(self, plaintext, hashed_password):
        """
        This function encrypts the data using a PBKDF2 (Password Based Key Derivation Function). The PBKDF is different
        from the password hash (also a Key Derivation Function) as it allows encryption to occur without the need to
        store the encryption key in the database. By using the hashed_password instead of the plaintext password as the
        input to the kdf it allows the kdf to be recreated from the stored hash vs the plaintext password. At each login
        and when an authenticated user is pulling their user profile the key can be recreated in order to decrypt the
        data. The function generates a 16 byte nonce and salt which are both returned to store and be used in the
        decryption function at login and during user profile calls. A sha256 key of length 24 bytes is generated and
        then used as the secret key in the aes ctr (Advanced Encryption Standard Counter stream cipher) to encrypt the
        object. The encrypted object nonce and salt are returned.
        """
        nonce = os.urandom(16)
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=24,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        hashed_password_bytes = bytes(hashed_password, "utf-8")
        key = base64.urlsafe_b64encode(kdf.derive(hashed_password_bytes))
        aes_ctr_cipher = Cipher(algorithms.AES(key), mode=modes.CTR(nonce))
        aes_ctr_encryptor = aes_ctr_cipher.encryptor()
        object_bytes = bytes(plaintext, "utf-8")
        encrypted_object = aes_ctr_encryptor.update(object_bytes)
        return encrypted_object, nonce, salt

    @coroutine
    def post(self):
        try:
            body = json_decode(self.request.body)
            email = body['email'].lower().strip()
            email_hash = yield self.hash_email(email)
            if not isinstance(email, str):
                raise Exception()
            password = body['password']
            hashed_pw, pw_salt = yield self.hash_password(password)
            if not isinstance(password, str):
                raise Exception()
            display_name = body.get('displayName')
            if display_name is None:
                display_name = email
            if not isinstance(display_name, str):
                raise Exception()
            name = body.get('name')
            if not isinstance(name, str):
                raise Exception()
            phone_number = body.get('phoneNumber')
            if not isinstance(phone_number, str):
                raise Exception()
            disabilities = body.get('disabilities')
            if not isinstance(disabilities, str):
                raise Exception()
        except Exception as e:
            self.send_error(400, message='You must provide an email address, password, display name, name, phone number and disabilities!')
            return

        if not email:
            self.send_error(400, message='The email address is invalid!')
            return

        if not password:
            self.send_error(400, message='The password is invalid!')
            return

        if not display_name:
            self.send_error(400, message='The display name is invalid!')
            return

        if not name:
            self.send_error(400, message='The name is invalid!')
            return

        if not phone_number:
            self.send_error(400, message='The phone number is invalid!')
            return

        if not disabilities:
            self.send_error(400, message='The disabilities is invalid!')
            return

        user = yield self.db.users.find_one({
          'emailHash': email_hash
        }, {})

        if user is not None:
            self.send_error(409, message='A user with the given email address already exists!')
            return

        try:
            encrypted_email, email_nonce, email_salt = yield self.encrypt_object(email, hashed_pw)
            if not isinstance(encrypted_email, bytes):
                raise Exception()
            encrypted_display_name, display_nonce, display_salt = yield self.encrypt_object(display_name, hashed_pw)
            if not isinstance(encrypted_display_name, bytes):
                raise Exception()
            encrypted_name, name_nonce, name_salt = yield self.encrypt_object(name, hashed_pw)
            if not isinstance(encrypted_name, bytes):
                raise Exception()
            encrypted_phone_number, phone_nonce, phone_salt = yield self.encrypt_object(phone_number, hashed_pw)
            if not isinstance(encrypted_phone_number, bytes):
                raise Exception()
            encrypted_disabilities, disabilities_nonce, disabilities_salt = yield self.encrypt_object(disabilities, hashed_pw)
            if not isinstance(encrypted_disabilities, bytes):
                raise Exception()
        except:
            self.send_error(400, message='Something went wrong with encryption')

        yield self.db.users.insert_one({
            'email': encrypted_email, # The encrypted email address is stored to protect users confidentiality & privacy while also being available to use when user login and return profile information.
            'emailHash': email_hash, # Email hash is stored for indexing. Encryption is not required as hash provides adequate cryptographic protection.
            'emailNonce': email_nonce, # Email nonce is stored for decryption. These are not considered secrets and therefore, encryption is not required.
            'emailSalt': email_salt, # Email salt is stored for decryption. These are not considered secrets and therefore, encryption is not required.
            'password': hashed_pw, # The password is never stored anywhere in the app to protect the user account. Only a one-way, salted, hash of the password is stored. This is then regenerated and verified during login. Encryption is not required as hash provides adequate cryptographic protection.
            'passwordSalt': pw_salt, # The password salt is stored to regenerate the hash at login. As a salt is not considered secret information it does not need to be encrypted when stored.
            'displayName': encrypted_display_name, # As the display name is considered PII under GDPR as it distinguishes one user from another and is therefore, stored in encrypted format to protect user confidentiality and privacy.
            'displayNonce': display_nonce, # Display nonce is stored for decryption. These are not considered secrets and therefore, encryption is not required.
            'displaySalt': display_salt, # Display salt is stored for decryption. These are not considered secrets and therefore, encryption is not required.
            'name': encrypted_name, # As the name is considered PII under GDPR as it identifies a user from another and is therefore, stored in encrypted format to protect user confidentiality and privacy.
            'nameNonce': name_nonce, # Name nonce is stored for decryption. These are not considered secrets and therefore, encryption is not required.
            'nameSalt': name_salt, # Name salt is stored for decryption. These are not considered secrets and therefore, encryption is not required.
            'phoneNumber': encrypted_phone_number, # As the phone number is considered PII under GDPR as it distinguishes one user from another and is therefore, stored in encrypted format to protect user confidentiality and privacy.
            'phoneNumberNonce': phone_nonce, # Phone number nonce is stored for decryption. These are not considered secrets and therefore, encryption is not required.
            'phoneNumberSalt': phone_salt, # Phone number salt is stored for decryption. These are not considered secrets and therefore, encryption is not required.
            'disabilities': encrypted_disabilities, # As the disabilities is considered PII under GDPR as it distinguishes one user from another and is therefore, stored in encrypted format to protect user confidentiality and privacy.
            'disabilitiesNonce': disabilities_nonce, # Disabilities nonce is stored for decryption. These are not considered secrets and therefore, encryption is not required.
            'disabilitiesSalt': disabilities_salt # Disabilities salt is stored for decryption. These are not considered secrets and therefore, encryption is not required.
        })

        self.set_status(200)
        self.response['email'] = str(encrypted_email) # Return encrypted email so user PII is not exposed on the terminal.
        self.response['displayName'] = str(encrypted_display_name) # Return encrypted display name so user PII is not exposed on the terminal.

        self.write_json()
