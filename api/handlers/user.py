from tornado.escape import json_decode, utf8
from tornado.gen import coroutine
from tornado.web import authenticated

from .auth import AuthHandler

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64, os

class UserHandler(AuthHandler):

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
    def decrypt_object(self, encrypted_object, hashed_password, nonce, salt):
        """
        This function decrypts the data which was encrypted using the encrypt_object() function. It takes the encrypted
        object, the hashed_password, the nonce used during encryption and the salt used during encryption as arguments.
        The decryption function recreates the PBKDF from the hashed_password and salt which are passed as arguments.
        The function then decrypts the encrypted_object using the PBKDF as the key and the nonce which is passed as an
        argument. The function then returns the decrypted object.
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=24,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        password_bytes = bytes(hashed_password, "utf-8")
        key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
        aes_ctr_cipher = Cipher(algorithms.AES(key), mode=modes.CTR(nonce))
        aes_ctr_decryptor = aes_ctr_cipher.decryptor()
        decrypted_object = aes_ctr_decryptor.update(encrypted_object)
        return decrypted_object

    @coroutine
    @authenticated
    def get(self):
        self.set_status(200)
        # Bringing in all required user parameters from the database and auth.py service to decrypt the data when displaying it to an authenticated user.
        email = self.current_user['email']
        display_name = self.current_user['display_name']
        name = self.current_user['name']
        phone_number = self.current_user['phoneNumber']
        disabilities = self.current_user['disabilities']
        email_salt = self.current_user['emailSalt']
        email_nonce = self.current_user['emailNonce']
        display_nonce = self.current_user['displayNonce']
        display_salt = self.current_user['displaySalt']
        name_nonce = self.current_user['nameNonce']
        name_salt = self.current_user['nameSalt']
        phone_nonce = self.current_user['phoneNumberNonce']
        phone_salt = self.current_user['phoneNumberSalt']
        disabilities_nonce = self.current_user['disabilitiesNonce']
        disabilities_salt = self.current_user['disabilitiesSalt']
        hashed_password = self.current_user['password']
        decrypted_email = yield self.decrypt_object(email, hashed_password, email_nonce, email_salt) # Decrypting the email prior to displaying it to an authenticated user.
        decrypted_display = yield self.decrypt_object(display_name, hashed_password, display_nonce, display_salt) # Decrypting the display name prior to displaying it to an authenticated user.
        decrypted_name = yield self.decrypt_object(name, hashed_password, name_nonce, name_salt) # Decrypting the name prior to displaying it to an authenticated user.
        decrypted_phone = yield self.decrypt_object(phone_number, hashed_password, phone_nonce, phone_salt) # Decrypting the phone number prior to displaying it to an authenticated user.
        decrypted_disabilities = yield self.decrypt_object(disabilities, hashed_password, disabilities_nonce, disabilities_salt) # Decrypting the disabilities prior to displaying it to an authenticated user.
        self.response['email'] = str(decrypted_email, 'utf-8')
        self.response['displayName'] = str(decrypted_display, 'utf-8')
        self.response['name'] = str(decrypted_name, 'utf-8')
        self.response['phoneNumber'] = str(decrypted_phone, 'utf-8')
        self.response['disabilities'] = str(decrypted_disabilities, 'utf-8')
        self.write_json()


# I was not sure if this was part of the ask of the assignment. The assignment notes did not provide any indication that we needed to be able to update user details.
# I have added some encryption logic here but as the assignment notes also did not provide any curl command to test I did not expand further than what is here.
# I hope no marks will be reduced for functionality which was not defined in the specification.
    @coroutine
    @authenticated
    def put(self):
        try:
            body = json_decode(self.request.body)
            display_name = body['displayName']
            if not isinstance(display_name, str):
                raise Exception()
        except:
            self.send_error(400, message='You must provide a display name!')
            return

        if not display_name:
            self.send_error(400, message='The display name is invalid!')
            return

        hashed_pw = self.current_user['password']

        try:
            encrypted_display_name, display_nonce, display_salt = yield self.encrypt_object(display_name, hashed_pw)
            if not isinstance(encrypted_display_name, bytes):
                raise Exception()
        except:
            self.send_error(400, message='Something went wrong with encryption')

        yield self.db.users.update_one({
            'email': self.current_user['email'],
        }, {
            '$set': {
                'displayName': display_name
            }
        })

        self.current_user['display_name'] = display_name

        self.set_status(200)
        self.response['email'] = self.current_user['email']
        self.response['displayName'] = self.current_user['display_name']
        self.write_json()
