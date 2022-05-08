from datetime import datetime, timedelta
from time import mktime
from tornado.escape import json_decode, utf8
from tornado.gen import coroutine
from uuid import uuid4
import hashlib, os
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from .base import BaseHandler

class LoginHandler(BaseHandler):

    @coroutine
    def hash_password(self, password, password_salt):
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
        kdf = Scrypt(salt=password_salt, length=32, n=2 ** 14, r=8, p=1)
        password_bytes = bytes(password, "utf-8")
        password_object = kdf.derive(password_bytes)
        key = str(password_object)
        return key

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
    def generate_token(self, email):
        token_uuid = uuid4().hex
        expires_in = datetime.now() + timedelta(hours=2)
        expires_in = mktime(expires_in.utctimetuple())

        token = {
            'token': token_uuid,
            'expiresIn': expires_in,
        }

        yield self.db.users.update_one({
            'email': email
        }, {
            '$set': token
        })

        return token

    @coroutine
    def post(self):
        try:
            body = json_decode(self.request.body)
            email = body['email'].lower().strip()
            email_hash = yield self.hash_email(email)
            if not isinstance(email, str):
                raise Exception()
            password = body['password']
            if not isinstance(password, str):
                raise Exception()
        except:
            self.send_error(400, message='You must provide an email address and password!')
            return

        if not email:
            self.send_error(400, message='The email address is invalid!')
            return

        if not password:
            self.send_error(400, message='The password is invalid!')
            return

        user = yield self.db.users.find_one({
          'emailHash': email_hash
        })

        if user is None:
            self.send_error(403, message='The user could not be found!')
            return

        if user['emailHash'] != email_hash:
            self.send_error(403, message='The email or password is not valid!')
            return

        try:
            hashed_pw = yield self.hash_password(password, user['passwordSalt'])
            if user['password'] != hashed_pw:
                raise Exception()
        except Exception as e:
            self.send_error(403, message='The email or password is not valid!')
            return

        token = yield self.generate_token(user['email'])

        self.set_status(200)
        self.response['token'] = token['token']
        self.response['expiresIn'] = token['expiresIn']

        self.write_json()
