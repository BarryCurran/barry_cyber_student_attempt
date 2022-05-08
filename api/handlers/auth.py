from datetime import datetime
from time import mktime
from tornado.gen import coroutine

from .base import BaseHandler

class AuthHandler(BaseHandler):

    @coroutine
    def prepare(self):
        super(AuthHandler, self).prepare()

        if self.request.method == 'OPTIONS':
            return

        try:
            token = self.request.headers.get('X-Token')
            if not token:
              raise Exception()
        except:
            self.current_user = None
            self.send_error(400, message='You must provide a token!')
            return

        # Updated this to include all data objects needed to decrypt the objects in the database.
        user = yield self.db.users.find_one({
            'token': token
        }, {
            'email': 1,
            'password': 1,
            'displayName': 1,
            'expiresIn': 1,
            'name': 1,
            'phoneNumber': 1,
            'disabilities': 1,
            'emailNonce': 1,
            'emailSalt': 1,
            'displayNonce': 1,
            'displaySalt': 1,
            'nameNonce': 1,
            'nameSalt': 1,
            'phoneNumberNonce': 1,
            'phoneNumberSalt': 1,
            'disabilitiesNonce': 1,
            'disabilitiesSalt': 1
        })

        if user is None:
            self.current_user = None
            self.send_error(403, message='Your token is invalid!')
            return

        current_time = mktime(datetime.now().utctimetuple())
        if current_time > user['expiresIn']:
            self.current_user = None
            self.send_error(403, message='Your token has expired!')
            return

        # Updated this to include all data objects needed to decrypt the objects in the database.
        self.current_user = {
            'email': user['email'],
            'password': user['password'],
            'display_name': user['displayName'],
            'name': user['name'],
            'phoneNumber': user['phoneNumber'],
            'disabilities': user['disabilities'],
            'emailNonce': user['emailNonce'],
            'emailSalt': user['emailSalt'],
            'displayNonce': user['displayNonce'],
            'displaySalt': user['displaySalt'],
            'nameNonce': user['nameNonce'],
            'nameSalt': user['nameSalt'],
            'phoneNumberNonce': user['phoneNumberNonce'],
            'phoneNumberSalt': user['phoneNumberSalt'],
            'disabilitiesNonce': user['disabilitiesNonce'],
            'disabilitiesSalt': user['disabilitiesSalt']
        }
