from tornado.httpclient import AsyncHTTPClient
from utils import UserAESCipher


class AsyncClientMixin(object):
    # Mixin for no copy of the code.
    def get_async_http_client(self):
        return AsyncHTTPClient()

    def get_user_cipher(self, user_id, keys_dir):
        return UserAESCipher(user_id, keys_dir)