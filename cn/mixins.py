from tornado.httpclient import AsyncHTTPClient
from cn.utils import UserAESCipher, AsyncUserAESCipher
from tornado import gen

class AsyncClientMixin(object):
    # Mixin for no copy of the code.
    def get_async_http_client(self):
        return AsyncHTTPClient()

    def get_user_cipher(self, user_id, keys_dir, aws_access_key=None, aws_secret_key=None, aws_bucket=None):
        return UserAESCipher(user_id, keys_dir, aws_access_key, aws_secret_key, aws_bucket)

    def get_async_user_cipher(self, user_id, keys_dir, aws_access_key=None, aws_secret_key=None, aws_bucket=None):
        return AsyncUserAESCipher(user_id, keys_dir, aws_access_key, aws_secret_key, aws_bucket)