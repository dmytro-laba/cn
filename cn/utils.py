import base64
from calendar import timegm
from contextlib import suppress
from email.utils import formatdate
import hashlib
import hmac
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Hash import MD5
from Crypto.PublicKey import RSA
import tornado
from datetime import datetime, timedelta
import chu
import sys
from cn.models import AsyncRabbitConsumer
import boto
from boto.s3.key import Key

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]


class AESCipher:
    # pycrypto helper
    def __init__(self, key):
        self.key = key

    def encrypt(self, raw):
        raw = pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:16]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(enc[16:]))


class UserAESCipher:
    # pycrypto helper
    def __init__(self, user_id, keys_dir, aws_access_key=None, aws_secret_key=None, aws_bucket=None):
        self.keys_dir = keys_dir
        self.user_id = user_id

        self.aws_bucket = aws_bucket
        self.aws_access_key = aws_access_key
        self.aws_secret_key = aws_secret_key

        # Enable amazon
        self.is_amazon = False
        self.boto = None
        self.bucket = None
        if self.aws_access_key and self.aws_secret_key and self.aws_bucket:
            # TODO: add check amazon
            self.is_amazon = True
            self.boto = boto.connect_s3(self.aws_access_key, self.aws_secret_key)
            self.bucket = self.boto.get_bucket(self.aws_bucket)

        self.key_hash = self.get_key_hash()
        self.cipher = AESCipher(self.key_hash)

    def get_key_hash(self):
        if self.is_amazon:
            return self.get_aws_key_hash()

        return self.get_local_key_hash()

    def get_local_key_hash(self):
        f = open('%s/user_%s_key.pem' % (self.keys_dir, self.user_id), 'rb')
        key = RSA.importKey(f.read())
        key_hash = MD5.new(key.exportKey('PEM')).hexdigest()
        return key_hash

    def get_aws_key_hash(self):
        s3_key = self.bucket.get_key('/{keys_dir}/user_{user_id}_key.pem'.format(keys_dir=self.keys_dir, user_id=self.user_id))

        if not s3_key:
            return None

        key = RSA.importKey(s3_key.get_contents_as_string())
        key_hash = MD5.new(key.exportKey('PEM')).hexdigest()

        return key_hash

    def create_key(self):
        if self.is_amazon:
            return self.create_aws_key()

        return self.create_local_key()

    def create_local_key(self):
        key = RSA.generate(2048)
        f = open('%s/user_%s_key.pem' % (self.keys_dir, self.user_id), 'wb')
        f.write(key.exportKey('PEM'))
        f.close()

        return key

    def create_aws_key(self):
        key = RSA.generate(2048)

        k = Key(self.bucket)
        k.key = '/{keys_dir}/user_{user_id}_key.pem'.format(keys_dir=self.keys_dir, user_id=self.user_id)

        k.set_contents_from_string(key.exportKey('PEM'))

        return key

    def encrypt(self, raw):
        return self.cipher.encrypt(raw).decode()

    def decrypt(self, enc):
        bytes(enc, 'UTF-8')
        return self.cipher.decrypt(enc).decode()




class AsyncUserAESCipher(object):
    AWS_S3_BUCKET_URL = "http://%(bucket)s.s3.amazonaws.com/%(path)s"
    AWS_S3_CONNECT_TIMEOUT = 10
    AWS_S3_REQUEST_TIMEOUT = 90

    def __init__(self, user_id, keys_dir, aws_access_key=None, aws_secret_key=None, aws_bucket=None):
        self.keys_dir = keys_dir
        self.user_id = user_id

        self.aws_bucket = aws_bucket
        self.aws_access_key = aws_access_key
        self.aws_secret_key = aws_secret_key

        # Enable amazon
        self.is_amazon = False
        if self.aws_access_key and self.aws_secret_key and self.aws_bucket:
            self.is_amazon = True
            self._client = AsyncHTTPClient()

    @tornado.gen.coroutine
    def create_cipher(self):
        self.key_hash = yield self.get_key_hash()
        self.cipher = AESCipher(self.key_hash)

    @tornado.gen.coroutine
    def get_key_hash(self):
        method = "GET"
        headers = {}
        path = '{keys_dir}/user_{user_id}_key.pem'.format(keys_dir=self.keys_dir, user_id=self.user_id)
        self._signHeaders(method, path, headers)

        try:
            response = yield self._client.fetch(
                self.AWS_S3_BUCKET_URL % {
                    "bucket": self.aws_bucket,
                    "path": path,
                },
                method=method,
                body=None,
                connect_timeout=self.AWS_S3_CONNECT_TIMEOUT,
                request_timeout=self.AWS_S3_REQUEST_TIMEOUT,
                headers=headers
            )

            if response.code == 200:
                # Get the metadata from the headers
                data = response.body
                return data

        except tornado.httpclient.HTTPError as error:

            if error.code == 404:
                pass

        return None

    def encrypt(self, raw):
        return self.cipher.encrypt(raw).decode()

    def decrypt(self, enc):
        bytes(enc, 'UTF-8')
        return self.cipher.decrypt(enc).decode()

    def _getRFC822DateTime(self, t=None):
        """
        Generate date in RFC822 format
        """

        if t is None:
            t = datetime.utcnow()

        return formatdate(timegm(t.timetuple()), usegmt=True)

    def _signHeaders(self, method, path, headers):
        date = self._getRFC822DateTime()

        # amz_headers_set = ["%s:%s" % (key.lower(), value)
        #                    for key, value in headers.iteritems()
        #                    if key.lower().startswith('x-amz')]
        # amz_headers_set.sort()
        # amz_headers_string = "\n".join(amz_headers_set).rstrip()

        signature_strings = \
            [
                "{method}",
                "{content_md5}",
                "{content_type}",
                "{date}"
            ]
        # if len(amz_headers_string) > 0:
        #     signature_strings.append(amz_headers_string)
        signature_strings.append("/{bucket}/{path}")

        signature = "\n".join(signature_strings).format(
            method=method,
            content_type=headers.get("Content-Type") or "",
            content_md5=headers.get("Content-MD5") or "",
            date=date,
            bucket=self.aws_bucket,
            path=path
        )

        try:

            auth_signature = base64.b64encode(hmac.new(
                self.aws_secret_key.encode("utf-8"),
                signature.encode("utf-8"),
                hashlib.sha1
            ).digest()).strip()

        except UnicodeDecodeError as e:
            pass

        headers.update({
            "Date": date,
            "Authorization": "AWS %(access_key)s:%(auth_signature)s" % {
                "access_key": self.aws_access_key,
                "auth_signature": auth_signature,
            }
        })


def get_img_to_base64(path):
    with open(path, "rb") as image_file:
        encoded_string = base64.b64encode(image_file.read())
    return encoded_string.decode("utf-8")


def auth_signature(secret, salt):
    from hashlib import sha1
    import hmac
    import base64

    if type(secret) == str:
        secret = bytes(secret, 'UTF-8')

    if type(salt) == str:
        salt = bytes(salt, 'UTF-8')

    hashed = hmac.new(secret, salt, sha1)

    return base64.b64encode(hashed.digest()).decode()


def auth_headers_parse(headers):
    salt = headers['Salt']
    auth = headers['Authorization']
    public, signature = auth.split(': ')

    return dict(public=public, signature=signature, salt=salt)


def auth_headers_request(public, secret, headers=None):
    headers = headers or {}

    salt = str(datetime.timestamp(datetime.now()))
    signature = auth_signature(secret, salt)

    headers['Salt'] = salt
    headers['Authorization'] = '%s: %s' % (public, signature)

    return headers


@tornado.gen.coroutine
def rpc_fetch(rpc_client, queue, timeout=None, **params):
    rpc_request = chu.rpc.RPCRequest(exchange='',
                                     routing_key=queue,
                                     params=params)

    future = yield tornado.gen.Task(rpc_client.rpc, rpc_request)
    if timeout is None:
        timeout = sys.maxsize

    response = yield tornado.gen.Task(future.get, timeout=timedelta(seconds=timeout))

    return response


