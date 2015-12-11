import tornado
from cn.utils import auth_headers_parse


def authentication(url_for_check):
    def decorator(func):
        @tornado.gen.coroutine
        def wrapper(self, **kwargs):
            http_client = self.get_async_http_client()

            try:
                auth_params = auth_headers_parse(self.request.headers)
            except KeyError as e:
                raise tornado.web.HTTPError(400, '%s is required' % str(e))

            try:
                url = tornado.httputil.url_concat(url_for_check, auth_params)
                response = yield http_client.fetch(url)
                return func(self, **kwargs)
            except tornado.httpclient.HTTPError as e:
                raise tornado.web.HTTPError(e.code, 'Token not valid')
            return wrapper
    return decorator
