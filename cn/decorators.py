import tornado
from cn.utils import auth_headers_parse


def authentication(url_for_check):
    def decorator(func):
        @tornado.gen.coroutine
        def wrapper(self, **kwargs):
            # http_client = self.get_async_http_client()
            # try:
            #     auth_params = auth_headers_parse(self.request.headers)
            # except KeyError as e:
            #     raise tornado.web.HTTPError(400, '%s is required' % str(e))
            #
            # url = tornado.httputil.url_concat(url_for_check, auth_params)
            # try:
            #     response = yield http_client.fetch(url,
            #                                        connect_timeout=float('inf'),
            #                                        request_timeout=float('inf'))
            #     return func(self, **kwargs)
            # except tornado.httpclient.HTTPError as e:
            #     print('Exception:%s' % url)
            #     raise tornado.web.HTTPError(e.code, 'Token not valid')
            return func(self, **kwargs)
        return wrapper
    return decorator
