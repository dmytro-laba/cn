from tornado.concurrent import Future
from tornado.httpclient import HTTPRequest, HTTPResponse
from io import StringIO


def setup_fetch(fetch_mock, status_code, body=None):
    def side_effect(request, **kwargs):
        if request is not HTTPRequest:
            request = HTTPRequest(request)
        buffer = StringIO(body)
        response = HTTPResponse(request, status_code, buffer=buffer)
        future = Future()
        if response.error:
            future.set_exception(response.error)
        else:
            future.set_result(response)
        return future

    fetch_mock.side_effect = side_effect

def setup_fetch_with_unknown_error(fetch_mock):
    def side_effect(request):
        raise Exception('Error')

    fetch_mock.side_effect = side_effect