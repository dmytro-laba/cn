import os
import logging
import librets
import tornado
import tornado.ioloop
import tornado.web
from pymongo import MongoClient
from tornado import httpclient
from tornado.escape import json_decode, json_encode
from tornado.httpclient import HTTPResponse, HTTPRequest

from io import BytesIO
from datetime import date, datetime, timedelta
from dateutil import parser

from cn.proxy import BaseProxy
from cn.mixins import AsyncClientMixin
from cn.utils import auth_headers_request
from constants import *

log = logging.getLogger()
log.setLevel(logging.DEBUG)

class BaseMlsProxy(AsyncClientMixin, BaseProxy):
    def __init__(self, auth_public, auth_secret):
        self.auth_public = auth_public
        self.auth_secret = auth_secret
        self.RETS_USER_AGENT = 'MRIS Conduit/1.0'
        self.RETS_USER_AGENT_PASSWORD = ''

        self.CONNECTOR_REGISTER_DATA = {}
        self.MLS_LOGIN_URL = ''
        self.MLS_SHORT_NAME = '<BaseMLS>'
        self.RETS_SELECT_QUERIES = {
            '<CLASS>' : '<Field1>,<Field2>'
        }

        # Dict of {'class_name': {'key': 'value'}} pairs for initializing empy listing, May be overwritten by data from MLS.
        self.RETS_CLASSES_DEFAULT_VALUES = {}

        # Dict of {'key': {'old_value': 'new_value'}} pairs for overwriting values received from MLS.
        self.RETS_VALUE_OVERRIDES = {}

        # Dict of {'existing_key': 'needed_key'}} pairs for adding needed keys to listings when you need to take
        # different keys from different classes but in mapping you can use only one key for sending data.
        self.RETS_KEY_OVERRIDES = {}

        # Override this value in child class if you need to search by date only.
        # Otherwise you can override 'get_search_query' method.
        self.RETS_DEFAULT_SEARCH_QUERY = '(<DATE_CREATED>=%s+)'

        self.RETS_DEFAULT_LIMIT = 10000
        self.RETS_LISTING_DATE_FIELD = '<LIST_DATE>'
        self.RETS_LISTING_ID_FIELD = '<LIST_ID>'
        self.RETS_DATE_FIELDS = ['<LIST_DATE>', '<EXPIRE_DATE>']
        self.RETS_ADDRESS_FIELDS = []
        self.RETS_CITY_FIELD = ''
        self.RETS_STATE_FIELD = ''
        self.RETS_ZIP_FIELD = ''

        self.HUB_URL = os.environ.get('HUB_URL', 'https://hub-stg.apination.com/')
        self.HUB_REGISTER_PROXY_URL = self.HUB_URL + os.environ.get('HUB_REGISTER_PROXY_URL', 'register/proxy')
        self.HUB_LOGS_URL = self.HUB_URL + os.environ.get('HUB_LOGS_URL', 'logs')

        # Override this value for storing and checking listing ids that were processed for each trigger.
        self.MONGO_STORE_LISTING_IDS = False
        self.MONGODB_URL = os.environ.get('MONGODB_URL', 'mongodb://localhost:27017')
        self.MONGODB_DB_NAME = os.environ.get('MONGODB_DB_NAME', 'apination_hub')
        self.MONGODB_COLLECTION_NAME = os.environ.get('MONGODB_COLLECTION_NAME', 'mls_test_collection')

        self.USE_CIPHER_AND_LOGS = True # Override this as False only for local testing.
        self.AWS_USERS_KEYS_DIR = os.environ.get('AWS_USERS_KEYS_DIR', 'environments/staging/secrets')
        self.AWS_BUCKET_NAME = os.environ.get('AWS_BUCKET_NAME', 'apination')
        self.AWS_ACCESS_KEY_ID = os.environ.get('AWS_ACCESS_KEY_ID', 'AKIAJUT3EQCT3OXEXGQQ')
        self.AWS_SECRET_ACCESS_KEY = os.environ.get('AWS_SECRET_ACCESS_KEY', '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')

    def get_rets_session(self):
        """ Returns RETS session object, initialized by url and (if present) User Agent and User Agent Password fields. """
        session = librets.RetsSession(self.MLS_LOGIN_URL)
        if self.RETS_USER_AGENT:
            session.SetUserAgent(self.RETS_USER_AGENT)
        if self.RETS_USER_AGENT_PASSWORD:
            session.SetUserAgent(self.RETS_USER_AGENT_PASSWORD)
        return session

    @tornado.gen.coroutine
    def check_mls_credentials(self, username, password):
        """ Proxy method that checks if MLS credentials are valid. """
        try:
            session = self.get_rets_session()
            if (session.Login(username, password)):
                log.info('Successful Credentials Validation (%s)' % self.MLS_SHORT_NAME)
                session.Logout()
                return 200
            log.error('Invalid Credentials Validation (%s)' % self.MLS_SHORT_NAME)
            return 401
        except Exception as e:
            log.error('Exception: ' + e.message)

    @tornado.gen.coroutine
    def register_self(self):
        """ Method performs connector initialization in hub. """
        print("Inside register_self of %s" % self.MLS_SHORT_NAME)
        super().register_self()
        client = self.get_async_http_client()
        response = yield client.fetch(
            self.HUB_REGISTER_PROXY_URL,
            method=HTTP_METHOD_POST,
            body=tornado.escape.json_encode(self.CONNECTOR_REGISTER_DATA),
            headers=auth_headers_request(self.auth_public, self.auth_secret))
        return response

    @tornado.gen.coroutine
    def listings_updated(self, trigger):
        """
        @description: Method which gets the data about trigger and launches him for processing.
        :param trigger: Parsed request body.
        :return: Response to hub.
        """

        trigger_info_json = json_encode({'url': self.MLS_LOGIN_URL, 'trigger': trigger})
        log.debug("Request to take listings from %s:  %s" %
            (self.MLS_SHORT_NAME, trigger_info_json)
        )

        request = HTTPRequest(self.MLS_LOGIN_URL)
        try:
            cipher = self.get_async_user_cipher(trigger['user_id'],
                                            self.AWS_USERS_KEYS_DIR,
                                            self.AWS_ACCESS_KEY_ID,
                                            self.AWS_SECRET_ACCESS_KEY,
                                            self.AWS_BUCKET_NAME)
            if self.USE_CIPHER_AND_LOGS:
                yield cipher.init_cipher()
            data = yield tornado.gen.Task(self.get_listings, trigger, cipher)
        except httpclient.HTTPError as e:
            log.error("""HTTPError error (request to take entities from %s):
                error=%s, trigger=%s""" %
                (self.MLS_SHORT_NAME, str(e), trigger_info_json)
            )
            response_to_hub = HTTPResponse(request, code=e.code, reason=str(e))
        except librets.RetsException as e:
            log.error("librets.RetsException was thrown.")
            log.error(e.GetFullReport())
            response_to_hub = HTTPResponse(request, code=e.code, reason=str(e))
        except Exception as e:
            log.error(
                """Exception (request to take entities from %s):
                error=%s, trigger=%s""" % (self.MLS_SHORT_NAME, str(e), trigger_info_json))
            response_to_hub = HTTPResponse(request, code=500, reason=str(e))
        else:
            log.info('Response success from %s: %s' %
                (self.MLS_SHORT_NAME, json_encode({'Login url': self.MLS_LOGIN_URL, 'trigger name': trigger, 'data count': len(data)}))
            )
            log.info('Begin processing listings from trigger: %s'
                     % json_encode({'trigger': trigger, 'data_count': len(data)}))

            entities = yield self.process_listings_updated_results(data, trigger)

            log.info('End processing listings from trigger: %s'
                     % json_encode({'trigger': trigger, 'return_data_count': len(entities)}))
            response_to_hub = HTTPResponse(request, code=200, buffer=self._get_buffer(entities))
        return response_to_hub

    def get_start_date_for_query(self, trigger):
        """ Default retrieving of start date for search condition in RETS API call. """
        last_start_date = trigger.get('last_start_date')
        start_date = date.today() - timedelta(days=2)

        if trigger.get('conditions'):
            condition_date = trigger.get('conditions').get('start_date')
            if condition_date:
                condition_start_date = datetime.strptime(condition_date, '%m/%d/%Y').date()
                if condition_start_date <= date.today():
                    start_date = condition_start_date
        if last_start_date:
            last_start_date = datetime.strptime(last_start_date, "%Y-%m-%dT%H:%M:%S.%fZ").date()
            start_date = last_start_date - timedelta(days=2)
        return start_date

    def get_search_query(self, trigger, cipher):
        start_date = self.get_start_date_for_query(trigger)
        return self.RETS_DEFAULT_SEARCH_QUERY % (start_date.isoformat())

    def get_rets_credentials(self, trigger, cipher):
        if self.USE_CIPHER_AND_LOGS:
            username = cipher.decrypt(trigger['user'])
            password = cipher.decrypt(trigger['password'])
        else:
            username = trigger['user']
            password = trigger['password']
        return {
            'username': username,
            'password': password
        }

    def get_processed_listing_ids(self, trigger_id):
        processed_listing_ids = []
        if (self.MONGO_STORE_LISTING_IDS):
            client = MongoClient(self.MONGODB_URL)
            db = client[self.MONGODB_DB_NAME]
            document = db[self.MONGODB_COLLECTION_NAME].find_one({'trigger_id': trigger_id})
            if (document != None):
                processed_listing_ids = document.get('processed_listing_ids', [])
            client.close()
        return processed_listing_ids

    def replace_processed_listing_ids(self, trigger_id, new_processed_listing_ids):
        if (self.MONGO_STORE_LISTING_IDS):
            client = MongoClient(self.MONGODB_URL)
            db = client[self.MONGODB_DB_NAME]
            document = db[self.MONGODB_COLLECTION_NAME].find_one({'trigger_id': trigger_id})
            if (document != None):
                db[self.MONGODB_COLLECTION_NAME].update_one(
                    {'trigger_id': trigger_id},
                    {
                        '$set': {'processed_listing_ids':new_processed_listing_ids}
                    })
            else:
                db[self.MONGODB_COLLECTION_NAME].insert_one({
                    'trigger_id': trigger_id,
                    'processed_listing_ids': new_processed_listing_ids
                })
            client.close()

    def get_listings(self, trigger, cipher, callback):
        rets_credentials = self.get_rets_credentials(trigger, cipher)
        search_query = self.get_search_query(trigger, cipher)

        session = self.get_rets_session()
        if (not session.Login(rets_credentials['username'], rets_credentials['password'])):
            log.error('Invalid Login to %s' % self.MLS_SHORT_NAME)
            return callback([])
        processed_listing_ids = self.get_processed_listing_ids(trigger['trigger_id'])
        data = []
        rets_classes = self.RETS_SELECT_QUERIES.keys()
        for rets_class in rets_classes :
            request = session.CreateSearchRequest("Property", rets_class, search_query)
            request.SetSelect(self.RETS_SELECT_QUERIES[rets_class])
            request.SetLimit(self.RETS_DEFAULT_LIMIT)
            request.SetOffset(librets.SearchRequest.OFFSET_NONE)
            request.SetFormatType(librets.SearchRequest.COMPACT_DECODED)
            results = session.Search(request)
            columns = results.GetColumns()
            while results.HasNext():
                listing_data = {}
                if rets_class in self.RETS_CLASSES_DEFAULT_VALUES:
                    listing_data = self.RETS_CLASSES_DEFAULT_VALUES.get(rets_class).copy()
                if self.is_skip_rets_result(results, trigger, cipher, processed_listing_ids):
                    continue
                for column in columns:
                    listing_data.update({column:results.GetString(column)})
                processed_listing_ids.append(listing_data[self.RETS_LISTING_ID_FIELD])
                data.append(listing_data)
        session.Logout()
        self.replace_processed_listing_ids(trigger['trigger_id'], processed_listing_ids)
        return callback(data)

    def is_skip_rets_result(self, result, trigger, cipher, processed_listing_ids):
        return (result.GetString(self.RETS_LISTING_ID_FIELD) in processed_listing_ids)

    def process_listing(self, listing):
        """
        @description: Corrects the data of a listing.
        :param listing: dictionary with listing data.
        """
        for key, value in listing.items():
            if value is None:
                listing[key] = ''
            elif (key in self.RETS_DATE_FIELDS) and (value != ''):
                listing[key] = int(parser.parse(value).replace(hour=12, minute=30).timestamp()) * 1000
        for key, value_pairs in self.RETS_VALUE_OVERRIDES.items():
            if (key in listing) and (listing[key] in value_pairs):
                listing.update({key: value_pairs[listing[key]]})
        for key, value in self.RETS_KEY_OVERRIDES.items():
            if (key in listing):
                listing.update({value: listing.get(key)})

    def listing_address (self, listing):
        """
        :param listing: Dictionary of listing data.
        :return: A listing address created from available values of fields from self.RETS_ADDRESS_FIELDS
        """
        address = []
        for field in self.RETS_ADDRESS_FIELDS:
            if listing.get(field):
                address.append(listing.get(field))
        return " ".join(address)

    def create_property_address(self, listing):
         """
             Create property address from listing, format "$address, $city, $state $zip"
         :param data: listing
         :return: property_address
         """
         property_address = '{address}, {city}, {state} {zip}'.format(address=self.listing_address(listing),
                                                                      city=listing[self.RETS_CITY_FIELD],
                                                                      state=listing[self.RETS_STATE_FIELD],
                                                                      zip=listing[self.RETS_ZIP_FIELD])
         return property_address

    @tornado.gen.coroutine
    def process_listings_updated_results(self, data, trigger):
        """
        @description: Method that handles the listings and sends them to the hub.
        :param data: dictionary of listing values.
        :param trigger:
        :return: The data have been sent to the hub.
        """
        for listing in data:
            self.process_listing(listing)
            property_address = self.create_property_address(listing)
            message = 'Listing retrieved (ID: {id}, Address: {address})'.format(
                id=listing[self.RETS_LISTING_ID_FIELD],
                address=property_address
            )
            if self.USE_CIPHER_AND_LOGS:
                uid = yield self.send_log(trigger_id=trigger['trigger_id'], message=message, status=LOG_STATUS_PROCESSED)
                listing['uid'] = uid
        return data

    @tornado.gen.coroutine
    def send_log(self, *args, **kwargs):
        """
        Create or Update workflow logs
        :param args:
        :param kwargs:  trigger_id, message, status, http_method, main_log_id, body (body - cipher data)
        :return id new log:
        """
        method = kwargs.pop('method', None)
        if not method:
            method = HTTP_METHOD_POST
            kwargs['date'] = datetime.utcnow().isoformat()
        try:
            response_log = yield self.get_async_http_client().fetch(
                self.HUB_LOGS_URL,
                method=method,
                body=json_encode(kwargs),
                headers=auth_headers_request(self.auth_public, self.auth_secret),
                connect_timeout=float('inf'), request_timeout=float('inf'))

            log_id = response_log.body.decode()
        except Exception as e:
            # Fake log_id
            log.error("Exception caught during  sending log. Applying fake log id.\n" + str(e))
            log_id = "507f191e810c19729de860ea"
        return log_id

    def strip_comma_separated_string_values(self, comma_separated_string):
        offices_id = [x.strip() for x in comma_separated_string.split(',') if x.strip()]
        return ",".join(offices_id)

    def _get_buffer(self, data):
        buffer = BytesIO(json_encode(data).encode())
        return buffer