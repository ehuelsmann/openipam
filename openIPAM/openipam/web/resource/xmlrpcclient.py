import os
import base64
import xmlrpclib
import urllib2
import cookielib
import httplib

import pickle

from tempfile import mkstemp
from openipam.utilities import error

class PickleCookieJar( cookielib.CookieJar ):
	def __init__( self, *args ):
		self._initargs = args
		cookielib.CookieJar.__init__(self, *args)
		
	def __getinitargs__( self ):
		return self._initargs

        def __getstate__( self ):
		cookie_list = []
		for cookie in self:
			cookie_list.append( pickle.dumps( cookie ) )
		return cookie_list

        def __setstate__( self, cookie_list ):
                for cookie_str in cookie_list:
			self.set_cookie( pickle.loads( cookie_str ) )

class ResponseWrapper():
	_response = None

	def __init__(self, response):
		self._response = response

	def info(self):
		return self

	def getheaders(self, name):
		return [item for item in self._response.getheaders()
			if item[0] == name]


class CookieAuthXMLRPCSafeTransport(xmlrpclib.Transport):
	"""xmlrpclib.Transport that sends HTTP(S) Authentication"""

	cj = None
	ssl = True
	_extra_headers = None
	_host = None
	
	def __init__(self, cookiejar=None, ssl=True, use_datetime=True):
		xmlrpclib.Transport.__init__(self, use_datetime=use_datetime)
		if not ssl:
			self.ssl = False

		if cookiejar:
			self.cj = cookiejar
		else:
			self.cj = PickleCookieJar()

	def get_cookiejar(self):
		return self.cj

	def send_cookie_auth(self, connection):
		"""Include Cookie Authentication data in a header"""
		for cookie in self.cj:
			if cookie.name == 'session_id':
				uuidstr = cookie.value
			connection.putheader("Cookie",cookie.name+'='+cookie.value)

	def send_host(self, connection, host):
		self.send_cookie_auth(connection)
		self._host = host

		return xmlrpclib.Transport.send_host(self, connection, host)

	def parse_response(self, response):
		if self.ssl:
			req = urllib2.Request('https://%s/' % self._host)
		else:
			req = urllib2.Request('http://%s/' % self._host)

		self.cj.extract_cookies(ResponseWrapper(response), req)
		
		return xmlrpclib.Transport.parse_response(self, response)


