'''
The main openIPAM database interface. This is where the magic happens.

CODING STANDARDS FOR DATABASE LAYER:
- Follow openIPAM coding conventions: see http://code.google.com/p/openipam/wiki/CodingConventions
- Always use full arguments for all functions and never use **kw because things should intentionally
break if the webservice layer or DHCP server is not invoking methods correctly.
Example:
	def get_dhcp_group_options(self, gid=None, rid=None):
		...

- Use SQLAlchemy query building conventions (don't do it all at once, build the query).
- Use SQLAlchemy Expression Language fully, never use hybrid or full text queries.
- We do not use any part of SQLAlchemy's Object Relational Mapper (ORM)
- Never use a list or a dictionary as a default argument. See http://code.google.com/p/openipam/wiki/CodingConventions#Functions

'''

import random
random.seed()

import types
import string
import time
import datetime

import sqlalchemy
import obj
import openipam.iptypes
import re
import thread
import binascii

from openipam.utilities import error
from openipam.utilities import validation
from openipam.utilities.perms import Perms
from openipam.config import backend

from sqlalchemy.sql import select, and_, or_, not_, join, outerjoin, subquery, text, union, column

import openipam.utilities.perms

from openipam.utilities.function_wrapper import fcn_wrapper

my_conn = obj.engine.connect()
query= select([obj.permissions.c.id,obj.permissions.c.name])
try:
	result = my_conn.execute(query).fetchall()
	my_conn.close()
except:
	my_conn.close()
	raise
perms = openipam.utilities.perms.PermsList( result )
del result
del my_conn
del query

# Make sure that the installed version of SQLAlchemy is up-to-date

SQLALCHEMY_MAJOR = 0
SQLALCHEMY_MINOR = 4
SQLALCHEMY_PATCH = 5

(minor, patch) = sqlalchemy.__version__.split('.')[1:]

if minor < SQLALCHEMY_MINOR:
	raise error.LibraryError("SQLAlchemy version %s.%s.%s or above is required" % (SQLALCHEMY_MAJOR, SQLALCHEMY_MINOR, SQLALCHEMY_PATCH))
if patch < SQLALCHEMY_PATCH and minor < SQLALCHEMY_MINOR:
	raise error.LibraryError("SQLAlchemy version %s.%s.%s or above is required"  % (SQLALCHEMY_MAJOR, SQLALCHEMY_MINOR, SQLALCHEMY_PATCH))

addresses_re = re.compile('[0-9., ]+')
def is_addresses(val):
	return bool( addresses_re.match(val) )

class DBBaseInterface(object):
	'''
	The base database interface components
	
	The base interface only does SELECTs (getters), all setters (INSERTs, UPDATEs, DELETEs)
	happen in the DBInterface class.
	'''
	def __init__( self ):
		pass

	def __del__( self ):
		self._rollback()
	
	def has_min_perms( self, permission ):
		return permission & self._min_perms == permission

	def require_perms( self, permission, error_str=None ):
		if not error_str:
			error_str = "Insufficient Permissions (have: %s, need: %s)" % (self._min_perms,permission)
		if permission & self._min_perms != permission:
			raise error.InsufficientPermissions( error_str )

	def _create_conn( self ):
		return obj.engine.connect()

	def _begin_transaction( self ):
		"""
		Create a transactional connection and begin the transaction
		"""

		# FIXME: this is not thread-safe
		
		# If we already have a connection, don't create another one
		# This should make nested transactions work properly
		# See: http://www.sqlalchemy.org/docs/05/dbengine.html#dbengine_transactions
		if not hasattr(self, '_conn'):
			# Initial creation of connection and transaction stack
			self._conn = self._create_conn()
			self._trans_stack = [self._conn.begin(),]
		else:
			# We already have a connection, so we're already in a transaction
			# Add the next transaction object to the transaction stack
			self._trans_stack.append(self._conn.begin())
		
	def _commit( self ):
		"""
		Commits the current connection and closes the connection to return it to the pool.
		"""
		
		# Pop the transaction object from the stack and commit it
		self._trans_stack.pop().commit()
		
		if not self._trans_stack:
			# We've committed the root transaction object, we're done! 
			self._conn.close()
		
			del self._conn
			del self._trans_stack
	
	def _rollback( self ):
		"""
		Rollback the transactional connection.
		"""

		# Make sure that the objects exist on self before rolling back.
		# This is done for nested transactions where an inner transaction may
		# call this function and already kill the objects, but the outer transaction
		# will then also call this function
		if hasattr(self, '_trans_stack'):
			for trans in self._trans_stack:
				trans.rollback()
			del self._trans_stack
		
		if hasattr(self, '_conn'):
			self._conn.close()
			del self._conn
	
	def __getattr__(self, name):
		"""
		On missing method
		"""
		if name[:4] == 'get_':
			obj = getattr( self, '_%s' % name )
			return fcn_wrapper(obj=self, fcn=self._execute_get, kwargs={'execute_get_function':obj,}, name=name)
		raise AttributeError(name)
		
	def _execute_get( self, execute_get_function, *args, **kw ):
		"""
		Called by __getattr__, unconditionally executes self.function (set in __getattr__)
		with the given arguments and executes the query.
		
		@return: result of query
		"""
		
		function = execute_get_function

		page = None
		if kw.has_key('page'):
			page = kw['page']
			del kw['page']
		
		limit = None
		if kw.has_key('limit'):
			limit = kw['limit']
			del kw['limit']
			
		order_by = None
		if kw.has_key('order_by'):
			order_by = kw['order_by']
			del kw['order_by']

		columns = None
		if kw.has_key('columns'):
			columns = kw['columns']
			del kw['columns']

		distinct = False
		if kw.has_key('distinct'):
			distinct = kw['distinct']
			del kw['distinct']
		
		count = False
		if kw.has_key('count'):
			count = kw['count']
			del kw['count']
		
		query = function( *args, **kw )

		# Apply given ORDER BY, OFFSET and LIMIT statements
		if distinct:
			query = query.distinct()

		if columns:
			query = query.with_only_columns(columns)
		
		if order_by:
			query = query.order_by(order_by)

		if count:
			# FIXME: this is a bit inefficient... but I can't figure out another way that will handle DISTINCT and other complex queries
			count = select(columns=[sqlalchemy.sql.func.count('*').label('count'),], from_obj=query.alias('countfoo'))

			count = self._execute( count )
			if count:
				count = count[0]['count']
			else:
				count=0

		if page and limit:
			query = self.__do_page( query=query, page=page, limit=limit)
		elif limit:
			query = query.limit(limit)

		data = self._execute( query )
		if count is not False:
			return count, data
		return data

	def _execute(self, query):
		if hasattr(self, '_conn') and hasattr(self, '_trans_stack'):
			# We're doing transactional stuff, probably because of DBInterface.
			# Use the transactional connection to keep a consistent view of the DB
			result = self._conn.execute(query).fetchall()
		else:
			# No connection exists, just call execute on the connection itself
			my_conn = self._create_conn()
			try:
				result = my_conn.execute(query).fetchall()
				my_conn.close()
			except:
				my_conn.close()
				raise
			
		return result
	
	def __do_page( self, query, page, limit ):
		"""
		Set the offset and limit on a query based on self.__limit and the specified
		page (zero-based index).
		@param query: An sqlalchemy selectable
		@param page: A zero-based index to the desired 'page'
		@param limit: An integer limit to the query
		@return: An sqlalchemy selectable with OFFSET and LIMIT set appropriately.
		"""
		if limit:
			return query.offset( int(page) * int(limit) ).limit(limit)
		else:
			return query
		
	def _is_user_in_group(self, gid):
		"""
		Check to see if the user is in a group to make sure they have permission
		"""
		
		if self.get_users( uid=self._uid, gid=gid ):
			return True
		return False
	
	def _require_perms_on_host(self, permission, mac, error_msg=None):
		"""
		Many functions need to simply make sure that the user has a certain access over a host
		This function does that.
		
		@raise: error.InsufficientPermission if they don't have perms over mac
		@return: None if they have permission 
		"""
		
		if not self.has_min_perms(permission):
			host_perms = obj.perm_query( self._uid, self._min_perms, hosts = True, required_perms = permission )
			net_perms = obj.perm_query( self._uid, self._min_perms, networks = True, required_perms = permission )
			dom_perms = obj.perm_query( self._uid, self._min_perms, domains = True, required_perms = permission )
			
			# Find all hosts where the user has access via networks_to_groups
			net_perms = net_perms.join(obj.addresses, and_(net_perms.c.nid == obj.addresses.c.network, obj.addresses.c.mac==mac))
			
			# Find all hosts where the user has access via hosts_to_groups
			host_perms = host_perms.join(obj.hosts, and_(host_perms.c.mac==obj.hosts.c.mac, obj.hosts.c.mac==mac))
			
			# Find all hosts where the user has access via networks_to_groups
			dom_perms = dom_perms.join(obj.domains, dom_perms.c.did == obj.domains.c.id).join(obj.hosts, and_( obj.hosts.c.hostname.like('%.' + obj.domains.c.name), obj.hosts.c.mac==mac))
			
			net_hosts = select([obj.addresses.c.mac], from_obj=net_perms)
			group_hosts = select([obj.hosts.c.mac], from_obj=host_perms)
			dom_hosts = select([obj.hosts.c.mac], from_obj=dom_perms)
			
			# Execute the queries -- FIXME - do a union
			net_hosts = self._execute(net_hosts)
			group_hosts = self._execute(group_hosts)
			dom_hosts = self._execute(dom_hosts)
			
			# If anything exists, we allow this to continue because the user has permissions
			# over that host either via a host group or a network
			# If empty, raise exception
			if not group_hosts and not net_hosts and not dom_hosts:
				raise error.InsufficientPermissions(error_msg)

	def _require_perms_on_address(self, permission, address, error_msg=None):
		if not self.has_min_perms(permission):
			addr_record = self.get_addresses(address = address)
			if len(addr_record) > 1:
				raise error.InvalidArgument('\'address\' argument should only match a single address: %s' % address)
			if addr_record:
				addr_record = addr_record[0]
			else:
				addr_record = None

			andwhere = obj.networks.c.network.op('<<')(address)

			net_perms = obj.perm_query( self._uid, self._min_perms, networks = True, required_perms = permission, do_subquery=False, andwhere=andwhere )
			net_perms = self._execute(net_perms)

			if net_perms:
				return

			if not addr_record or not addr_record['mac']:
				if not error_msg:
					error_msg = "need %s or greater on network containing %s" % (perms,address)
				raise error.InsufficientPermissions(error_msg)


			addr_where = obj.hosts.c.mac == addr_record['mac']
			host_perms = obj.perm_query( self._uid, self._min_perms, hosts = True, required_perms = permission, do_subquery=False, andwhere=addr_where )
			host_perms = self._execute(host_perms)
			
			if host_perms is None or len(host_perms) == 0:
				if not error_msg:
					error_msg = "need %s or greater network containing %s or host with mac %s" % (perms,address,addr_record['mac'])
				raise error.InsufficientPermissions(error_msg)
			return

	def _require_perms_on_net(self, permission, network=None, address=None, error_msg=None):
		if not self.has_min_perms(permission):
			if (not network and not address) or (network and address):
				raise error.InvalidArgument('Requires exactly one of network, address: network = %s, address = %s' % (network,address))
			if network:
				andwhere = obj.networks_to_groups.c.nid == network
			else:
				andwhere = obj.networks_to_groups.c.nid.op('>>')(address)
			net_perms = obj.perm_query( self._uid, self._min_perms, networks = True, required_perms = permission, do_subquery=False, andwhere=andwhere )
			net_perms = self._execute(net_perms)
		
			if not net_perms:
				if not error_msg:
					error_msg = "need %s or greater on network %s or network containing %s" % (perms,network,address)
				raise error.InsufficientPermissions(error_msg)

			
	def find_owners_of_host(self, mac, get_users=False):
		"""
		Find groups or users who have OWNER over this host
		where their permissions over a group that contains that host is OWNER
		
		@param get_users: whether to go further than group names and get usernames
		@return: either groups owners or, if get_users=True, usernames
		"""
		
		self.require_perms(perms.READ)
		
		# Groups --> Hosts to Groups
		fromobject = obj.groups.join(obj.hosts_to_groups, and_(obj.hosts_to_groups.c.gid == obj.groups.c.id, obj.hosts_to_groups.c.mac == mac))
		
		# Make sure to OR users_to_groups.host_permissions after finding the user's group permissions
		# Hosts to Groups --> Users to Groups
		fromobject = fromobject.outerjoin(obj.users_to_groups, obj.users_to_groups.c.gid == obj.hosts_to_groups.c.gid )
		whereobject = obj.users_to_groups.c.permissions.op('|')(obj.users_to_groups.c.host_permissions).op('&')(str(perms.OWNER)) == str(perms.OWNER)
		# Handle groups with no owners :/
		whereobject = or_(whereobject, obj.users_to_groups.c.id == None)
		
		if get_users:
			# Users to Groups --> Users
			fromobject = fromobject.join(obj.users, obj.users.c.id == obj.users_to_groups.c.uid)
			query = select([obj.users], whereobject, from_obj=fromobject, distinct=True)
		else:
			query = select([obj.groups], whereobject, from_obj=fromobject, distinct=True)
		
		return self._execute(query)
	
	def find_mac_from_lease(self, ip):
		"""
		Get a MAC address back from an IP address lease
		
		@param ip: if specified, return the lease associated with this IP addresses
		@return: mac address or None
		"""
		
		self.require_perms(perms.READ)
		
		query = select([obj.leases.c.mac], obj.leases.c.address==ip)
		
		# This is a special function, not a _get so we have to execute on our own
		return self._execute(query)
	
	def find_expiring_hosts(self):
		"""
		Returns all of the hosts that will be expiring from now up until interval
		"""
		
		self.require_perms(perms.DEITY)
		
		from_object = obj.hosts.join(obj.notifications_to_hosts, obj.notifications_to_hosts.c.mac==obj.hosts.c.mac)
		from_object = from_object.join(obj.notifications, obj.notifications.c.id==obj.notifications_to_hosts.c.nid)
		from_object = from_object.join(obj.hosts_to_groups, obj.hosts_to_groups.c.mac==obj.notifications_to_hosts.c.mac)
		from_object = from_object.join(obj.users_to_groups, obj.users_to_groups.c.gid==obj.hosts_to_groups.c.gid)
		from_object = from_object.join(obj.users, obj.users_to_groups.c.uid==obj.users.c.id)
		from_object = from_object.outerjoin(obj.addresses, obj.hosts.c.mac==obj.addresses.c.mac)
		
		columns = [ obj.hosts.c.mac, obj.hosts.c.hostname, obj.hosts.c.expires, obj.hosts.c.description,
				obj.notifications_to_hosts.c.id.label('nid'), obj.notifications.c.notification,
				obj.users.c.username, (obj.addresses.c.address != None).label('is_static'),
				#(sqlalchemy.sql.func.cast(obj.hosts.c.expires,'DATE') - sqlalchemy.sql.func.cast(sqlalchemy.sql.func.now(),'DATE')).label('days'),
				text('hosts.expires::DATE - NOW()::date AS days'),
				]
		query = select(columns, from_obj=from_object).distinct()
		
		# Don't add this to the join above, things get funky
		query = query.where((obj.hosts.c.expires - obj.notifications.c.notification) <= sqlalchemy.sql.func.now())
		
		return self._execute(query)
	
	def _finalize_whereclause(self, whereclause):
		"""
		Accepts an iterable of criterion and creates a SQLAlchemy-ready whereclause
		
		@param whereclause: a list of criterion that will be AND'd together
		"""
		
		if len(whereclause) == 1:
			# We only have one whereclause clause, don't AND anything
			final_whereclause = whereclause[0]
		elif len(whereclause) > 1:
			# More than one whereclause, AND them all together
			final_whereclause = and_(whereclause.pop(), whereclause.pop()) 
			while whereclause:
				final_whereclause = and_(final_whereclause, whereclause.pop())
		else:
			raise error.RequiredArgument("_finalize_whereclause needs a list of criterion")
				
		return final_whereclause
	
	def _get_attributes( self, aid=None, name=None, ):
		"""Get possible host attributes
		"""
		query = select( [obj.attributes] )
		if aid:
			query=query.where(obj.attributes.c.id == aid)
		if name:
			query=query.where(obj.attributes.c.name == name)

		return query
		
	def _get_attributes_to_hosts( self, aid=None, mac=None ):
		a2h = obj.attributes_to_hosts
		if not self.has_min_perms( perms.READ ):
			if not mac:
				raise error.InsufficientPermissions("Must have global read perms to look up all attributes: aid=%s mac=%s" % (aid,mac))
			self._require_perms_on_host(permission=perms.READ, mac=mac)

		query = select([a2h],)
		if aid:
			query = query.where(a2h.c.id == aid)
		if mac:
			query = query.where(a2h.c.mac == mac)

		return query

	def _get_structured_attribute_values( self, avid=None, aid=None ):
		"""Get possible values for structured attributes"""
		sav = obj.structured_attribute_values
		if avid is None and aid is None:
			raise error.RequiredArgument("Must specify either avid or aid")
		query = select([sav])
		if avid:
			query = query.where(sav.c.id == avid)
		if aid:
			query = query.where(sav.c.aid == aid)

		return query

	def _get_addresses(self, address=None, network=None, mac=None, pool=None):
		"""
		Return rows from the addresses table
		
		@param address: an IP address
		@param mac: a MAC address
		@param pool: a pool ID
		@return: rows from the addresses table, filtered by the above parameters
		"""
		
		self.require_perms(perms.READ)
		
		if not address and not mac and not pool and not network:
			self.require_perms(perms.OWNER)
		
		fromobject = obj.addresses.join(obj.networks, obj.networks.c.network == obj.addresses.c.network)
		

		query = select( [obj.addresses, sqlalchemy.sql.func.netmask(obj.addresses.c.network).label('netmask'), obj.networks.c.gateway], from_obj=fromobject )
		
		if address:
			query = query.where(obj.addresses.c.address == address)
		if mac:
			query = query.where(obj.addresses.c.mac == mac)
		if pool:
			query = query.where(obj.addresses.c.pool == pool)
		if network:
			query = query.where(obj.addresses.c.address.op('<<')(network))
			
		return query
		
	
	def _get_auth_sources( self, name=None ):
		"""auth_source"""
		self.require_perms( perms.DEITY )
		query = select([obj.auth_sources,])
		if name:
			query = query.where(obj.auth_sources.c.name == name)
		return query
	
	def _get_dhcp_options( self, gid=None, id=None, option=None ):
		"""
		Get valid DHCP option types
		
		@param gid: if specified, return option types related to this group id
		"""
		
		# Check permissions
		self.require_perms(perms.DEITY)
		
		fromobject = obj.dhcp_options
		
		if gid:
			fromobject = fromobject.join(obj.dhcp_groups.c.id == gid)

		query = select([obj.dhcp_options], from_obj=fromobject)
		
		if id:
			query = query.where( obj.dhcp_options.c.id == id )

		if option:
			query = query.where( obj.dhcp_options.c.option == option )

		return query
		
	
	def _get_dhcp_group_options(self, gid=None, rid=None):
		"""
		Get all (or filtered) DHCPOptionToGroup relations
		"""
		pass
	
	def _get_dhcp_groups( self, id=None, name=None ):
		"""
		Get DHCP groups, optionally filtered
		@param id: a DHCP group ID, if only one needs to be returned
		"""
		query = select([obj.dhcp_groups])
		
		if id:
			query = query.where(obj.dhcp_groups.c.id == id)
		if name:
			query = query.where(obj.dhcp_groups.c.name == name)

		return query
	
	def _get_dns_records( self, tid=None, typename=None, id=None, name=None, content=None, mac=None, changed=None, address=None, did=None, columns=None, vid=False ):
		"""
		Get DNS Records
		
		@param tid: a database DNS record type ID
		@param name: the name of this DNS record for filtering
		@param content: the content field
		@param mac: filter on a mac address
		@param changed: if given, will return the DNS records changed after this datetime.
		@param address: return the A or AAAA record for this IP address
		
		@return: filtered DNS records
		"""
		# A: A record -> IP -> mac
		# CNAME: content=A record name -> IP -> mac,
		# MX: name = A record -> ip -> mac
		# SRV: content = '% <A record name>' -> IP -> mac
		# PTR: name = A record ip_content reverse
		
		self.require_perms( perms.READ )
		if not columns:
			columns = [obj.dns_records, obj.dns_types.c.name.label('type'), sqlalchemy.sql.func.coalesce(obj.dns_records.c.text_content,sqlalchemy.sql.expression.cast(obj.dns_records.c.ip_content, sqlalchemy.types.VARCHAR)).label('content')]
		
		whereclause = []
		
		if id:
			if type(id) is types.IntType or type(id) is types.StringType:
				whereclause.append( obj.dns_records.c.id == id )
			elif type(id) is types.TupleType or type(id) is types.ListType:
				whereclause.append( obj.dns_records.c.id.in_(id) )
			else:
				raise Exception("Invalid type for id: %s" % type(id))
		if address:
			if type(address) == types.ListType:
				whereclause.append( obj.dns_records.c.ip_content.in_( address ) )
			else:
				whereclause.append( obj.dns_records.c.ip_content == address )
		if tid:
			if type(tid) == types.ListType:
				whereclause.append( obj.dns_records.c.tid.in_( tid ) )
			else:
				whereclause.append( obj.dns_records.c.tid == tid )
		elif typename:
			whereclause.append( obj.dns_records.c.tid == self.get_dns_types(typename=typename)[0]['id'] )
		if name:
			if type(name) == types.ListType:
				whereclause.append( obj.dns_records.c.name.in_( name ) )
			else:
				name = name.lower()
				if '%' in name:
					# Use a LIKE condition
					whereclause.append( obj.dns_records.c.name.like( name ) )
				else:
					# name = 'exact string'
					whereclause.append( obj.dns_records.c.name == name )
		if vid is not False:
			whereclause.append( obj.dns_records.c.vid == vid )
				
				
		if content:
			# FIXME: is there a better way to do this?
			if type(content) == types.ListType:
				if validation.is_ip(content[0]): 
					raise error.InvalidArgument('Addresses are not valid in the \'content\' field (searching for %s)' % content)
				else:
					whereclause.append( obj.dns_records.c.text_content.in_( content ) )
				
			else:
				if validation.is_ip(content): 
					raise error.InvalidArgument('Addresses are not valid in the \'content\' field (searching for %s)' % content)
				else:
					if '%' in content:
						# Use a LIKE condition
						whereclause.append( obj.dns_records.c.text_content.like( content ) )
					else:
						# content = 'exact string' OR content like '% exact string'
						whereclause.append( or_(obj.dns_records.c.text_content == content, obj.dns_records.c.text_content.like( '%% %s' % content )  ) )

		if did is not None:
			whereclause.append( obj.dns_records.c.did == int(did) )

		if changed:
			whereclause.append( obj.dns_records.c.changed >= changed )
		
		if whereclause:
			whereclause = self._finalize_whereclause( whereclause )
		else:
			whereclause = True

		if mac:
			host = self.get_hosts( mac = mac )[0]
			addresses = [ i['address'] for i in self.get_addresses( mac = mac ) ]

			union_foo = []

			if addresses:
				a_records = self._get_dns_records( address = addresses, columns=columns ).distinct()
				union_foo.append(a_records.where(whereclause))

				ptr_names = [ openipam.iptypes.IP(i).reverseName()[:-1] for i in addresses ]
				if ptr_names:
					ptrs = self._get_dns_records( name=ptr_names, columns=columns ).distinct()
					union_foo.append(ptrs.where(whereclause))

				a_record_names = [ i['name'] for i in self._execute(self._get_dns_records(address=addresses).with_only_columns([obj.dns_records.c.name,]) ) ]
				if a_record_names:
					other_records = self._get_dns_records( content = a_record_names, columns=columns ).distinct()
					union_foo.append(other_records.where(whereclause))
					other_records = self._get_dns_records( name = a_record_names, columns=columns ).distinct()
					union_foo.append(other_records.where(whereclause))

			if len(union_foo) > 2:
				query = union( *union_foo )
			elif union_foo:
				query = union_foo[0]
			else:
				query = select( columns, from_obj = obj.dns_records ).where(False)

		else:
			from_object = obj.dns_records.join(obj.dns_types, obj.dns_records.c.tid == obj.dns_types.c.id )
			query = select( columns, from_obj = from_object )

			if whereclause is not True:
				query = query.where( whereclause )
			else:
				raise error.InvalidArgument("You're trying to retrieve all DNS records ... why?")

		return query
	
	def _get_dns_types( self, typename=None, only_useable=False ):
		"""
		Returns all DNS resource record types
		"""
		
		query = select([obj.dns_types])
		
		if only_useable:
			query = query.where( and_(not_(obj.dns_types.c.min_permissions == '00000000'), obj.dns_types.c.min_permissions.op('&')(str(self._min_perms)) == obj.dns_types.c.min_permissions))
		if typename:
			query = query.where( obj.dns_types.c.name == typename.upper() )

		return query

	def _get_dns_views( self ):
		"""Return a list of all DNS views"""
		pass
	
	def _get_domains( self, did=None, name=None, contains=None, gid=None, additional_perms='00000000', columns=None, show_reverse=True ):
		"""
		Return a filtered list of domains
		Search through domains by passing a percent sign (%) in the name param
		
		@param did: return only one domain of this ID
		@param name: return only one domain of this name
		@param gid: return only the domains in this group ID
		@param contains: return the most specific domain containing this name
		@param additional_perms: require these additional permissions also
		@param show_reverse: whether or not to show reverse lookup (in-addr.arpa) domains 
		"""
		# require read permissions over associated domains
		required_perms = perms.READ
			
		if additional_perms:
			required_perms = required_perms | additional_perms
			
		# Permissions may be a little bit screwy...again
		if self.has_min_perms(required_perms): 
			query = obj.domains
			if gid:
				query = query.join(obj.domains_to_groups, and_(obj.domains.c.id == obj.domains_to_groups.c.did, obj.domains_to_groups.c.gid==gid))
		else:
			domain_perms = obj.perm_query( self._uid, self._min_perms, domains = True, gid=gid, required_perms = required_perms )
			query = domain_perms.join(obj.domains, obj.domains.c.id == domain_perms.c.did )

		if not columns:
			columns = [obj.domains]
		
		query = select(columns, from_obj=query )
		
		if did:
			query = query.where(obj.domains.c.id == did)
		if name:
			if '%' in name:
				query = query.where(obj.domains.c.name.like(name))
			else:
				query = query.where(obj.domains.c.name==name)
		if contains:
			domains = []
			
			if type(contains) is types.ListType or type(contains) is types.TupleType:
				# We have been given a list of names (whether hostnames or domain names),
				# return a list of only the first-level containing domains for every name.
				# ie ... this does NOT do the normal functionality of returning all containing
				# domains, just the first-level for each

				for record in contains:
					# If record is "test.place.example.com", we will append "place.example.com" to the list of domains
					domains.append('.'.join( record.split('.')[1:] ))
					
				# If record is "example.com", we need to include that also because it could be a domain
				# So, just include all the original record names
				domains += contains
			else:
				# Find all of the containing domains for this single hostname
				names = contains.split('.')
				while names:
					domains.append('.'.join(names))
					del names[0]
					
			# Apply our search list to the query
			query = query.where(obj.domains.c.name.in_(domains))
		
			# Awesome...order by descending on the length of domain names.
			# Gives the most specific domains first, followed by the rest.
			query = query.order_by(sqlalchemy.sql.func.length(obj.domains.c.name).desc())
		if not show_reverse:
			query = query.where(not_(obj.domains.c.name.like('%.arpa')))
		
		return query
	
	def _get_expiration_types( self ):
		"""
		Return expiration types that this user can access
		"""
		
		query = select( [obj.expiration_types.c.id, obj.expiration_types.c.expiration], obj.expiration_types.c.min_permissions <= str(self._min_perms) )
		
		return query
	
	def _get_guest_tickets(self, ticket=None, uid=None):
		"""
		Get guest tickets
		
		@param ticket: get the information related to this ticket name
		@param uid: only get tickets tied to this user ID
		@return: rows from the guest_tickets table
		"""
		
		if (not ticket and not uid):
			raise error.RequiredArgument("Must specify at least one of name or uid to get guest tickets")
		
		query = select( [obj.guest_tickets, (and_(obj.guest_tickets.c.starts <= sqlalchemy.sql.func.now(),obj.guest_tickets.c.ends > sqlalchemy.sql.func.now())).label('valid')] )
		
		if ticket:
			query = query.where(obj.guest_tickets.c.ticket == ticket)
			
		if uid:
			if self._uid != uid and not self.has_min_perms(perms.DEITY):
				# I'm not a DEITY and I'm trying to get someone else's tickets
				raise error.InsufficientPermissions()
			
			query = query.where(obj.guest_tickets.c.uid == uid) 
			
		return query

	def _get_users_to_groups(self, uid=None, gid=None):
		# require read permissions over associated groups
		self.require_perms(perms.READ)

		query = select([obj.users_to_groups], from_obj=obj.users_to_groups)
		if uid:
			query = query.where(obj.users_to_groups.c.uid==int(uid))
		if gid:
			query = query.where(obj.users_to_groups.c.gid==int(gid))
			
		return query

	def _get_groups( self, gid=None, name=None, ignore_usergroups=False, uid=None, additional_perms=None):
		"""
		Return groups
		
		@param gid: return a single group of this database ID
		@param name: return groups matching this name
		@param ignore_usergroups: a boolean, if true no groups prepended with 'user_' will be returned
		@param uid: a user's database ID, returns a user's groups, optionally filtered by permissions in that group
		@param additional_perms: return groups where the users_to_groups.permissions meet these additional permission requirements
		"""
		
		# require read permissions over associated groups
		self.require_perms(perms.READ)
		
		if gid and name:
			raise error.RequiredArgument("Specify exactly one of gid or name")
		if (gid or name or ignore_usergroups) and (uid or additional_perms):
			raise error.RequiredArgument("If uid or additional_perms is specified, you cannot filter by gid, name, or use ignore_usergroups.")
		
		if uid:
			if additional_perms is None:
				additional_perms = '00000000'
				
			fromobj = obj.groups.join(obj.users_to_groups, and_(and_(obj.groups.c.id==obj.users_to_groups.c.gid, obj.users_to_groups.c.uid == uid), 
												obj.users_to_groups.c.permissions.op('|')(obj.users_to_groups.c.host_permissions).op('&')(str(additional_perms)) == str(additional_perms)))
		else:
			fromobj = obj.groups
		
		query = select( [obj.groups], from_obj=fromobj )
		
		if gid:
			query = query.where(obj.groups.c.id == gid)
		if name:
			if '%' in name:
				query = query.where( sqlalchemy.sql.func.lower(obj.groups.c.name).like(name.lower()) )
			else:
				query = query.where(sqlalchemy.sql.func.lower(obj.groups.c.name) == name.lower())
		if ignore_usergroups:
			query = query.where(not_(sqlalchemy.sql.func.lower(obj.groups.c.name).like('user_%')))
			
		return query
	
	def _get_hosts( self, mac=None, endmac=None, hostname=None, ip=None, network=None, uid=None, username=None, gid=None, groupname=None, descriptionsearch=None, columns=None, additional_perms=None, expiring=False, namesearch=None, show_expired=True, show_active=True, only_dynamics=False, only_statics=False, funky_ordering=False ):
		"""
		Get hosts and DNS records from the DB
		@param mac: return a list containing the host with this mac
		@param endmac: with mac, specify a range of MAC addresses
		@param hostname: hostname (allowing wildcards) on which to filter
		@param ip: return host associated (statically) with this IP
		@param network: network on which to filter
		@param username: a username on which to filter
		@param gid: return only the hosts in this group ID
		@param columns: list of columns to select. defaults to [obj.hosts]
		@param additional_perms: return hosts that meet these additional permission requirements
		@param expiring: show hosts that are expiring within this many days
		@param show_expired: default true, will show all hosts that have expired before now. If false, will only show non-expired hosts.
		@param show_active: default true, will show all hosts that are active now. If false, will not show non-expired hosts.
		@param only_dynamics: only return dynamic addresses 
		@param only_statics: only return statics addresses
		@param funky_ordering: if on, hosts are ordered by hostname length ... fixes problems with guest registrations
		"""

		# require read permissions over hosts
		required_perms = perms.READ
		
		if additional_perms != None:
			required_perms = required_perms | additional_perms
		
		# Extremely important to have this ... BAD bad things happen if hostnames are ever mixed-case
		if hostname != None:
			# Make sure the hostname is always lower case
			if type(hostname) is types.ListType or type(hostname) is types.TupleType:
				hostname = [name.lower() for name in hostname]
			else:
				hostname = hostname.lower()

		if endmac and not mac:
			raise error.RequiredArgument("Beginning of range not specified: mac: %s endmac: %s" % (mac,endmac))

		if endmac and only_statics:
			raise error.InvalidArgument("Specifying endmac and only_statics not supported")

		if (only_dynamics and only_statics):
			raise error.RequiredArgument("Cannot specify both only_dynamics and only_statics")
		
		if backend.enable_gul:
			gul_byaddr_fromclause = obj.addresses.join(obj.gul_recent_arp_byaddress, obj.gul_recent_arp_byaddress.c.address == obj.addresses.c.address)
			gul_addr_seen_column = sqlalchemy.sql.func.max(obj.gul_recent_arp_byaddress.c.stopstamp).label('address_seen')
			gul_byaddr_columns = [obj.addresses.c.mac, gul_addr_seen_column ]
			#query = subquery( 'label', columns, whereclause, from_obj = fromclause )
			gul_by_addr_subq = select( gul_byaddr_columns, from_obj = gul_byaddr_fromclause).group_by(obj.addresses.c.mac).alias('gul_byaddress_subq')

		if not columns:
			columns = [obj.hosts, (obj.hosts.c.expires < sqlalchemy.sql.func.now()).label('expired'), (obj.disabled.c.mac != None).label('disabled'),
					obj.dhcp_groups.c.name.label('dhcp_group_name'), obj.dhcp_groups.c.description.label('dhcp_group_description') ]
			if backend.enable_gul:
				columns.append( obj.gul_recent_arp_bymac.c.stopstamp.label('mac_seen') )
				columns.append( 'gul_byaddress_subq.address_seen' )

		if funky_ordering:
			columns.append(sqlalchemy.sql.func.length(obj.hosts.c.hostname).label('len'))
			
		# If username was passed in, get the uid
		if username:
			if uid:
				raise Exception("You cannot specify both username and uid.")
			user = self.get_users(username=username)
			if not user:
				raise error.NotUser("No user found named %s" % username)
			uid = user[0]['id']
			
		# If groupname was passed in, get the gid
		if groupname:
			if gid:
				raise Exception("You cannot specify both groupname and gid.")
			group = self.get_groups(name=groupname)
			if not group:
				raise error.NotUser("No group found named %s" % groupname)
			gid = group[0]['id']
			
		# Filter and make the whereclause
		
		whereclause = []
		
		# Apply all the filtering that was specified
		if ip != None:
			if type(ip) == types.ListType:
				whereclause.append( or_(obj.addresses.c.address.in_(ip), obj.leases.c.address.in_(ip)))
			else:
				# This allows us to search on IP addresses that are dynamically assigned
				whereclause.append(or_(obj.addresses.c.address==ip, obj.leases.c.address==ip))
		if only_statics:
			whereclause.append(obj.addresses.c.mac == obj.hosts.c.mac)
		if mac is not None:
			if endmac is not None:
				whereclause.append(and_(obj.hosts.c.mac >= mac, obj.hosts.c.mac <= endmac))
			else:
				whereclause.append(obj.hosts.c.mac==mac)
		if hostname != None:
			if type(hostname) is types.ListType or type(hostname) is types.TupleType:
				whereclause.append(obj.hosts.c.hostname.in_( hostname ))
			elif '%' in hostname:
				whereclause.append(obj.hosts.c.hostname.like( hostname ))
			else:
				whereclause.append(obj.hosts.c.hostname == hostname)
		if descriptionsearch != None:
			whereclause.append(obj.hosts.c.description.op('~*')(descriptionsearch))
		if network != None:
			whereclause.append(obj.addresses.c.address.op('<<')(network))
		if not show_expired:
			whereclause.append(obj.hosts.c.expires >= sqlalchemy.sql.func.now())
		if not show_active:
			whereclause.append(obj.hosts.c.expires < sqlalchemy.sql.func.now())
		if expiring:
			whereclause.append(obj.hosts.c.expires < sqlalchemy.sql.func.now() + text("interval '%d days'" % int(expiring) ) )

		# Check permissions and generate the query
		hosts = obj.hosts
		hosts = hosts.outerjoin(obj.dhcp_groups, obj.hosts.c.dhcp_group == obj.dhcp_groups.c.id)
		hosts = hosts.outerjoin(obj.disabled, obj.hosts.c.mac == obj.disabled.c.mac)
		hosts = hosts.outerjoin(obj.addresses, obj.hosts.c.mac==obj.addresses.c.mac)
		hosts = hosts.outerjoin(obj.leases, obj.hosts.c.mac==obj.leases.c.mac)

		if only_dynamics:
			hosts = hosts.join(obj.hosts_to_pools, obj.hosts_to_pools.c.mac == obj.hosts.c.mac)

		if gid:
			hosts = hosts.join(obj.hosts_to_groups, and_(obj.hosts.c.mac == obj.hosts_to_groups.c.mac, obj.hosts_to_groups.c.gid==gid))

		if uid:
			# FIXME: we're ignoring additional_perms/required_perms here to make this make any sense
			hosts = hosts.join(obj.hosts_to_groups, obj.hosts.c.mac == obj.hosts_to_groups.c.mac)
			# Make sure to bitwise OR users_to_groups.host_permissions after finding the user's group permissions
			hosts = hosts.join(obj.users_to_groups, and_(obj.users_to_groups.c.gid==obj.hosts_to_groups.c.gid,
								and_(obj.users_to_groups.c.uid == uid,
								obj.users_to_groups.c.permissions.op('|')(obj.users_to_groups.c.host_permissions).op('&')(str(perms.OWNER)) == str(perms.OWNER))))
		else:
			# FIXME: we should be able to include a column with effective permissions over a host and reduce some network traffic.
			# FIXME: we should really be using the same code as find_permissions_for_hosts here
			if not self._min_perms & required_perms == required_perms:
				# Get our permissions over hosts
				net_perms = obj.perm_query( self._uid, self._min_perms, networks = True, required_perms = required_perms, do_subquery=False ).alias('net_perms')
				
				# Get our permissions over networks
				host_perms = obj.perm_query( self._uid, self._min_perms, hosts = True, required_perms = required_perms, do_subquery=False ).alias('host_perms')

				# Get our permissions over domains
				dom_perms = obj.perm_query( self._uid, self._min_perms, domains = True, required_perms = required_perms, do_subquery=False ).alias('domain_perms')

				hosts = [hosts.join(host_perms, host_perms.c.mac == obj.hosts.c.mac),
						hosts.join(net_perms, net_perms.c.nid == obj.addresses.c.network),
						hosts.outerjoin(obj.domains, obj.hosts.c.hostname.like('%.' + obj.domains.c.name) ).join(dom_perms, obj.domains.c.id == dom_perms.c.did),
					]

				#columns.append( (sqlalchemy.sql.func.coalesce(net_perms.c.permissions,self._min_perms).op('|')(sqlalchemy.sql.func.coalesce(host_perms.c.permissions,self._min_perms))).label('effective_perms')


		if namesearch:
			# Let's get some DNS records, shall we?

			a_tbl = obj.dns_records.alias('a')
			cname_tbl = obj.dns_records.alias('cname')

			if '%' in namesearch:
				cname_where = cname_tbl.c.name.like(namesearch)
				a_where = a_tbl.c.name.like(namesearch)
				hosts_where = obj.hosts.c.hostname.like(namesearch)
			else:
				cname_where = cname_tbl.c.name == namesearch
				a_where = a_tbl.c.name == namesearch
				hosts_where = obj.hosts.c.hostname == namesearch

			dns_where = or_( hosts_where, or_(a_where, cname_where) )

			dns_q = a_tbl.outerjoin(cname_tbl, and_(cname_where, and_(a_tbl.c.name == cname_tbl.c.text_content, cname_tbl.c.tid == 5)))

			cname_from = a_tbl.join(cname_tbl, and_(cname_where, and_(a_tbl.c.name == cname_tbl.c.text_content, cname_tbl.c.tid == 5)))
			dns_hosts_from = obj.hosts.join(obj.addresses, obj.addresses.c.mac == obj.hosts.c.mac)

			a_q = select(columns=[obj.hosts.c.mac], from_obj=dns_hosts_from.join(a_tbl, and_(a_tbl.c.ip_content == obj.addresses.c.address, a_where)) )
			cname_q = select(columns=[obj.hosts.c.mac], from_obj=dns_hosts_from.join(cname_from, a_tbl.c.ip_content == obj.addresses.c.address) )
			hosts_q = select(columns=[obj.hosts.c.mac], from_obj=obj.hosts, whereclause=hosts_where)

			dns_q = union(a_q, cname_q, hosts_q).alias('namesearch_macs')

			hosts = hosts.join(dns_q, obj.hosts.c.mac == dns_q.c.mac)

		# Finalize the WHERE clause
		if whereclause:
			whereclause = self._finalize_whereclause( whereclause )
		else:
			whereclause = True


		if type(hosts) == types.ListType:
			if backend.enable_gul:
				newhosts = []
				for i in hosts:
					i = i.outerjoin(obj.gul_recent_arp_bymac, obj.hosts.c.mac == obj.gul_recent_arp_bymac.c.mac)
					i = i.outerjoin( gul_by_addr_subq, obj.hosts.c.mac == gul_by_addr_subq.c.mac )
					i = select(columns, from_obj=i, distinct=True).where(whereclause)
					newhosts.append(i)
				hosts = newhosts
			else:
				hosts = [ select(columns, from_obj=i, distinct=True).where(whereclause) for i in hosts ]
			hosts = union(*hosts)
		else:
			if backend.enable_gul:
				# hosts=hosts.join()
				hosts = hosts.outerjoin(obj.gul_recent_arp_bymac, obj.hosts.c.mac == obj.gul_recent_arp_bymac.c.mac)
				hosts = hosts.outerjoin( gul_by_addr_subq, obj.hosts.c.mac == gul_by_addr_subq.c.mac )
				hosts = select(columns, from_obj=hosts, distinct=True)
			else:
				hosts = select(columns, from_obj=hosts, distinct=True)
			hosts = hosts.where(whereclause)

		if self.has_min_perms( required_perms ):
			# Funky ordering to order by length ... fixes problems with guest registrations
			# because, technically, 11 in ASCII is before 9 in ASCII ... think about it 	
			if funky_ordering:
				hosts = hosts.order_by('len DESC').order_by(obj.hosts.c.hostname.desc())
			
		return hosts
		
	def _find_permissions_for_objects_query(self, objects, primary_table, primary_key, bridge_table, foreign_key, alternate_perms_key=None ):
		primary_key_name = primary_key.name
		
		# Create a list of primary key IDs
		
		if objects and (type(objects[0]) is types.DictionaryType or type(objects[0] is sqlalchemy.engine.base.RowProxy)):
			objects_list = [object[primary_key_name] for object in objects]
		else:
			objects_list = objects
			
		if objects_list is None or len(objects_list) == 0:
			return None, None
		
		# Query for the objects, LEFT joining permissions
		fromobj = (bridge_table.join( primary_table, and_(foreign_key==primary_key, primary_key.in_(objects_list) ) )
			.outerjoin(obj.users_to_groups, and_(obj.users_to_groups.c.gid==bridge_table.c.gid, obj.users_to_groups.c.uid == self._uid)))
		
		permissions_col = sqlalchemy.sql.func.coalesce(sqlalchemy.sql.func.bit_or(obj.users_to_groups.c.permissions).op('|')(str(self._min_perms)),str(self._min_perms))

		if primary_key==obj.hosts.c.mac:
			host_permissions_col = sqlalchemy.sql.func.coalesce(sqlalchemy.sql.func.bit_or(obj.users_to_groups.c.host_permissions),str(self._min_perms))
			permissions_col = permissions_col.op('|')(host_permissions_col)

		return permissions_col, fromobj
		
	def _find_permissions_for_objects(self, objects, primary_table, primary_key, bridge_table, foreign_key, alternate_perms_key=None ):
		'''
		Returns a dictionary of { object's primary key : permissions bitstring } 
		for this user's overall permissions on the objects
		
		@param objects: A list of dictionaries of objects to find permissions for, usually hosts or
		domains, or a list of primary key values
		@param primary_table: A SQLAlchemy table object, usually obj.some_table
		@param primary_key: A SQLAlchemy column object, usually obj.some_table.c.id
		@param bridge_table: A SQLAlchemy table object, usually obj.something_to_groups 
		@param foreign_key: A SQLAlchemy column object, usually obj.something_to_groups.c.xid
		@param alternate_perms_key: A SQLAlchemy column object, usually obj.some_table.c.some_name, that
		will be used as the key for the returned permissions object. If not specified, the
		primary_key's name is used. This better be a unique column or bad things may happen.
		'''
		
		permissions_col, fromobj = self._find_permissions_for_objects_query( objects, primary_table, primary_key, bridge_table, foreign_key, alternate_perms_key )

		columns = [primary_key, permissions_col.label('permissions') ]

		if alternate_perms_key is not None:
			columns.append(alternate_perms_key)
		
		query = select(columns, from_obj=fromobj).group_by(primary_key)
		if alternate_perms_key is not None:
			query = query.group_by(alternate_perms_key)
		
		results = self._execute(query)
		
		permissions = {}
		
		# If the alternate_perms_key is specified, use that for our permissions object
		perms_key_name = alternate_perms_key.name if alternate_perms_key is not None else primary_key.name
		
		for row in results:
			permissions[row[perms_key_name]] = row['permissions']
			
		# FIXME: why are we making a list of length 1?
		return [permissions]
	
	def find_permissions_for_hosts(self, hosts, alternate_perms_key=None):
		'''
		Returns a dictionary of { MAC (or alternate_perms_key) : permissions bitstring } 
		for this user's overall permissions on the each host
		
		@param host: a list of dictionaries of hosts (or a list of MACs).
		The dictionary must have 'mac' key, all others keys are not used
		'''
		
		primary_key=obj.hosts.c.mac

		permissions_col, fromobj = self._find_permissions_for_objects_query(objects=hosts, primary_table=obj.hosts, primary_key=primary_key, bridge_table=obj.hosts_to_groups, foreign_key=obj.hosts_to_groups.c.mac, alternate_perms_key=alternate_perms_key)
		if permissions_col is None or fromobj is None:
			return [{}]

		dom_u2g = obj.users_to_groups.alias('domain_users_to_groups')
		dom_u2g2d = dom_u2g.join(obj.domains_to_groups, and_(dom_u2g.c.gid == obj.domains_to_groups.c.gid, dom_u2g.c.uid == self._uid ))

		fromobj = fromobj.outerjoin( obj.domains, obj.hosts.c.hostname.like('%.' + obj.domains.c.name) )
	
		fromobj = fromobj.outerjoin(dom_u2g2d, obj.domains_to_groups.c.did == obj.domains.c.id)

		# Bad order!
		#fromobj = fromobj.outerjoin( obj.domains_to_groups, obj.domains_to_groups.c.did == obj.domains.c.id )
		#fromobj = fromobj.outerjoin( dom_u2g, and_(dom_u2g.c.gid == obj.domains_to_groups.c.gid, dom_u2g.c.uid == self._uid ))

		# Do _not_ or in the 'host_perms' here, or everyone will be able to mess with everything.
		dom_permissions_col = sqlalchemy.sql.func.coalesce( sqlalchemy.sql.func.bit_or(dom_u2g.c.permissions), str(self._min_perms))
		permissions_col = permissions_col.op('|')(dom_permissions_col)

		columns = [primary_key, permissions_col.label('permissions'), dom_permissions_col.label('meh') ]

		if alternate_perms_key is not None:
			columns.append(alternate_perms_key)
		
		query = select(columns, from_obj=fromobj).group_by(primary_key)
		if alternate_perms_key is not None:
			query = query.group_by(alternate_perms_key)

		#debug = select( [primary_key, dom_u2g.c.permissions, dom_u2g.c.uid, dom_u2g.c.gid, obj.hosts.c.hostname, obj.domains.c.name], from_obj=fromobj )
		#print self._execute(debug)
		
		results = self._execute(query)
		#print results
		
		permissions = {}
		
		# If the alternate_perms_key is specified, use that for our permissions object
		perms_key_name = alternate_perms_key.name if alternate_perms_key is not None else primary_key.name
		
		for row in results:
			permissions[row[perms_key_name]] = row['permissions']
			
		# FIXME: why are we making a list of length 1?
		return [permissions]
	
	def find_permissions_for_domains(self, domains, alternate_perms_key=None):
		'''
		Returns a dictionary of { domain ID : permissions bitstring } 
		for this user's overall permissions on the each domain
		
		@param domains: a list of dictionaries of domains (or a list of domain IDs).
		The dictionary must have 'id' key, all others keys are not used
		'''
		
		return self._find_permissions_for_objects(objects=domains, primary_table=obj.domains, primary_key=obj.domains.c.id, bridge_table=obj.domains_to_groups, foreign_key=obj.domains_to_groups.c.did, alternate_perms_key=alternate_perms_key)
	
	def find_permissions_for_dns_records(self, records):
		'''
		Returns a dictionary of { DNS record ID : permissions bitstring } 
		for this user's overall permissions on the DNS records.
		
		@param records: a list of dictionaries of DNS records
		'''
		
		if not records:
			return [{}]
		
		try:
			names = [row['name'] for row in records]
		except Exception, e:
			raise error.NotImplemented("You likely did not supply a list of dictionaries of DNS records. Error was: %s" % e)

		# Get the hosts who have names from above, then get the permissions for those hosts
		hosts = self.get_hosts( hostname=names )
		host_perms = self.find_permissions_for_hosts( hosts, alternate_perms_key=obj.hosts.c.hostname )
		host_perms = host_perms[0] if host_perms else {}

		# Get the domain permissions for these names
		fqdn_perms = self.find_domain_permissions_for_fqdns(names=names)
		fqdn_perms = fqdn_perms[0] if fqdn_perms else {}

		# Get the DNS types so that we can clear permissions to default if they can't read the type
		dns_types = self.get_dns_types( only_useable=True )
		dns_type_perms = {}
		# Have [ { 'id' : 0, 'name' : 'blah' }, ... ]
		for typename in dns_types:
			dns_type_perms[typename['id']] = typename
			# Now have { 0 : { ... dns dict ... }, 12 : { ... dns dict ... } ... }
		
		# Time to make the final permission set...
		permissions = {}
		
		# Initialize the permissions dictionary with my min_perms to GUARANTEE a result for every record input
		for rr in records:
			permissions[rr['id']] = str(self._min_perms)
		
		for rr in records:
			# For every record that was a host, add that permission set to the final result
			if host_perms.has_key(rr['name']):
				permissions[rr['id']] = str(Perms(permissions[rr['id']]) | host_perms[rr['name']])

			# For every record that was a domain, or had permissions via a domain, add in those permissions
			if fqdn_perms.has_key(rr['name']):
				permissions[rr['id']] = str(Perms(permissions[rr['id']]) | fqdn_perms[rr['name']])
				
			# If they cannot use the DNS type of this record, even if they have host
			# or domain perms over it, then they cannot modify it 
			if not dns_type_perms.has_key(rr['tid']):
				permissions[rr['id']] = str(backend.db_default_min_permissions)

		return [permissions]
	
	def find_domain_permissions_for_fqdns(self, names):
		'''
		Get the permissions for a set of fully-qualified domain names based
		on the domain of each name. This must be combined (later, in any view)
		with DNS type permissions for the "complete" permissions over any
		DNS record.
		
		@param records: a list of fully-qualified domain names
		@return: { 'dns.record.name' : permissions bitstring, ... }
		'''
		
		if not names:
			return [{}]
		
		# Get the domains who have those names, then get the permissions for those domains
		domains = self.get_domains( contains=names )
		if len(domains) == 0:
			return []

		# FIXME: Holy inefficiency, batman!  These are never used!
		#domain_perms = self.find_permissions_for_domains( domains )
		
		#domain_perms = domain_perms[0] if domain_perms else {}
		
		permissions = {}
		
		# Initialize the permissions dictionary with my min_perms to GUARANTEE a result for every record input
		for name in names:
			permissions[name] = str(self._min_perms)
		
		# Turn the domain_perms from { domain ID : permissions } into { name : permissions } so that we can do O(1) lookups
		domain_name_perms = self.find_permissions_for_domains( domains, alternate_perms_key=obj.domains.c.name )
		domain_name_perms = domain_name_perms[0] if domain_name_perms else {}
		
		for name in names:
			first_level_domain_name = '.'.join(name.split('.')[1:])

			# For every name, add in the domain permissions over that name
			if domain_name_perms.has_key(name) or domain_name_perms.has_key(first_level_domain_name):
				perms_to_add = domain_name_perms[name] if domain_name_perms.has_key(name) else domain_name_perms[first_level_domain_name]
				permissions[name] = str(Perms(permissions[name]) | perms_to_add)
				
		return [permissions]
	
	def _get_hosts_to_groups( self, mac=None, gid=None ):
		"""
		Return rows of hosts_to_groups
		"""
		
		if not mac and not gid:
			raise error.RequiredArgument("Must specify mac and/or gid")
		
		# Require read perms on the group
		if self.has_min_perms(perms.READ):
			relation = select( [obj.hosts_to_groups] )
			if mac:
				relation = relation.where(obj.hosts_to_groups.c.mac == mac)
			if gid:
				relation = relation.where(obj.hosts_to_groups.c.gid==gid)
		else:
			# TODO: v2: write getting a HTG relation for user's without at least READ permissions
			raise error.NotImplemented("You should never see this")
			
		return relation
	
	def _get_hosts_to_pools(self, mac=None):
		"""
		Get hosts_to_pools relations
		"""
		
		if mac:
			self.require_perms(perms.READ)
		else:
			self.require_perms(perms.DEITY)
			

		fromobj = obj.hosts_to_pools.join(obj.pools, obj.hosts_to_pools.c.pool_id == obj.pools.c.id)
		query = select([obj.hosts_to_pools, obj.pools.c.name, obj.pools.c.description, ], from_obj=fromobj)
		
		if mac:
			query = query.where(obj.hosts_to_pools.c.mac==mac)
		
		return query
	
	def _get_leases(self, address=None, mac=None, show_expired=True):
		"""
		Get leases
		"""

		columns = [obj.leases, (obj.leases.c.ends < sqlalchemy.sql.func.now()).label('expired')]
		
		if address:
			self.require_perms(perms.READ)
			query = select( columns ).where(obj.leases.c.address == address)
		elif mac:
			self.require_perms(perms.READ)
			query = select( columns ).where(obj.leases.c.mac == mac)
		else:
			raise error.RequiredArgument( 'Exactly one of mac or address required' )

		if not show_expired:
			query = query.where( obj.leases.c.ends > sqlalchemy.sql.func.now() )
		
		return query
	
	def _get_internal_auth( self, uid ):
		"""
		Get a row from internal_auth
		"""
		
		self.require_perms( perms.DEITY )
		
		return select( [obj.internal_auth], obj.internal_auth.c.id == uid )

	def _get_networks( self, nid=None, network=None, gid=None, address=None, shared_network_id=False, additional_perms='00000000', exact=True ):
		'''
		Return networks
		@param nid: the database network id, returns one network
		@param network: a CIDR address, returns one network
		@param gid: return on the networks within this group ID
		'''
		
		# require read permissions over networks
		required_perms = perms.READ
			
		if additional_perms:
			required_perms = required_perms | additional_perms
		
		if self.has_min_perms( required_perms ):
			query = obj.networks
		else:
			net_perms = obj.perm_query( self._uid, self._min_perms, networks = True, required_perms = required_perms )
			query = net_perms.join(obj.networks, obj.networks.c.network == net_perms.c.nid )

		if gid:
			query = query.join(obj.networks_to_groups, and_(obj.networks.c.network == obj.networks_to_groups.c.nid, obj.networks_to_groups.c.gid==gid))			
		
		# Create the selectable
		query = select( [obj.networks, sqlalchemy.sql.func.netmask(obj.networks.c.network).label('netmask')], from_obj=query )

		if nid:
			query = query.where(obj.networks.c.network == nid)
		if network:
			if exact:
				query = query.where(obj.networks.c.network==network)
			else:
				query = query.where(obj.networks.c.network.op('<<=')(network))
		if address:
			query = query.where(obj.networks.c.network.op('>>=')(address))
		if shared_network_id is not False:
			query = query.where(obj.networks.c.shared_network == shared_network_id)
		
		return query 
	
	def _get_shared_networks( self, shared_network_id=False ):
		self.require_perms(perms.READ)
		q = select( [ obj.shared_networks ] )
		if shared_network_id is not False:
			q = q.where( obj.shared_networks.c.id == shared_network_id )
		return q
					
	def _get_networks_to_groups( self, nid=None, gid=None ):
		"""
		Get a networks_to_groups row
		"""
		
		# Require read perms on the group
		if self._min_perms & perms.READ is perms.READ:
			relation = select( [obj.networks_to_groups] )
			relation = relation.where(and_(obj.networks_to_groups.c.nid == nid, obj.networks_to_groups.c.gid==gid))
		else:
			# TODO: v2: write getting a HTG relation for user's without at least READ permissions
			pass
		
	def _get_notifications( self):
		"""
		Get all notification types
		"""
		
		self.require_perms(perms.READ)
		
		query = select([obj.notifications])
		
		return query
		
	def _get_pools( self, name=None ):
		'''
		Return pools
		
		@param name: the pool name
		'''

		# Permissions
		self.require_perms(perms.DEITY)
		
		# Set base query
		query = select([obj.pools])
		
		if name != None:
			query = query.where(obj.pools.c.name == name)

		return query
		
	def _get_disabled( self, mac=None ):
		'''
		Return pools
		
		@param name: the pool name
		'''

		# Permissions
		self.require_perms(perms.READ)
		
		# Set base query
		query = select( [obj.disabled] )
		
		if mac:
			query = query.where(obj.disabled.c.mac == mac)

		return query
		
	def _get_permissions(self):
		'''
		Return all of the permission types present in the database
		'''
		
		self.require_perms(perms.READ)
		
		query = select([obj.permissions])
		
		return query
		
	def is_disabled(self, mac=None, address=None):
		'''
		If disabled, return a list containing the disabled record, else an empty list
		'''
		# Is there an XOR boolean operator?
		if (not address and not mac) or (address and mac):
			raise error.RequiredArgument('You must specify exactly one of mac or address: address=%s, mac=%s' % (address, mac))
		
		self.require_perms(perms.READ)
		if mac:
			query = select([obj.disabled]).where( obj.disabled.c.mac == mac )
		elif address:
			query = select([obj.disabled], from_obj = obj.disabled.join( obj.leases, obj.leases.c.mac == obj.disabled.c.mac) )
			query = query.where( obj.leases.c.address == address )
		
		return self._execute( query )
		
	def _get_supermaster( self ):
		"""supermaster"""
		# ???
		pass
		
	def _get_users( self, uid=None, username=None, source=None, gid=None ):
		'''
		Return a filtered list of users
		@param uid: a database user id
		@param username: a database username
		@param page: A zero-based index to the desired 'page'
		@param gid: return only the users within this group ID
		'''

		# Permissions
		self.require_perms(perms.READ)
		
		columns = [obj.users]
		
		query = obj.users
		
		if gid:
			columns.append(obj.users_to_groups.c.permissions)
			query = obj.users.join(obj.users_to_groups, and_(obj.users.c.id == obj.users_to_groups.c.uid, obj.users_to_groups.c.gid==gid))

		# Set base query
		query = select(columns, from_obj=query)
		
		if username:
			if '%' in username:
				query = query.where(sqlalchemy.sql.func.lower(obj.users.c.username).like( username.lower()))
			else:
				query = query.where(sqlalchemy.sql.func.lower(obj.users.c.username) == username.lower())
		if uid != None:
			query = query.where(obj.users.c.id == uid)
		if source != None:
			query = query.where(obj.users.c.source == source)

		return query
	
	def _get_user_to_group( self ):
		"""
		Get a row from users_to_groups
		"""
		
		pass
		
	def _get_vlan( self ):
		"""vlan"""
		pass
		
	def _get_vlan_to_group( self ):
		"""vlan_to_group"""
		pass
	def _get_gul_recent_arp_byaddress( self, address ):
		self.require_perms( perms.READ )
		if not backend.enable_gul:
			raise Exception("GUL functionality is disabled in backend config")

		if type(address) == list:
			where = obj.gul_recent_arp_byaddress.c.address.in_(address)
		elif type(address) == str:
			where = obj.gul_recent_arp_byaddress.c.address == address
		else:
			raise error.InvalidArgument('expecting string or list for address: %r' % address)

		fmt = 'FMDD"d "FMHH24"h "FMMI"m "FMSS"s"'
		last_seen = sqlalchemy.sql.func.to_char(sqlalchemy.sql.func.now() - obj.gul_recent_arp_byaddress.c.stopstamp, fmt).label('last_seen')

		query = select( columns=[obj.gul_recent_arp_byaddress, last_seen],  ).where( where )

		return query

	def _get_gul_recent_arp_bymac( self, mac ):
		self.require_perms( perms.READ )
		if not backend.enable_gul:
			raise Exception("GUL functionality is disabled in backend config")
		
		fmt = 'FMDD"d "FMHH24"h "FMMI"m "FMSS"s"'
		last_seen = sqlalchemy.sql.func.to_char(sqlalchemy.sql.func.now() - obj.gul_recent_arp_bymac.c.stopstamp, fmt).label('last_seen')


		query = select( columns=[obj.gul_recent_arp_bymac, last_seen],  ).where(obj.gul_recent_arp_bymac.c.mac == mac)

		return query

class DBBackendInterface( DBBaseInterface ):
	def __init__(self):
		DBBaseInterface.__init__( self )
		self._min_perms = perms.READ

class DBInterface( DBBaseInterface ):
	'''Components that write to the database
	
		Every function should create a query and execute it using
		the _execute_set( query ) function for single CRUD operations.
		
		For functions that do multiple CRUD operations, use a transaction:
		------
		self._begin_transaction()
		try:
			query = self._execute_set( ... some query ... )
			self.add_thing_to_group( ... this function executes a query ... )
			
			# Commit the transaction
			self._commit()
		except:
			self._rollback()
			raise
		------
	'''
	def __init__(self, username, uid=None, min_perms=None):
		'''
		@param uid: the user's database ID
		@param username: the user's username
		@param min_permissions: the user's minimum permissions set
		'''
		DBBaseInterface.__init__( self )
		self._username = username
		if not uid or not min_perms:
			# bootstrap - this perm is required to do the query
			self._min_perms = perms.READ
			user = self.get_users(username=username)
			if not user:
				raise error.NotFound('Auth user not found. May need to create it in the database or check config settings.')
			user = user[0]
			self._username = user['username']
			uid = user['id']
			min_perms = user['min_permissions']
		self._uid = uid
		self._min_perms = Perms(min_perms)
	
	def _assign_ip6_address(self, mac, network, dhcp_server_id=0, use_lowest=False, is_server=False):
		# FIXME: how do we get this?
		network = openipam.iptypes.IP(network)
		if network.prefixlen() == 64:
			# FIXME: the logic for choosing an address to try should go in a config file somewhere
			address_prefix = network | ( dhcp_server_id << 48 )
			if not is_server:
				address_prefix |= 1 << 63
			address_prefix = address_prefix.make_net(48)
		if network.prefixlen() == 128:
			address = network
		elif use_lowest:
			a = obj.addresses.alias('a')
			q = select(columns = [(obj.addresses.c.address + 1).label('next'),], from_obj=obj.addresses).where(obj.addresses.c.address.op('<<')(str(network)))
			sub_q =  sqlalchemy.sql.exists(whereclause=and_(a.c.address == obj.addresses.c.address + 1, (a.c.address + 1).op('<<')(str(network))))
			q = q.where(~sub_q)
			q = q.limit(1).order_by('next')
			results = self._execute(q)
			if not results:
				raise Exception('Did not find an ip6 address?! network: %s prefixlen: %s mac: %s'%(network,network.prefixlen(),mac))
			address = results[0][0]
		else:
			macaddr = int('0x' + re.sub(mac,'[^0-9A-Fa-f]+',''))
			lastbits = (macaddr & 0xffffff) ^ ( macaddr >> 24 ) | ( random.getrandbits(24) << 24 )
			address = address_prefix | lastbits
			# FIXME: check to see if it is used
		addr = self.get_addresses(address=str(address))
		if addr:
			raise Exception("Address %r in use" % addr)
		# assign address
		network = self._execute(select(columns=[obj.networks.c.network,],from_obj=obj.networks).where(obj.networks.c.network.op('>>')(str(address))))[0][0]
		self.add_address(mac=mac, network=str(network), address=str(address))

		return address

	def _audit_vals(self, table, vals):
		# auditing
		if table.name == 'disabled':
			vals['disabled'] = sqlalchemy.sql.func.now()
			vals['disabled_by'] = self._uid
		if 'changed' in table.c:
			vals['changed'] = sqlalchemy.sql.func.now()
		if 'changed_by' in table.c:
			vals['changed_by'] = self._uid

		return vals


	
	def _do_insert(self, table, values):
		vals = self._audit_vals(table, values)
		return self._execute_set( table.insert(values=values) )

	def _do_update(self, table, where, values):
		vals = self._audit_vals(table, values)
		return self._execute_set( table.update(values=values).where(where) )

	def _do_delete(self, table, where):
		if where is None or where is True or where == '':
			raise error.InvalidArgument('You just tried to delete everything in the "%s" table.  where=%s' % (str(table.name), str(where)))

		self._begin_transaction()
		try:
			# Let's do some auditing :)
			if table.name == 'disabled' or 'changed' in table.c or 'changed_by' in table.c:
				# should update our audit log
				self._do_update(table=table, where=where, values={})
			result = self._execute_set(table.delete().where(where))
			# Commit the transaction
			self._commit()
		except:
			self._rollback()
			raise
		return result

	def _execute_set(self, query, **kw):
		"""
		Execute the given query. If in a transaction, I'll use that transactional
		connection. Otherwise, a non-transactional, auto-commiting connection will
		be created, used, and closed.
		
		@param query: a query object to execute
		@param **kw: additional arguments to pass to the execute function
		"""

		if hasattr(self, '_conn'):
			# We are currently in a transaction, so just execute the given query
			# The caller must commit manually after all queries have been executed
			result = self._conn.execute(query, **kw)
		else:
			# We are not in a transaction, so create a non-transactional, auto-committing
			# connection and execute the query. After, close the connection.
			
			conn = obj.engine.connect()
			result = conn.execute(query, **kw)
			conn.close()
		
		return result

	def _finalize_expires(self, expires, expiration_format=None):
		"""
		Makes expires a SQL-Alchemy capable datetime, whether it already is or is a string with an expiration format
		"""

		# Make sure we have an appropriate datetime object
		#if expires and not isinstance(expires, datetime.datetime) and not isinstance(expires, datetime.date):
		if expiration_format:
			# there has to be a better way than this...
			expires = datetime.datetime(*time.strptime(expires, expiration_format)[0:6])
		else:

			if expires and isinstance(expires, datetime.date):
				# Need to make this datetime.date a datetime.datetime
				expires = datetime.datetime.combine(expires, datetime.time(0))

			if expires and not isinstance(expires, datetime.datetime):
				try:
					# xmlrpclib happily converts datetime.datetime to xmlrpclib.DateTime (which is a string in ISO 8601 format)
					expires = datetime.datetime.strptime( str( expires ), '%Y%m%dT%H:%M:%S' )
				except ValueError, e:
					raise error.RequiredArgument("Could not convert expires to datetime object (from %r %s) -- expiration_format must be specified for strings" % (expires,type(expires)))
		return expires
	
	def add_address( self, address, network, mac=None, pool=None, reserved=False ):
		"""
		Add an address in either the specified pool or belonging to the specified MAC.
		
		@param address: the IP address to add
		@param mac: the MAC address this ip belongs to
		@param pool: the pool id of the pool this ip belongs to
		@param reserved: a boolean of if this address is reserved (broadcast, network, and others)
		"""

		addr = openipam.iptypes.IP(address)
		if addr.family == 6 and not backend.allow_ipv6:
			raise error.InvalidArgument('IPv6 support is disabled in backend configuration.')
		del addr

		self.require_perms( perms.DEITY )

		values={'address':str(address),
				'network':str(network),
				'mac':mac,
				'pool':pool,
				'reserved': reserved }
		return self._do_insert(table=obj.addresses, values=values)
	
	def update_address(self, address, mac=None, pool=None):
		"""
		Update a row in the addresses table
		"""
		
		addr = openipam.iptypes.IP(address)
		if addr.family == 6 and not backend.allow_ipv6:
			raise error.InvalidArgument('IPv6 support is disabled in backend configuration.')
		del addr

		if mac and pool:
			raise error.RequiredArgument("Specify exactly one of MAC or pool")
		
		c_address = self.get_addresses(address=address)

		if len(c_address) != 1:
			raise error.NotFound('Address %s does not exist (%s)' % (address, c_address))
		c_address = c_address[0]

		if not self.has_min_perms( perms.DEITY ):
			if c_address['reserved']:
				raise error.InsufficientPermissions('You must be a superuser to alter reserved addresses (%s)' % address)
			
			# check to see if we are allowed to rob this pool
			if c_address['pool'] is not None and c_address['pool'] not in backend.assignable_pools:
				raise error.InsufficientPermissions('Only a superuser can alter addresses in this pool: %s' % c_address)

			if pool is not None:
				if pool != backend.func_get_pool_id( address=address ):
					raise error.InsufficientPermissions('Only a superuser can assign addresses to pools not returned by backend.func_get_pool_id(): %s' % c_address)
			
			if c_address['mac'] == None:
				# check for ADD permissions over the network
				self._require_perms_on_net(permission=perms.ADD, address=address)
			else:
				try:
					# check for ADMIN permissions over this network
					self._require_perms_on_net(permission=perms.OWNER, address=address)
				except error.InsufficientPermissions, e:
					# or ADMIN permissions over this host
					self._require_perms_on_host(permission=perms.OWNER, mac=c_address['mac'])
		
		if mac is not None:
			# delete any previous leases
			self._do_delete( table=obj.leases, where=obj.leases.c.address == address )
		
		# FIXME: take care of "reserved" ... right now just doesn't change whatever it is set to and has DB constraints
		return self._do_update(table=obj.addresses, where=obj.addresses.c.address == address, values={ 'mac' : mac, 'pool' : pool })

	def add_pool( self, name, description = None, allow_unknown=False, allow_known=True, lease_time=None, dhcp_group=None ): 
		"""
		Add a pool with the given values
		"""
		
		self.require_perms( perms.DEITY )

		values={'name' : name,
				'description' : description,
				'allow_unknown' : allow_unknown,
				'lease_time' : lease_time,
				'allow_known': allow_known,
				'dhcp_group' : dhcp_group }

		return self._do_insert(table=obj.pools, values=values)
	
	def add_pool_to_group( self, pool, gid ):
		"""
		Add a pool to a group
		"""
		
		self.require_perms(perms.DEITY)
		
		return self._do_insert(table=obj.pools_to_groups, values={ 'pool' : pool, 'gid' : gid })
		

	def add_host_to_pool( self, mac, pool_id ):
		"""
		Give the host permission to get addresses from pool
		"""
		if not self.has_min_perms( perms.ADD ):
			# Get our permissions over pools
			pool_perms = obj.perm_query( self._uid, self._min_perms, pools = True, required_perms = perms.ADD, do_subquery=False, andwhere = obj.pools_to_groups.c.pool==pool_id )
			pools = self._execute( pool_perms )
			if not pools:
				raise error.InsufficientPermissions('ADD permission required over pool id %s' % pool_id)
		
		return self._do_insert(table=obj.hosts_to_pools, values={ 'mac' : mac, 'pool_id' : pool_id })

	def add_attribute( self, name, description=None, structured=False, required=False, validation=None ):
		"""
		"""
		self.require_perms(perms.DEITY)

		return self._do_insert(table=obj.attributes, values={'name':name, 'description':description, 'structured': structured,
			'required': required, 'validation': validation } )

	def add_structured_attribute_value( self, aid, value, is_default=False ):
		"""
		"""
		self.require_perms(perms.DEITY)

		attr = self.get_attributes(aid=aid)
		if len(attr) != 1:
			raise error.InvalidArgument("aid not unique or non-existent: %s" % attr)
		attr=attr[0]
		if not attr['structured']:
			raise error.InvalidArgument("aid specified is not a structured attribute: %s" % attr)

		return self._do_insert(table=obj.structured_attribute_values, values={'aid':aid, 'value':value, 'is_default': is_default})

	def add_structured_attribute_to_host( self, mac, avid ):
		"""
		"""
		self._require_perms_on_host(permission=perms.OWNER, mac=mac)

		attr_value = self.get_structured_attribute_values(avid=avid)
		if len(attr_value) != 1:
			raise error.InvalidArgument("Structured attribute value non-existent or not unique: %s" % attr_value)

		return self._do_insert(table=obj.structured_attributes_to_hosts, values={'mac':mac, 'avid': avid})

	def del_structured_attribute_to_host( self, mac, avid ):
		"""
		"""
		self._require_perms_on_host(permission=perms.OWNER, mac=mac)

		where = and_( obj.structured_attributes_to_hosts.c.mac == mac, obj.structured_attributes_to_hosts.c.avid == avid )

		return self._do_delete(table=obj.structured_attributes_to_hosts, where=where)

	def add_freeform_attribute_to_host( self, mac, aid, value ):
		"""
		"""
		self._require_perms_on_host(permission=perms.OWNER, mac=mac)

		attr = self.get_attributes(aid=aid)
		if len(attr) != 1:
			raise error.InvalidArgument("aid not unique or non-existent: %s" % attr)
		attr=attr[0]
		if attr['structured']:
			raise error.InvalidArgument("aid specified is not a freeform attribute: %s" % attr)

		return self._do_insert(table=obj.freeform_attributes_to_hosts, values={'mac':mac, 'aid':aid, 'value':value})

	def del_freeform_attribute_to_host( self, mac, aid, value ):
		"""
		"""
		self._require_perms_on_host(permission=perms.OWNER, mac=mac)

		where = and_( obj.freeform_attributes_to_hosts.c.mac == mac, obj.freeform_attributes_to_hosts.c.aid == aid,
				obj.freeform_attributes_to_hosts.c.value == value )

		return self._do_delete(table=obj.freeform_attributes_to_hosts, where=where)

	def add_auth_source( self ):
		"""auth_source"""
		pass
		
		
		
	def add_soa_record( self, name, primary, hostmaster, serial=0, refresh=10800, retry=3600, expire=604800, default_ttl=3600 ):
		"""Add an SOA using add_dns_record()
			@param name: name for SOA record
			@param primary: primary name server for this SOA
			@param hostmaster: email address ( no dots before the @, because of the broken way these records work )
			@param serial: leave this at 0 unless your _really_ know what you are doing
			@param refresh:
			@param retry:
			@param expire:
			@param default_ttl: """
		
		self.require_perms(perms.DEITY)
		
		content = "%(primary)s %(hostmaster)s %(serial)d %(refresh)d %(retry)d %(expire)d %(default_ttl)d" % locals()
		return self.add_dns_record( name=name, text_content=content, tid=6 )

	def add_dns_record( self, name, tid, ip_content=None, text_content=None, priority=None, ttl=None, vid=None, add_ptr=True ):
		"""Add a DNS resource record
			@param name: name for SOA record
			@param tid: the database type ID
			@param ip_content:
			@param text_content:
			@param add_ptr: Adds a PTR record when an A record is added
			"""
		if (not ip_content and not text_content) or (ip_content and text_content):
			raise error.RequiredArgument("Pass exactly one of ip_content or text_content to add_dns_record. Got: (%s, %s)" % (ip_content, text_content))
		
		# Important, lowercase the name
		name = name.lower()

		if not ttl:
			ttl = backend.default_ttl
		
		# FIXME: default to 0 for unspecified priority
		
		# Require priority for MX and SRV
		if ((tid == 15 or tid == 33) and priority==None) or ((tid != 15 and tid != 33) and priority!=None):
			raise error.RequiredArgument("Must specify priority for MX(15) or SRV(33) records, but not others (tid=%s, prio=%s)" % (tid, priority))

		if tid == 5: # CNAME
			records = self.get_dns_records( name=name, vid=vid )
			if records:
				raise error.InvalidArgument("Trying to create CNAME record while other records exist: %r" % records)
		else: # not CNAME
			records = self.get_dns_records( name=name, vid=vid, tid=5 )
			if records:
				raise error.InvalidArgument("Trying to create record while CNAME record exists: %r" % records)

		
		self._begin_transaction()
		try:
			domains = self.get_domains(contains=name, additional_perms=perms.ADD)

			# Check if we have the required permissions over this domain
			if not domains:
				domains = self.get_domains(contains=name)
				if not domains:
					raise error.NotFound("Could not find domain to contain %s" % name)
				if tid == 12 and domains:
					# FIXME: Find permissions over IP address
					if 'in-addr.arpa' in name:
						parts = name.split('.')[:4]
						parts.reverse()
						address = '.'.join(parts)
					elif 'ip6.arpa' in name and backend.allow_ipv6:
						parts = name.split('.')[:-2]
						parts.reverse()
						addr = []
						for i in range( len(parts) / 4 ):
							addr.append(''.join(parts[4*i,4*(i+1)]))
						address = ':'.join(addr)
					else:
						raise error.InvalidArgument('Invalid name for PTR: %s' % name)

					self._require_perms_on_address(perms.OWNER, address)
				else:
					raise error.InsufficientPermissions("Insufficient permissions to access domain containing %s" % name)
			
			if domains[0]['type'] == 'SLAVE':
				raise error.InvalidArgument("Cannot create name %s: not authoritative for domain %s" % (name, domains[0]['name']))

			values = { 
				'name' : name,
				'tid' : tid,
				'did' : domains[0]['id'],
				'ip_content' : ip_content,
				'priority' : priority,
				'text_content' : text_content,
				'ttl' : ttl,
				'vid' : vid,
			}
			
			if not self.has_min_perms( perms.DEITY ):
				# check permissions...
				# we need to find the permissions required to add this kind of record
				
				query = select([obj.dns_types], and_(obj.dns_types.c.id == tid, obj.dns_types.c.min_permissions.op('&')(str(self._min_perms)) == obj.dns_types.c.min_permissions ))
				result = self._execute(query)
				
				if not result:
					raise error.InsufficientPermissions("Insufficient permissions to add a DNS record of type %s" % tid)
			
			# We want to add the PTR after here in case we decide to do extra checking in the db at some point
			#  (ie. ensure there is a valid fwd lookup associated with each ptr)
			result = self._do_insert( table=obj.dns_records, values=values )
			
			if tid == 1 or tid == 28:
				# FIXME: Be sure we have owner perms or so over this address
				ip = openipam.iptypes.IP(ip_content)
				if tid == 1 and ip.version() != 4:
					raise Exception('A record must have ip4 address: name: %s tid: %s address: %s' % (name,tid,ip_content))
				if tid == 28 and ip.version() != 6:
					raise Exception('AAAA record must have ip6 address: name: %s tid: %s address: %s' % (name,tid,ip_content))
				# PTR record
				if add_ptr:
					ptrname = ip.reverseName()[:-1]
					self.add_dns_record(name=ptrname, text_content=name, tid=12, ttl=ttl, vid=vid)
					

			# Commit the transaction
			self._commit()
		except:
			self._rollback()
			raise
		
		return result
		
	def add_dns_type( self ):
		"""dns_type"""
		pass
		
		
	def add_domain( self, name, description=None, master=None, typename=None ):
		"""Add a domain
		@param name: the fully qualified domain name
		@param master: ???
		@param type: ???"""
		
		self.require_perms(perms.DEITY)
		
		name = name.lower()
		
		return self._do_insert(table=obj.domains, values={'name':name, 'master':master, 'type':typename, 'description':description, 'changed_by' : self._uid })
		
	def add_dns_view( self):
		pass
		
	def add_dhcp_group( self, name, description ):
		"""Add a group
		@param name: the group name
		@param description: a description of the group"""

		self.require_perms(perms.DEITY)
		return self._do_insert(obj.dhcp_groups,
				{'name':name,'description':description})

	def add_dhcp_option( self ):
		"""dhcp_option"""
		pass
		
	def add_dhcp_option_to_dhcp_group(self, gid, oid, value, is_hex=False):
		"""Add a DHCP option to a DHCP group
		@param oid: the database option id
		@param gid: the database group id
		@param value: the value of this DHCP option within the group"""
		
		self.require_perms( perms.DEITY )
		
		dhcp_option = self.get_dhcp_options( id=oid )

		if len(dhcp_option) != 1:
			raise Exception("dhcp_option %d does not exist or not unique: %r" % (oid,dhcp_option))

		dhcp_option = dhcp_option[0]
		if is_hex:
			value = str( binascii.unhexlify(value) )
		elif int(dhcp_option['size'][0]) == 4:
			# expect an IP address
			if is_addresses( value ):
				if '+' not in dhcp_option['size']:
					# sorry, pal... just the one
					assert ',' not in value
				addresses = value.split(',')
				byteslst = []
				for address in addresses:
					address=address.strip()
					octets = address.split('.')
					if len(octets) != 4:
						raise Exception('invalid ip address: %s' % address)
					byteslst.extend( octets )
				byteslst = map(int, byteslst)
				value = ''.join( map(chr , byteslst ) )

		if value == 51: # lease time
			value = int_to_bytes( oid, 4 )

		values = { 'oid':oid, 'gid':gid, 'value':value }

		return self._do_insert( table=obj.dhcp_options_to_dhcp_groups, values=values )
		
	def add_domain_to_group( self, did, gid):
		'''
		Add a domain to a group
		@param did: the database domain ID
		@param gid: the database group ID
		'''
		
		# FIXME: more granular permissions?
		self.require_perms(perms.DEITY)
		
		return self._do_insert(table=obj.domains_to_groups, values={'did' : did,'gid' : gid,})
		
	
	def add_guest_ticket( self, ticket, starts, ends, description=None ):
		"""
		Adds a guest ticket to the database and associate it to this user
		
		@param starts: the start datetime
		@param ends: the end datetime
		@return: the row added ResultProxy object
		"""
		
		# Permissions, non-restrictive at all
		# No permissions for guest tickets, free game
		
		values={'uid' : self._uid,
				'ticket' : ticket,
				'starts' : starts,
				'ends' : ends,
				'description' : description }

		return self._do_insert(table=obj.guest_tickets, values=values)
			
	
	def add_group( self, name, description=None ):
		"""
		Add a group
		@param name: the group name
		@param description: a description of the group
		"""
		
		# Check permissions
		if not self._is_user_in_group(gid=backend.db_service_group_id):
			self.require_perms( perms.DEITY, "Only super admins can add new groups" )

		# Do this INSERT no matter what authentication source
		return self._do_insert(table=obj.groups, values={'name' : name,'description' : description,})
		
	def __find_next_mac(self, mac):
		if mac.lower() == 'vmware':
			oui = '00:50:56:00:00:00'
		else:
			raise Exception("Don't know how to handle OUI: %s" % mac )

		# find the next unused MAC address in the vmware OUI -- FIXME: make a table of name,min_mac,max_mac to get this from
		q = self.get_hosts(mac=oui)
		if not q:
			return oui
		h = obj.hosts.alias('h')
		q = select(columns = [(obj.hosts.c.mac + 1).label('next'),], from_obj=obj.hosts).where(sqlalchemy.sql.func.trunc(obj.hosts.c.mac) == oui)
		sub_q =  sqlalchemy.sql.exists(whereclause=and_(h.c.mac == obj.hosts.c.mac + 1, sqlalchemy.sql.func.trunc(h.c.mac + 1) == oui))
		q = q.where(~sub_q)
		q = q.limit(1).order_by('next')
		results = self._execute(q)
		if not results:
			raise Exception('Did not find a usable MAC address?! mac: %s (oui: %s)'%(mac, oui))
		address = results[0][0]
		return address

	# FIXME: this function should require and id from expiration_types instead of an expiration date
	def add_host( self, mac, hostname, description=None, dhcp_group=None, expires=None ):
		"""Add a host
		@param mac: the new host's MAC address
		@param hostname: a valid hostname
		@param description: description
		@param dhcp_group: this host's DHCP group id, from dhcp_groups table, for DHCP options
		@param expires: an expiration date
		"""

		hostname = hostname.lower()
		
		if len(hostname) < 3:
			raise error.InvalidArgument("hostname (%s) is too short" % hostname)

		if re.search(r'\.arpa$',hostname):
			raise error.InvalidArgument("hostname (%s) appears to be in a reverse-lookup domain" % hostname)
		
		if not validation.is_mac(mac):
			mac = self.__find_next_mac(mac)
		
		if self.is_disabled(mac=mac):
			raise error.InvalidArgument('This host is disabled (mac: %s)' % mac)

		if dhcp_group:
			dhcp_group = int(dhcp_group)
		else:
			dhcp_group = None

		self._begin_transaction()
		try:
			# Check permissions
			if self.has_min_perms(perms.DEITY):
				# If I'm a DEITY, just let me add any hosts
				pass
			elif not self.get_domains(contains=hostname, additional_perms=perms.ADD):
				raise error.InsufficientPermissions("User %s doesn't have domain access to add host %s" % (self._username, hostname))
			
			
			# FIXME: think about the following flag del_extraneous being set to False here
			# In the current form, if you register a host with the same name or MAC as an expired
			# host, you'll get the expired host's DNS records.
			# If we do delete the expired host's DNS records, what would that hurt? I think nothing ...
			
			# If the host exists by mac, but is expired, delete old host
			host = self.get_hosts(mac=mac, show_expired=True, show_active=False)
			addresses = self.get_addresses(mac=mac)
			if host:
				if addresses:
					raise error.AlreadyExists("Static host with mac %s already exists.  Please renew or delete it via the openipam interface." % mac, mac = mac)
				else:
					self.del_host(mac=mac)
			
			host = self.get_hosts(hostname=hostname, show_expired=True, show_active=False)
			dns = self.get_dns_records(name=hostname)
			if host:
				raise error.AlreadyExists("Host with name %s already exists.  Please delete it first." % hostname, hostname = hostname)
			if dns:
				raise error.AlreadyExists("DNS record(s) with name %s already exist(s).  Please delete first." % hostname, hostname = hostname)
			
			values={
					'mac' : mac,
					'hostname' : hostname,
					'description' : description,
					'dhcp_group' : dhcp_group,
					'expires' : expires,
					'changed_by' : self._uid
					}
		
			result = self._do_insert(table=obj.hosts, values=values)
			
			self.add_host_to_group(mac, group_name="user_%s" % self._username)
				
			self._commit()
		except:
			self._rollback()
			raise
		
		return mac
	
	def add_host_to_group( self, mac, gid=None, group_name=None ):
		'''
		Add a host to a group
		
		@param mac: the host's mac address
		@param gid: the database group ID
		@param group_name: if not gid, give the group_name and gid will be determined
		'''


		# Get the gid if not given
		if not gid:
			if not group_name:
				raise error.RequiredArgument("Must pass exactly one of gid or group_name")
			
			query = self.get_groups(name=group_name)
			if not query:
				raise error.NotFound("No group found matching: %s" % group_name)
			else:
				gid = query[0]['id']
				
		self._begin_transaction()
		try:
			if self.get_hosts_to_groups(mac=mac):			
				# Require permissions over the host
				self._require_perms_on_host(permission=perms.ADMIN, mac=mac, error_msg="Couldn't add host %s to group %s, %s" % (mac, gid, group_name))
			
			# They have permission ... do the insert
			result = self._do_insert( table=obj.hosts_to_groups, values={'mac' : mac,'gid' : gid,} )
			
			# Commit the transaction
			self._commit()
		except:
			self._rollback()
			raise
		
		return result
	
	def assign_static_address(self, mac, hostname=None, network=None, address=None):
		"""
		Assign a static address from the addresses table to this mac from the
		specified network. This is a smart function, it will determine the available
		address and assign it.
		
		@param mac: required MAC address
		@param network: required when address is not specified - CIDR network
		@param address: an optional argument, which address to assign
		@return: the IP address that was assigned to this MAC

		"""
		if not network and not address:
			raise error.RequiredArgument('You must specify either a network or an address.')

		if address:
			address = openipam.iptypes.IP(address)
		if network:
			network = openipam.iptypes.IP(network)
		if (address and network):
			if address.version() != network.version():
				raise Exception('address family mismatch: %s, %s' % (address, network))
			if not (address in network):
				raise error.InvalidArgument('address %s does not belong to network %s' % (address, network))
			network = None # this information is useless to us... we have an address.
		ipv4 = (address and address.version() == 4) or (network and network.version() == 4)
		
		self._begin_transaction()
		try:
			if not self.has_min_perms(perms.ADD):
				if address:
					andwhere = obj.networks_to_groups.c.nid.op('>>=')(str(address))
				else:
					andwhere = obj.networks_to_groups.c.nid == str(network)
				net_perms = obj.perm_query( self._uid, self._min_perms, networks = True, required_perms = perms.ADD, do_subquery=False,
						andwhere=andwhere )
				net_perms = self._execute(net_perms)
			
				if not net_perms:
					raise error.InsufficientPermissions("Insufficient permissions to add a host to the %s network (address: %s)." % (network,address))
			
			query = select([obj.addresses.c.address], and_(and_(obj.addresses.c.mac == None, obj.addresses.c.pool == None), obj.addresses.c.reserved == False))

			if network:
				# FIXME: if ipv6, we don't really want to reuse these
				if ipv4:
					query = query.where(obj.addresses.c.address.op('<<')(str(network))).order_by(obj.addresses.c.address)
				else:
					query = query.where(False)

			if address:
				if ipv4:
					query = query.where(obj.addresses.c.address == str(address))
				else:
					query = query.where(False)

			
			addresses = self._execute(query)
			
			created = False

			if not addresses:
				# If no totally free addresses, steal one from a pool
				# FIXME: if we are using ipv6, autogenerate a new IP here.
				if ipv4:
					
					# Get all addresses and the leases if they exist
					from_object = obj.addresses.outerjoin(obj.leases, obj.addresses.c.address == obj.leases.c.address)
					
					# Filter all addresses to where MAC is none (address hasn't been assigned)
					# and don't return broadcast, network, gateway and other reserved IP addresses
					query = select([obj.addresses.c.address], from_obj=from_object).where( and_(obj.addresses.c.mac == None, obj.addresses.c.reserved == False) )

					# Only rob certain pools, since some have special meanings
					query = query.where( obj.addresses.c.pool.in_( backend.assignable_pools ) )
					
					if network:
						query = query.where(obj.addresses.c.address.op('<<')(str(network))).order_by(obj.addresses.c.address)
					
					# Only show expired or owned leases
					query = query.where(or_(or_(obj.leases.c.ends < sqlalchemy.sql.func.now(), obj.leases.c.ends == None),obj.leases.c.mac == mac))
					
					if address:
						query = query.where(obj.addresses.c.address == str(address))
					
					addresses = self._execute(query)
					
					if address and not addresses:
						raise error.NotFound("Could not assign IP address %s to MAC address %s.  It may be in use or not contained by a network." % (address, mac))
					
					if not addresses:
						raise error.NoFreeAddresses()
				else:
					# FIXME: how do we determine 'is_server'?  should we always use_lowest for a static address?
					ip6net = address if address else network
					address = self._assign_ip6_address(network=ip6net, mac=mac, use_lowest=True, is_server=True, dhcp_server_id = 0)
					address = str(address)
					created = True

				
			# If here, we have a list of usable addresses, pick one
			if not created:
				address = addresses[0]['address']

				self.update_address(address=address, mac=mac)
			
				# If claimed, delete any previous leases
				self._do_delete( table=obj.leases, where=obj.leases.c.address == address )
			
			# Add the A record for this static (also adds PTR)
			if hostname:
				# delete any ptr's
				# FIXME: this is a sign that something wasn't deleted cleanly... maybe we shouldn't?
				#self.del_dns_record(name=openipam.iptypes.IP(address).reverseName()[:-1])
				# FIXME: is it safe to delete other DNS records here?
				if ipv4:
					self.add_dns_record(name=hostname, tid=1, ip_content=address)
				else:
					self.add_dns_record(name=hostname, tid=28, ip_content=address)

			self._commit()
		except:
			self._rollback()
			raise

		return address
	
	def release_static_address(self, address, pool=False):
		"""
		Release a static address back into a dynamic pool.
		Deletes all A records of this address and PTR records.
		
		@param address: the IP address to release
		"""
		
		# Check permissions
		addresses = self.get_addresses(address=address)
		
		if not addresses:
			raise error.NotFound("No addresses returned in release_static_address for address %s" % address)
		
		# The MAC address associated with this IP address
		mac = addresses[0]['mac']

		if not self.has_min_perms(perms.DEITY):
			
			host = self.get_hosts(mac=mac)
			
			if not host:
				raise error.NotFound("No host found for MAC %s in release_static_address" % mac)
			
			# Require MODIFY over the host that is using this address
			self._require_perms_on_host(permission=perms.MODIFY, mac=mac, error_msg="Insufficient permissions to release static address %s for MAC %s" % (address, mac))
		
		if not address:
			raise error.RequiredArgument("address is required in release_static_address")
		
		self._begin_transaction()
		try:
			if pool is False:
				pool = backend.func_get_pool_id( address=address )
			
			# Delete all the PTR records for this address
			ptrrecord = openipam.iptypes.IP(address).reverseName()[:-1]
			ptrrecord = self.get_dns_records(name=ptrrecord)
			
			if ptrrecord:
				for rr in ptrrecord:
					self.del_dns_record(rid=rr['id'], mac=mac)
				
			# Delete the A records
			a_records = self.get_dns_records(address=address)
			
			for rr in a_records:
				self.del_dns_record(rid=rr['id'], mac=mac)

			result = self.update_address( address=address, pool=pool )
			
			self._commit()
		except:
			self._rollback()
			raise
		
		return result
		
		
	# FIXME: this function should require and id from expiration_types instead of an expiration date
	def register_host(self, mac, hostname, description=None, dhcp_group=None, expires=None, expiration_format=None, is_dynamic=None, add_ptr=True, owners=None, pool=None, network=None, add_host_to_my_group=True, address=None):
		"""
		Registers a host. This is a smart function, it calls many DB functions to do
		a full insert of a registration for a host.
		"""
		
		expires = self._finalize_expires(expires=expires, expiration_format=expiration_format)

		if not hostname:
			raise Exception("No hostname given: %s" % hostname)
		
		# If this is a dynamic host and no pool is specified, use the default pool
		if is_dynamic==True and pool is None:
			pool = backend.db_default_pool_id
			address = None

		if pool is not None and (network or address):
			raise error.InvalidArgument("Cannot assign a pool and an address: pool:%s,network:%s,address:%s" % (pool,network,address))

		if add_host_to_my_group and owners:
			raise error.NotImplemented("add_host_to_my_group must be False if owners is specified")
		
		self._begin_transaction()
		try:
			# Add the host, which will also add the host to my user group so that the following additions can happen.
			# See add_host_to_my_group code below for how deleting my host_to_group relation works
			result = self.add_host(mac=mac, hostname=hostname, description=description, dhcp_group=dhcp_group, expires=expires)
			mac = result
			
			# STATIC HOST
			if pool is None:
				# assign_static_address will check our args
				address = self.assign_static_address(mac=mac, hostname=hostname, network=network, address=address)
			
			# DYNAMIC HOST
			if pool:
				self.add_host_to_pool(mac=mac, pool_id=pool)
			
			self.make_notifications_for_host(mac=mac, expires=expires)
			
			my_usergroup = 'user_%s' % self._username
			
			# If not add_host_to_my_group, then delete the host from my group after all other actions are finished
			if not add_host_to_my_group:
				if not owners:
					raise error.InvalidArgument('Must specify owners if add_host_to_my_group is false.')
				self.del_host_to_group(mac=mac, group_name=my_usergroup)
				
			# Make sure I'm first in the owners list so that I have permissions
			# FIXME: document why
			if owners and my_usergroup in owners:
				owners.remove(my_usergroup)
				owners.insert(0, my_usergroup)
			
			# Add owners is specified
			if owners:
				for owner in owners:
					# Make sure it actually exists and is not ''
					if owner:
						self.add_host_to_group(mac=mac, group_name=owner)
						
			# Commit the transaction
			self._commit()
		except Exception, e:
			self._rollback()
			raise
		
		return result
			
		
	def add_internal_auth( self ):
		"""internal_auth"""
		raise Exception('This functionality is provided by DBAuthInterface.create_internal_user(...)')
		
	def update_network( self, network, new_network=None, pool=False, **kw ):
		# Check permissions
		self.require_perms(perms.DEITY)

		kw['changed_by'] = self._uid
		if kw.has_key('changed'):
			raise Exception("Naughty!")

		for k in kw.keys():
			if k not in obj.networks.c:
				raise Exception("Invalid column for networks: %s" % k)

		if new_network:
			kw['network'] = new_network
			addr = openipam.iptypes.IP(new_network)
			if addr.family == 6 and not backend.allow_ipv6:
				raise error.InvalidArgument('IPv6 support is disabled in backend configuration.')
			del addr

			# Add all addresses from this network into the addresses table
			net = openipam.iptypes.IP(new_network)
			ip4 = net.version() == 4
			if not ip4 and net.prefixlen() != 64:
				raise Exception('Are you really trying to allocate a network that isn\'t a /64?')
			if pool and not ip4:
				raise Exception('Pools are only used for IPv4 addresses; net=%s' % net)
		
		# Check if this network overlaps with another network
		self._begin_transaction()
		try:
			if new_network:
				query = select([obj.networks.c.network], or_(obj.networks.c.network.op("<<=")(new_network), obj.networks.c.network.op(">>")(new_network)))
				result = self._execute(query)

				if len(result) != 1:
					raise Exception("I can't do what you want: %s" % result)

				net = openipam.iptypes.IP(new_network)
				old_net = openipam.iptypes.IP(network)
				if not old_net in net:
					raise Exception("Cannot change network %s to %s.  Network must be a strict subset of new_network." % (network, new_network))
				
			result = self._do_update(table=obj.networks, where=obj.networks.c.network == network, values=kw)

			# new network must contain old network
			if new_network:
				invalid = [ net[0], net[backend.default_gateway_address_index], net.broadcast(), ] # mark gateways as reserved, although we should assign the mac of the router

				if ip4:
					for address in net:
						# FIXME: probably should un-reserve the old gateway, etc. if necessary
						if address not in old_net:
							if (address not in invalid) or (net.prefixlen() >= 31):
								# If address is not invalid or in a /31 or /32, add the address as unreserved
								# otherwise we would end up with no available addresses
								if pool == False:
									addr_pool = backend.func_get_pool_id( address )
								else:
									addr_pool = pool
								self.add_address( address = str( address ), network=new_network, pool = addr_pool )
							else:
								self.add_address( address = str( address ), network=new_network, pool = None, reserved=True )
				else:
					# FIXME: IPv6: reserve our router/network addresses here
					for address in invalid:
						self.add_address(address=address, network=network, reserved=True)
				
			self._commit()
		except:
			self._rollback()
			raise
		
		return result
		

	def add_network( self, network, name=None, gateway=None, description=None, dhcp_group=None, pool=False, shared_network=None ):
		"""Add a network
		@param network: a CIDR network mask
		@param name: a string name for this network
		@param gateway: an IP address of the gateway for this network
		@param description:	a description for this name
		@param dhcp_group: the ID of a DHCP group
		@param pool: the ID of a pool, None for NULL, False for auto-generated from config (default)
		@param shared_network: the ID of a shared network
		"""

		# Check permissions
		self.require_perms(perms.DEITY)

		addr = openipam.iptypes.IP(network)
		if addr.family == 6 and not backend.allow_ipv6:
			raise error.InvalidArgument('IPv6 support is disabled in backend configuration.')
		del addr

		# Add all addresses from this network into the addresses table
		net = openipam.iptypes.IP(network)
		ip4 = net.version() == 4
		if not ip4 and net.prefixlen() != 64:
			raise Exception('Are you really trying to allocate a network that isn\'t a /64?')
		if pool and not ip4:
			raise Exception('Pools are only used for IPv4 addresses. net: %s' % net)
			
		
		# Check if this network overlaps with another network
		self._begin_transaction()
		try:
			query = select([obj.networks.c.network], or_(obj.networks.c.network.op("<<=")(network), obj.networks.c.network.op(">>")(network)))
			result = self._execute(query)
			
			if result:
				raise error.AlreadyExists('Unable to add network %s because of overlap with existing network %s' % (network, str(result[0])))
			if not gateway:
				gateway = str( net[backend.default_gateway_address_index] )
			
			values={'network' : network,
					'name' : name,
					'gateway' : gateway,
					'description' : description,
					'dhcp_group' : dhcp_group,
					'shared_network' : shared_network,
					#'broadcast' : broadcast,
					'changed_by' : self._uid }
			result = self._do_insert(table=obj.networks, values=values)
			
			if ip4:
				invalid = [ net[0], net[backend.default_gateway_address_index], net.broadcast(), ] # mark gateways as reserved, although we should assign the mac of the router
				for address in net:
					if (address not in invalid) or (net.prefixlen() >= 31):
						# If address is not invalid or in a /31 or /32, add the address as unreserved
						# otherwise we would end up with no available addresses
						if pool == False:
							addr_pool = backend.func_get_pool_id( address )
						else:
							addr_pool = pool
						self.add_address( address = str( address ), network=network, pool = addr_pool )
					else:
						self.add_address( address = str( address ), network=network, pool = None, reserved=True )
			else: #ipv6
				router_index = 1
				if hasattr(backend,"devault_gateway_address_index_v6"):
					router_index = backend.devault_gateway_address_index_v6
				invalid = [ net[0], net[router_index], ]

				# FIXME: IPv6: reserve our router/network addresses here
				for address in invalid: # we do sparse addressing for ipv6.  This is very important.
					self.add_address(address=address, network=network, reserved=True)
			
			self._commit()
		except:
			self._rollback()
			raise
		
		return result
		
	def add_network_to_group( self, nid, gid ):
		'''Add a network to a group
		@param nid: the database network ID
		@param gid: the database group ID'''
		
		# Check permissions
		self.require_perms(perms.DEITY)
		
		return self._do_insert(table=obj.networks_to_groups, values={'nid' : nid,'gid' : gid,})
	
	def add_notification_to_host( self, nid, mac ):
		"""
		Add a notification type to a host
		
		@param nid: the database notification ID
		@param mac: the database host mac
		"""
				
		self._begin_transaction()
		try:
			if self.get_hosts_to_groups(mac=mac):
				self._require_perms_on_host(permission=perms.ADMIN, mac=mac)
			
			# They have permission ... do the insert
			result = self._do_insert(table=obj.notifications_to_hosts, values={'nid' : nid,'mac' : mac,})
			
			# Commit the transaction
			self._commit()
		except:
			self._rollback()
			raise
		
		return result
	
	def add_permission( self ):
		"""permission"""
		pass
	
	def add_shared_network( self, name, description=None):
		"""
		Add a shared network to the database
		
		@param name: a required name for this shared network
		@param description: an optional description for this shared_network
		"""
		# Check permissions
		self.require_perms(perms.DEITY)
		
		return self._do_insert(table=obj.shared_networks, values={'name' : name,'description' : description})
		
	
	def add_supermaster( self ):
		"""supermaster"""
		pass
	
	
	def add_user_to_group( self, uid, gid, permissions, host_permissions=None ):
		'''Add a user to a group
		@param info: a dictionary of information for the bridge relation'''

		# Check permissions
		if not self._is_user_in_group(gid=backend.db_service_group_id):
			self.require_perms(perms.DEITY)
		
		values={
			'uid' : uid,
			'gid' : gid,
			'permissions' : permissions,
			'changed_by' : self._uid,
			'host_permissions' :  backend.default_host_permissions
		}
		
		if host_permissions is not None:
			values['host_permissions'] = str(host_permissions)
		
		return self._do_insert(table=obj.users_to_groups, values=values)
	
	def add_vlan( self ):
		"""vlan"""
		pass
		
	def add_vlan_to_group( self ):
		"""vlan_to_group"""
		pass
		
	def del_host_to_pool( self, mac, pool_id=None ):
		"""
		Give the host permission to get addresses from pool
		"""
		if not self.has_min_perms( perms.DELETE ):
				self._require_perms_on_host(permission=perms.DELETE, mac=mac, error_msg="Insufficient permissions to delete pool membership for MAC %s" % mac)
		where = obj.hosts_to_pools.c.mac == mac
		if pool_id:
			where = and_(where, obj.hosts_to_pools.c.pool_id == pool_id)
		return self._do_delete( table=obj.hosts_to_pools, where=where )

	def del_attribute( self ):
		"""attribute"""
		pass
		
	def del_attribute_to_host( self ):
		"""attribute_to_host"""
		pass
		
	def del_attribute_value( self ):
		"""attribute_value"""
		pass
		
	def del_auth_source( self ):
		"""auth_source"""
		pass

	def del_dhcp_option( self ):
		"""dhcp_option"""
		pass
		
	def del_dhcp_group( self, gid ):
		"""Delete a DHCP group"""
		pass
		
	def del_dns_record( self, rid=None, did=None, mac=None ):
		"""
		Delete a DNS record
		
		@param rid: the ID of the row in dns_records
		"""
		
		# TODO: now that we have find_permissions_for_dns_records, re-write this function
		# to not accept a mac address (and find all the places that are calling this)
		
		if rid is not None and did is not None:
			raise error.InvalidArgument('del_dns_records only accepts one of (did=%s, rid=%s)' % (did,rid))

		if did is not None:
			self.require_perms(perms.DEITY)
			where=obj.dns_records.c.did == int(did)

		else:
			records = self.get_dns_records(id=rid, did=did)
			
			if not records:
				raise error.NotFound("Couldn't delete DNS record id %s because it could not be found." % rid)
		
			record = records[0]
		
			# If MAC is not specified, require DEITY
			if not mac:
				id_perms = self.find_permissions_for_dns_records(records)[0]
				
				if Perms(id_perms[rid]) & perms.DELETE != perms.DELETE:
					raise error.InsufficientPermissions("Insufficient permissions to delete DNS record %s %s" % (rid, record['name']))
			else:
				# Require DELETE permissions if MAC is specified
				self._require_perms_on_host(permission=perms.DELETE, mac=mac, error_msg="Insufficient permissions to delete DNS records for MAC %s" % mac)
			
			where = obj.dns_records.c.id==rid

			# If it was an A Record, delete the associated PTR (without permissions checking)
			if record['tid'] == 1:
				ptr = self.get_dns_records(name=openipam.iptypes.IP(record['ip_content']).reverseName()[:-1], content=record['name'])
				
				if ptr:
					where = or_(where, (obj.dns_records.c.id==ptr[0]['id']))

		return self._do_delete( obj.dns_records, where=where )
	
	def del_dns_type( self ):
		"""dns_type"""
		pass
		
	def del_dns_view( self ):
		pass
	
	def del_domain( self, did ):
		"""domain"""
		self.require_perms(perms.DEITY)
		where = obj.domains.c.id == int(did)
		return self._do_delete( table=obj.domains, where=where )
	
	def del_domain_to_group( self, did, gid ):
		"""Remove a domain from a group
		@param did: the domain database id
		@param gid: the group database id"""
		
		# Check permissions
		self.require_perms(perms.DEITY)
		
		where = and_(obj.domains_to_groups.c.did==did, obj.domains_to_groups.c.gid==gid)
		
		return self._do_delete( table=obj.domains_to_groups, where=where )
		
	def del_dhcp_option_to_group( self, rid, gid ):
		"""Remove a DHCP option from a DHCP group
		@param rid: the option relation id (NOT the option's ID, because gid+oid is not unique in this table) 
		@param gid: the group database id"""
		pass
	
	def del_dhcp_dns_record(self, name=None, ip=None, network=None):
		"""
		Delete a DHCP DNS record based on its name or IP address
		"""

		# normal users shouldn't be calling this...
		self.require_perms(perms.DEITY)
		
		if (bool(name) + bool(ip) + bool(network)) != 1:
			raise error.RequiredArgument("Specify exactly one of name or IP address or network")
		
		if ip:
			where = obj.dhcp_dns_records.c.ip_content==ip
		if name:
			where = obj.dhcp_dns_records.c.name==name
		if network:
			where = obj.dhcp_dns_records.c.ip_content.op('>>')(network)
		
		return self._do_delete( table=obj.dhcp_dns_records, where=where )

	def del_guest_ticket( self, ticket ):
		"""
		Delete a guest ticket
		
		@param ticket: get the information related to this ticket name
		@return: the delete resultproxy
		"""
	
		if not self.has_min_perms(perms.DEITY):
			# I'm not a DEITY and I'm trying to delete a ticket
			
			my_ticket = self.get_guest_tickets(ticket=ticket)
			
			if not my_ticket:
				raise error.NotFound("Ticket to delete was not found")
			
			if my_ticket[0]['uid'] != self._uid:
				raise error.InsufficientPermission("Cannot delete another person's ticket")
		else:
			my_ticket = self.get_guest_tickets(ticket=ticket)
		
			if not my_ticket:
				raise error.NotFound("Ticket to delete was not found")
			
		where = obj.guest_tickets.c.id == my_ticket[0]['id']
		 
		return self._do_delete( table=obj.guest_tickets, where=where )

	def del_group( self, gid ):
		"""
		Delete a group
		@gid: the database group ID
		"""
		
		# Check permissions
		self.require_perms(perms.DEITY)
		
		where = obj.groups.c.id==gid
		
		return self._do_delete( table=obj.groups, where=where )
	
	def del_host( self, mac ):
		"""
		Delete a host. Relations of this host to groups will cascade delete.
		
		Doesn't currently delete all associated DNS records, but will in v1.5 or 2
		
		@param mac: MAC address of host
		@param del_extraneous: remove all associated DNS records and release associated addresses
		"""

		if not mac:
			raise error.InvalidArgument('Invalid MAC address: %s' % mac)
		
		if self.is_disabled(mac=mac):
			raise error.InvalidArgument('This host is disabled (mac: %s)' % mac)

		self._begin_transaction()
		try:
			host = self.get_hosts(mac=mac, show_expired=True, show_active=True, columns=[obj.hosts, (obj.hosts.c.expires < sqlalchemy.sql.func.now()).label('expired')])
			
			if host:
				if not host[0]['expired']:
					self._require_perms_on_host(permission=perms.DELETE, mac=mac)
				
				# Addresses to release
				release_addresses = self.get_addresses(mac=mac)
				
				for addr in release_addresses:
					self.release_static_address(address=addr['address'])
				
				self.del_dhcp_dns_record( name = host[0]['hostname'] )

				# Delete the DNS records associated with the old static host
				dns_records = self.get_dns_records( mac=mac )
				
				for rr in dns_records:
					try:
						self.del_dns_record(rid=rr['id'], mac=mac)
					except error.NotFound:
						# FIXME: this may not be the best way, but catch the case where a PTR
						# has already been deleted by del_dns_record, but we still have it in this list
						pass
					
				where = obj.hosts.c.mac==mac
			else:
				raise error.NotFound("Couldn't find host to delete. MAC: %s " % mac)
			
			result = self._do_delete( table=obj.hosts, where=where )
			
			self._commit()
		except:
			self._rollback()
			raise
		
		return result
	
	def del_host_attribute( self, aid ):
		"""Delete a host attribute"""
		pass
	
	def del_host_to_group( self, mac, gid=None, group_name=None ):
		"""
		Remove a host from a group
		
		@param mac: the host database id
		@param gid: the group database id
		@param group_name: the database group name if gid is unknown
		"""
		
		# Check permissions
		self._require_perms_on_host(permission=perms.ADMIN, mac=mac, error_msg="Cannot delete host to group relation for host %s in group %s, %s" % (mac, gid, group_name))
			
		whereclause = obj.hosts_to_groups.c.mac == mac
		
		if not gid and not group_name:
			# Require DEITY permissions to delete all host_to_group relations
			self.require_perms(perms.DEITY, "You do not have permission to delete multiple host to group relations")
		
		if gid:
			whereclause = and_(whereclause, obj.hosts_to_groups.c.gid==gid)
		if group_name:
			gid = self.get_groups(name=group_name)[0]['id']
			whereclause = and_(whereclause, obj.hosts_to_groups.c.gid==gid)
		
		return self._do_delete( table=obj.hosts_to_groups, where=whereclause )
	
	
	def del_internal_auth( self ):
		"""internal_auth"""
		pass
		
	
	def del_network( self, network ):
		"""Delete a network and all associated addresses"""
		
		# Check permissions
		self.require_perms(perms.DEITY)
		
		self._begin_transaction()
		try:
			nets = self.get_networks(network=network)
			if len(nets) != 1:
				raise error.NotFound('%d networks found matching %s -- not deleting' % (len(nets),network) )

			# Delete all addresses that were in this network
			self._do_delete( table=obj.addresses, where=obj.addresses.c.address.op("<<")(network) )
			
			# Delete the network
			where = obj.networks.c.network == network
			result = self._do_delete( table=obj.networks, where=where )
			
			self._commit()
		except:
			self._rollback()
			raise
		
		return result
	
	def del_network_to_group( self, nid, gid  ):
		"""
		Remove a network from a group
		
		@param nid: the network database id
		@param gid: the group database id
		"""
				
		# FIXME: these permissions should probably be more granular
		# Check permissions
		self.require_perms(perms.DEITY)

		where = and_(obj.networks_to_groups.c.nid == nid,
				obj.networks_to_groups.c.gid == gid)

		return self._do_delete(table=obj.networks_to_groups, where=where,)
	
	def del_notification_to_host( self, id=None, mac=None ):
		"""
		Remove a notification applied to a host	( a row in the notifications_to_hosts table)
		
		@param id: the relation ID
		"""
		
		if id and not self.has_min_perms(perms.DEITY):
			raise error.InsufficientPermissions("Must be DEITY to specify ID of notification on host to remove")
		
		# FIXME: do we need to do this if here? or just the require permissions
		if not self.has_min_perms(perms.DEITY) and mac and self.get_hosts_to_groups(mac=mac):
			self._require_perms_on_host(permission=perms.ADMIN, mac=mac)

		where = None
					
		if id:
			if type(id) == types.ListType:
				where = obj.notifications_to_hosts.c.id.in_(id)
			else:
				where = obj.notifications_to_hosts.c.id==id
		elif mac:
			where = obj.notifications_to_hosts.c.mac==mac
		else:
			raise error.RequiredArgument("Must specify exactly one of id or mac to del_notification_to_host")
		
		return self._do_delete( table=obj.notifications_to_hosts, where=where )
		
	def del_supermaster( self ):
		"""supermaster"""
		pass
	
	def del_user( self, uid ):
		"""Delete a user. If that user is an internal user account, the delete will cascade to internal_auth
		@param uid: the database user ID"""
		
		raise error.NotImplemented('This action is not currently supported.')
		# Check permissions
		self.require_perms(perms.DEITY)
		
		where = obj.users.c.id==uid
		
		return self._do_delete( table=obj.users, where=where )
	
	def del_lease( self, address=None, mac=None ):
		"""Delete a lease ... this function is probably going away"""
		
		# Check permissions
		self.require_perms(perms.DEITY)
		
		if not address and not mac:
			raise error.RequiredArgument("Need one of address or mac in del_lease")
		
		if address:
			where = obj.leases.c.address==address
		if mac:
			where = obj.leases.c.mac==mac
		
		return self._do_delete( table=obj.leases, where=where )
	
	def del_user_to_group( self, uid, gid ):
		"""Remove a user from a group
		@param uid: the user database id
		@param gid: the group database id"""
		
		
		# FIXME: these permissions should probably be more granular
		# Check permissions
		self.require_perms(perms.DEITY)
		
		where = and_(obj.users_to_groups.c.uid==uid, obj.users_to_groups.c.gid==gid)
		
		return self._do_delete( obj.users_to_groups, where=where )
		
	
	def make_notifications_for_host(self, mac, expires):
		"""
		Makes sure that the state of notifications on a host is up-to-date
		"""
		
		# Require MODIFY permissions if not DEITY
		if not self.has_min_perms(perms.DEITY):
			self._require_perms_on_host(permission=perms.MODIFY, mac=mac, error_msg="Could not make_notifications_for_host(%s, %s)" % (mac, expires))
		
		# Delete all the notifications on this host
		self.del_notification_to_host(mac=mac)
		
		# Add all of the default notifications for this host
		notification_types = self.get_notifications()
		
		for notify_type in notification_types:
			# Don't add notifications to hosts if the notification should have happened already
			if datetime.datetime.fromtimestamp(time.time()) + notify_type['notification'] < expires:
				self.add_notification_to_host(notify_type['id'], mac)
	
	# FIXME: this function should require and id from expiration_types instead of an expiration date
	def update_host( self, old_mac, mac=None, hostname=None, description=None, expires=None, dhcp_group=None, expiration_format=None ):
		"""
		Update a host record ... just a host record.
		No arguments are required except for old_mac ... whatever is passed in
		will be updated, the rest will remain the same
		"""
		
		values = {}

		if self.is_disabled(mac=old_mac):
			raise error.InvalidArgument('This host is disabled (mac: %s)' % old_mac)

		# Always very important
		if hostname:
			hostname = hostname.lower()

		if not old_mac:
			raise error.InvalidArgument('Invalid MAC address for old_mac: %s' % old_mac)

		if dhcp_group:
			dhcp_group = int(dhcp_group)
		else:
			dhcp_group = None

		# Allow setting DHCP group to NULL
		values['dhcp_group'] = dhcp_group
		
		# Require MODIFY permissions if not DEITY
		if not self.has_min_perms(perms.DEITY):
			self._require_perms_on_host(permission=perms.MODIFY, mac=old_mac)
		
		expires = self._finalize_expires(expires=expires, expiration_format=expiration_format)
		
		# If any argument is set, put it in the values that will be changed
		# Doing a for loop instead of if mac: values['mac'] = ..., if hostname: values['hostname'] = ... for every one
		# Because Python is just cool like that
		args = locals()
		for arg in ('mac', 'hostname', 'dhcp_group', 'description', 'expires'):
			if args.has_key(arg) and args[arg] != None:
				values[arg] = args[arg]
		
		values['changed'] = sqlalchemy.sql.func.now()
		values['changed_by'] = self._uid
		
		# Update the host
		results = self._do_update(table=obj.hosts, where=obj.hosts.c.mac == old_mac, values=values )
			
		# If we change expires, make sure notifications on the host are up-to-date
		if expires:
			self.make_notifications_for_host(mac=(mac if mac else old_mac), expires=expires)
			
		return results 
	
	# FIXME: this function should require and id from expiration_types instead of an expiration date
	# FIXME: trash this function and replace it with smaller ones.
	def change_registration( self, old_mac, mac=None, hostname=None, description=None,
			expires=None, expiration_format=None, is_dynamic=True, network=None,
			address=None, owners=None, dhcp_group=None, pool=None ):
		"""
		The continuation of register_host ... this is a smart function that will update
		everything required if a registration needs to change.
		
		No arguments are required except for old_mac ... whatever is passed in
		will be updated, rest will remain the same
		"""
		
		# ------------- TODO: MAKE SURE we're updating all the DNS records correctly (A records work, what about MX? others?)
		
		# Check permissions
		required_perms = perms.MODIFY
		# Require the ADMIN flag to change permissions
		# FYI: handled by set_owners_for_host(...)
		#if owners:
		#	required_perms = perms.OWNER

		if is_dynamic and pool is None:
			pool = backend.db_default_pool_id

		if address and network:
			network = openipam.iptypes.IP(network)
			if address in network:
				network = None
			else:
				raise error.InvalidArgument('The address %s does not belong to the network %s' % (address, str(network)) )
				
		self._require_perms_on_host(permission=required_perms, mac=old_mac)
		
		# Always very important
		if hostname:
			hostname = hostname.lower()
		
		expires = self._finalize_expires(expires=expires, expiration_format=expiration_format)
		
		self._begin_transaction()
		try:
			# Get the old_host for reference
			old_host = self.get_hosts(mac=old_mac)
			
			if not old_host:
				raise error.NotFound("change_registration could not find the host %s to update" % old_mac)
			old_host = old_host[0]
			
			# If this host was in any pools, we know it was dynamic
			tmp_pool = self.get_hosts_to_pools( mac=old_mac )
			if len(tmp_pool)>1:
				raise Exception("Host has multiple pools assigned, cannot use register_host()")

			old_pool = None
			if tmp_pool:
				old_pool = tmp_pool[0]['pool_id']
			
			# Ahh...hello states
			if pool is not None and old_pool is None:
				if pool is None:
					pool = backend.db_default_pool_id
				# FIXME: maybe this should be an unsupported action...  Deleting the host is not an expected behavior
				#raise error.NotImplemented('You should delete and re-create the host instead')

				# STATIC REGISTRATION ---> DYNAMIC REGISTRATION
					
				# Check for any unusual records that might be missed (ie. A/PTR don't match hostname, CNAME, etc)
				former_addresses = self.get_addresses( mac=old_host['mac'] )
				if len(former_addresses) != 1:
					raise error.NotImplemented(
							'Host has multiple addresses or inconsistent data.  Delete and re-create it to convert to dynamic. addresses: %s' % ', '.join([a['address'] for a in former_addresses]))
				former_address = openipam.iptypes.IP(former_addresses[0]['address'])
				dns_records = self.get_dns_records(mac=old_host['mac'])
				nonstandard_records = []
				for record in dns_records:
					if record['tid'] == 1: # A
						if (record['name'] != old_host['hostname']
								or openipam.iptypes.IP(record['ip_content']) != former_address):
							nonstandard_records.append(record)
					elif record['tid'] == 12: # PTR
						if (record['name'] != former_address.reverseName()[:-1]
							or record['text_content'] != old_host['hostname']):
							nonstandard_records.append(record)
					else:
						# Anything else is not recognized (CNAME, etc).
						nonstandard_records.append(record)

				if len(nonstandard_records) > 0:
					raise error.NotImplemented( "Host has non-standard DNS records.  Either delete the records or delete and re-create the host: %s" %
						', '.join( [ "id: %(id)s name: %(name)s tid: %(tid)s text_content: %(text_content)s ip_content: %(ip_content)s" % r for r in nonstandard_records] ) )

				deleted = set()
				for r in dns_records:
					if r['id'] not in deleted:
						if r['tid'] == 12: # PTR
							# this may have been deleted with the A record
							oldptr = self.get_dns_records(id=r['id'])
							if len(oldptr) == 0:
								deleted.add(r['id'])
								continue
						self.del_dns_record(rid = r['id'])
						deleted.add(r['id'])

				self.release_static_address(address=str(former_address))

				self.add_host_to_pool(mac=old_host['mac'], pool_id=pool)

				self.update_host(old_mac=old_mac, mac=mac, hostname=hostname, description=description, expires=expires, expiration_format=expiration_format, dhcp_group=dhcp_group)
				
			elif pool is not None and old_pool is not None:
				# STAYING DYNAMIC REGISTRATION
				
				# Update the host row information
				if pool != old_pool:
					self.del_host_to_pool(mac=old_mac)
					self.add_host_to_pool(mac=old_mac,pool_id=pool)
				self.update_host(old_mac=old_mac, mac=mac, hostname=hostname, description=description, expires=expires, expiration_format=expiration_format, dhcp_group=dhcp_group)
				
			elif pool is None and old_pool is not None:
				# FIXME: Deleting the host is not an expected behavior.

				# DYNAMIC REGISTRATION ---> STATIC REGISTRATION
				
				# Delete the host in its entirety
				self.del_host(mac=old_mac)
				
				# If anything wasn't specified, use the old host's data
				mac = mac if mac else old_mac
				hostname = hostname if hostname else old_host['hostname']
				description = description if description else old_host['description']
				expires = expires if expires else old_host['expires']
				
				self.register_host(mac=mac, hostname=hostname, description=description, expires=expires, is_dynamic=False, pool=pool, owners=owners, add_host_to_my_group=False, network=network, address=address )
				
			elif pool is None and old_pool is None:
				# STAYING STATIC REGISTRATION

				# Are we changing the IP address?
				if address or network:
					# ----------------------------------------
					# ------- FIXME: what if I only want to update ONE IP address on a host?
					# Addresses to release
					host_addresses = self.get_addresses(mac=old_mac)
					
					if not host_addresses:
						raise error.NotFound("Couldn't find address(es) to release for this host")
					
					if len(host_addresses) > 1:
						raise error.NotImplemented("Cannot change IP address on a host with multiple IPs via this function: %s" % host_addresses)
					
					#self.assign_static_address(mac=mac, hostname=hostname, network=network, address=address)
					self.change_address(mac=old_mac, old_address=host_addresses[0]['address'], address=address, network=network)
					# If the previous worked, we have permission to mess with that address.  It shouldn't be a problem
					#  to directly modify DNS at this point.
					
					# We don't care about the network, really... let assign_static_address worry about that
					#if not network:
					#	network = self.get_networks(address=address)
					#	if not network:
					#		raise error.NotFound("Couldn't find appropriate network for specified address %s" % address)
					#	network = network[0]['network']
					
					# If anything wasn't specified, use the old host's data
					mac = mac if mac else old_mac
					hostname = hostname if hostname else old_host['hostname']
					
					# Update the host row information
					self.update_host(old_mac=old_mac, mac=mac, hostname=hostname, description=description, expires=expires, expiration_format=expiration_format, dhcp_group=dhcp_group)
					
					# Done changing IP address
				else:
					# Not changing the IP address
					
					# Update the host row information
					self.update_host(old_mac=old_mac, mac=mac, hostname=hostname, description=description, expires=expires, expiration_format=expiration_format, dhcp_group=dhcp_group)
					
				if hostname:
					# FIXME: does this fix any PTRs that might exist?
					# Updating the hostname, make sure to update the associated DNS records
					a_records = self.get_dns_records(mac=(mac if mac else old_mac), tid=1, name=old_host['hostname'])
					
					for rr in a_records:
						self.update_dns_record(mac=(mac if mac else old_mac), old_address=rr['ip_content'], address=(address if address else None), old_name=rr['name'], name=hostname)
				
			# At this point, the MAC address has been updated if it's changed ... so let's set the variable for future use
			mac = (mac if mac else old_mac)

			
			# Update owners in every state if it is specified
			if owners:
				self.set_owners_for_host(mac=mac, owner_names=owners)

			self._commit()
		except:
			self._rollback()
			raise

	def set_owners_for_host(self, mac, owner_ids=None, owner_names=None):
		self._require_perms_on_host(mac=mac, permission=perms.OWNER)

		if ( (owner_ids == None and owner_names == None)
				or not (owner_ids == None or owner_names == None) ):
			raise error.InvalidArgument("Must specify exactly one of (owner_ids, owner_names) = (%s,%s)" % (owner_ids,owner_names) )

		if not owner_ids:
			new_owner_ids = set()
			for name in owner_names:
				if name:
					g = self.get_groups(name=name)
					try:
						new_owner_ids.add( int(g[0]['id']) )
					except:
						raise Exception("No match for %s (owner_names: %s)" % (name, ', '.join(owner_names)))
		else:
			new_owner_ids = set(owner_ids)


		# Find which owners have been deleted or added
		old_owners = self.get_hosts_to_groups(mac=mac)
		old_owner_ids = set([int(row['gid']) for row in old_owners])

		if not new_owner_ids:
			raise error.InvalidArgument("Host must have at least one owner -- mac: %s owners: %s" % (mac,owners))

		print new_owner_ids, old_owner_ids
		# Wow, there's got to be a more pythonic way of doing this. Anyone?
		for new_owner in new_owner_ids.difference(old_owner_ids):
			print "adding %s" % new_owner
			# Make sure it actually exists and is not ''
			self.add_host_to_group(mac=mac, gid=new_owner)
		for old_owner in old_owner_ids.difference(new_owner_ids):
			print "deleting %s" % old_owner
			self.del_host_to_group(mac=mac, gid=old_owner)

	def update_dhcp_group( self, gid, name, description ):
		'''Update a DHCP Group's information
		@param gid: the database group id
		@param name: the group's name
		@param description: the group's description'''
		pass
	
	def change_address( self, mac, old_address, address=None, network=None ):
		if (address and network) or (not address and not network):
			raise error.InvalidArgument('Please specify exactly one of address(%s) and network(%s)' % (address,network))
		if not self._min_perms == perms.DEITY:
			# FIXME
			# First, make sure old_address belongs to this MAC
			oldaddr = self.get_addresses(mac=mac, address=old_address)
			if len(oldaddr) != 1:
				raise error.NotFound("old_address (%s) and mac (%s) are not associated" % (old_address,mac,))
			# update_addresses should make sure that address is available
			#newaddr = self.get_addresses(mac=None, address=new_address)
			#if len(newaddr) != 1:
			#	raise error.NotFound("new address (%s) is in use or does not exist in the database" % (new_address))
			# update_addresses should make sure we are allowed access to new_address, so we won't worry about it here
		self._begin_transaction()
		try:
			new_address = self.assign_static_address(address=address,network=network,mac=mac)

			# UPDATE dns_records SET ip_content=new_address WHERE ip_content=old_address;
			values = { 'ip_content':new_address, }
			self._do_update(table=obj.dns_records, where=obj.dns_records.c.ip_content == old_address, values=values)
			
			# FIXME: Find the old PTR, add an equivalent one
			old_ptr = self.get_dns_records( name = openipam.iptypes.IP(old_address).reverseName()[:-1], typename='PTR')
			if len(old_ptr) != 1:
				raise Exception('Something is wrong with your PTR: %s' % old_ptr)
			old_ptr = old_ptr[0]
			# Delete the old PTR and dump the old address so we don't have a conflict
			self.release_static_address(address=str(old_address))

			self.add_dns_record( name=openipam.iptypes.IP(new_address).reverseName()[:-1], tid=old_ptr['tid'], text_content=old_ptr['text_content'] )
			
			self._commit()
		except:
			self._rollback()
			raise

	def update_dns_record( self, mac=None, old_address=None, address=None, old_name=None, name=None ):
		"""
		Update a DNS record on a host
		
		@param old_address: the old IP address
		@param address: the new IP address
		"""

		# TODO: Update did on record change

		# FIXME: implement updating of other RR types
		# If MAC is not specified, require DEITY
		if not mac:
			self.require_perms(perms.DEITY)
		else:
			# Require MODIFY permissions if MAC is specified
			self._require_perms_on_host(permission=perms.MODIFY, mac=mac, error_msg="Insufficient permissions to update DNS records for MAC %s" % mac)
		
		values = {}
		
		if (old_name and not name) or (not old_name and name):
			# Make sure that we update only the intended record
			raise error.RequiredArgument("If old_name or name are specified, both must be given.")
		
		self._begin_transaction()
		try:
			if old_address:
				# Updating an A record and PTR
				
				# A record
				
				if address:
					# Updating the hosts A record address
					values['ip_content'] = address
				
				if name:
					values['name'] = name
				
				dnswhere = and_(obj.dns_records.c.ip_content == old_address, obj.dns_records.c.name==old_name)

				if address:
					dnswhere = and_(dnswhere, obj.dns_records.c.ip_content == old_address)
		
				self._do_update(table=obj.dns_records, where=dnswhere, values=values)
				
				# PTR record
				values = {}
				
				if address:
					# Updating the PTR name
					values['name'] = openipam.iptypes.IP(address).reverseName()[:-1]
				
				if old_name and name:
					values['text_content'] = name
				
				ptrname = openipam.iptypes.IP(old_address).reverseName()[:-1]
				
				result = self._do_update(table=obj.dns_records, where=obj.dns_records.c.name == ptrname, values=values)
			else:
				raise error.NotImplemented()
				
			self._commit()
		except:
			self._rollback()
			raise

		return result
	
	def update_dhcp_option_to_group( self, rid, oid, value ):
		'''Update a DHCP Group's information
		@param gid: the database group id
		@param name: the group's name
		@param description: the group's description'''
		pass
		
	def update_group( self, gid, name=None, description=None ):
		"""Update a group
		@param gid: the database group id
		@param name: the group name
		@param description: a description of the group"""
		
		self.require_perms(permission=perms.DEITY, error_str="Insufficient permissions to update group")
		
		values = {}
		
		if name:
			values['name'] = name
		if description:
			values['description'] = description
			
		return self._do_update(table=obj.groups, where=obj.groups.c.id == gid, values = values)

	def disable_host( self, mac, reason=None):
		'''Disable a host for the given reason'''

		# Check permissions
		self.require_perms(perms.SECURITY)
		
		return self._do_insert(table=obj.disabled, values={'mac' : mac, 'reason' : reason,})

	def enable_host( self, mac, reason=None ):
		'''Disable a host for the given reason'''

		# Check permissions
		self.require_perms(perms.SECURITY)

		return self._do_delete( table=obj.disabled, where=obj.disabled.c.mac==mac )

	def renew_hosts(self, hosts=None):
		# Renew the given hosts until 1 year from now.
		if not hosts:
			raise error.InvalidArgument('No hosts specified.')
		# 1 year
		new_expires = datetime.datetime.now() + datetime.timedelta(365)
		self._begin_transaction()
		try:
			for mac in hosts:
				self.update_host( old_mac=mac, expires=new_expires )
			self._commit()
		except:
			self._rollback()
			raise

	def delete_hosts(self, hosts=None):
		# Renew the given hosts until 1 year from now.
		if not hosts:
			raise error.InvalidArgument('No hosts specified.')

		# I hope you know what you are doing here...
		self._begin_transaction()
		try:
			for mac in hosts:
				if not mac:
					raise error.InvalidArgument('Invalid MAC address: %s in host list %s' % (mac,hosts) )
				self.del_host( mac=mac )
			self._commit()
		except:
			self._rollback
			raise

	def change_hosts(self, hosts, owners):
		# Renew the given hosts until 1 year from now.
		if not hosts:
			raise error.InvalidArgument('No hosts specified.')
		if not owners:
			raise error.InvalidArgument('No owners specified.')

		# I hope you know what you are doing here...
		self._begin_transaction()
		try:
			for mac in hosts:
				if not mac:
					raise error.InvalidArgument('Invalid MAC address: %s in host list %s' % (mac,hosts) )
				self.set_owners_for_host( mac=mac, owner_names=owners )
			self._commit()
		except:
			self._rollback
			raise



class DBAuthInterface( DBInterface ):
	def __init__(self):
		DBInterface.__init__( self, username=backend.auth_user )
	def change_internal_password(self, id, hash):
		self._do_update(table=obj.internal_auth, where=obj.internal_auth.id == id, values={'hash':hash} )
	def add_user( self, username, source, min_perms=None ):
		"""
		Add a user to the database
		
		@param username: the username, either internal or their LDAP username
		@param source: require to say where this is coming from, see backend.auth.sources
		@param min_perms: the minimum permissions for this user over everything
		"""
		
		# Check permissions -- probably futile since this will be run by the 'auth user'
		if not self._is_user_in_group(gid=backend.db_service_group_id):
		   self.require_perms(perms.DEITY)
		
		# Make the caller set the source of where this is coming from, don't assume
		if source is None:
			raise error.RequiredArgument("source")

		if not min_perms:
			min_perms = backend.db_default_min_permissions
		
		self._begin_transaction()
		try:
			# Do this INSERT no matter what authentication source
			vals = {'username' : username, 'source' : source, 'min_permissions' : min_perms, }
			query = self._do_insert(table=obj.users, values=vals)

			uid = query.last_inserted_ids()[0]
			
			# When creating a new user, make a group for that user prepended with user_
			group_query = self.add_group('user_%s' % username, "Default group for this user")
			
			gid = group_query.last_inserted_ids()[0]
			
			self.add_user_to_group(uid=uid, gid=gid, permissions=str(perms.OWNER))
			self.add_user_to_group(uid=uid, gid=backend.db_default_group_id, permissions=str(perms.ADD))
			
			self._commit()
		except:
			self._rollback()
			raise
		
		return (uid,gid)
	def create_internal_user (self, username, hash, name=None, email=None ):
		"""
		Add a user to the database
		
		@param username: the username desired
		@param hash: the value to put in for the hash
		@param name: the user's actual name, optional
		@param email: the user's email address, optional
		
		"""
		
		# Check permissions
		self.require_perms(perms.DEITY)
		
		self._begin_transaction()
		try:
			s_id = self.get_auth_sources(name='INTERNAL')[0]['id']
			uid, gid = self.add_user( username=username, source=s_id )
			self._do_insert(table=obj.internal_auth, values={'id' : uid,
									'hash' : hash,
									'name' : name,
									'email' : email } )
			self._commit()
		except:
			self._rollback()
			raise

		return uid,gid
	
	def change_internal_password (self, id, hash ):
		# Check permissions
		self.require_perms(perms.DEITY)
		
		return self._do_update(table=obj.internal_auth, where=obj.internal_auth.c.id == id, values={'hash':hash} )
	
def ago( sec ):
	return sqlalchemy.sql.func.now() - text("interval '%s sec'" % sec)

# 1 week
MAX_LEASE_TIME=604800

class DBDHCPInterface(DBInterface):
	"""
	The interface for all DHCP-related backend stuff
	"""
	from openipam.config import dhcp
	show_queries = False
	debug = False

	def __init__( self ):
		# FIXME: this should come from the config file
		DBInterface.__init__(self, uid=4, username='dhcp', min_perms=perms.DEITY)

	def _create_conn( self ):
		conn = obj.engine.connect()
		conn.isolation_level = 'SERIALIZABLE'
		return conn

	# For debugging only
	def _execute(self, query):
		if self.show_queries:
			print query.compile()
		return DBBaseInterface._execute(self, query)

	def _execute_set(self, query):
		if self.show_queries:
			print query.compile()
		return DBInterface._execute_set(self, query)

	def update_or_create_lease_and_delete_conflicting(self, mac, address, expires, server_address):
		# FIXME: rename this to something like 'handle lease'
		# FIXME: do the lease thing -- delete (set MAC -> NULL, expires -> old or NULL) existing leases for the host, then update address
		
		# delete from leases where (mac = mac and address != address) or (mac != mac and address = address) and starts < NOW() - interval '10 sec' or so?
		print "update_or_create_lease_and_delete_conflicting(mac=%s,address=%s,expires=%s)" % (mac,address,expires)
		
		min_lease_age = 10 # If the lease was given out less than this many seconds ago, don't touch it.
		print 'got %s for expires' % expires

		self._begin_transaction()
		try:
			query = obj.leases.delete( and_(
													or_(
														and_( obj.leases.c.mac == mac, obj.leases.c.address != address ),
														and_( and_( obj.leases.c.mac != mac, obj.leases.c.ends < sqlalchemy.sql.func.now() ), obj.leases.c.address==address )
													),
													obj.leases.c.starts < ago(min_lease_age )
												) )
			self._execute_set(query)
			
			query = select([obj.leases,((sqlalchemy.sql.func.now() - obj.leases.c.starts) < text("interval '%s sec'" % min_lease_age)).label('recent'),(text('extract( epoch from leases.ends - NOW() )::int AS time_left'))], obj.leases.c.mac==mac, for_update=True)
			result = self._execute(query)
			
			# If this lease is < 10 seconds old, don't bother updating it
			values={
					#'mac':mac, # The MAC here must be the same mac, RIGHT?
					'address':address,
					#'starts':sqlalchemy.sql.func.now(), # Doesn't really matter, since we are extending a lease; RIGHT?
					'server':server_address,
					'ends':sqlalchemy.sql.func.now() + text("interval '%s sec'" % (expires + 300) ) # store an extra 5 minutes on the lease to reduce writes caused by stupid client software
					}
			# select * from leases where mac = mac, if exists: update where starts < NOW()-10 sec else, insert.
			if result:
				if result[0]['recent'] or result[0]['time_left'] > expires:
					# do nothing
					if self.debug and result[0]['recent']:
						print "Recent match (< %s s old) found: %s" % (min_lease_age,str(result))
					else:
						print "Longer existing lease found (requested %s): %s" % (expires,str(result))
					self._commit()
					return result
				query = obj.leases.update(and_(obj.leases.c.mac==mac, obj.leases.c.starts < ago(min_lease_age) ),
									values=values )
				result = self._execute_set(query)
			else:
				values['mac'] = mac
				values['starts'] = sqlalchemy.sql.func.now()
				query = obj.leases.insert( values=values )
				result = self._execute_set(query)

			self._commit()
		except:
			self._rollback()
			raise
		
		query = select([obj.leases]).where( and_( obj.leases.c.mac==mac, obj.leases.c.address == address))
		result = self._execute(query)
		if not result:
			raise Exception('Could not create lease for mac: %s address: %s' % mac, address)
		else:
			if self.debug:
				print "mac: %s address: %s matching lease: %s" % (mac, address, result)

		return values

	def get_valid_nets( self, gateway ):
		net_alias = obj.networks.alias('src_net')
		net_query = select( [obj.networks.c.network], from_obj = obj.networks.join(net_alias,
			and_(net_alias.c.network.op('>>')(gateway), obj.networks.c.shared_network == net_alias.c.shared_network)) )

		networks = []
		for i in self._execute(net_query):
			networks.append( i['network'] )
		if not networks:
			raise error.NotFound('No networks found for gateway %s' % gateway)
		return networks

#	def check_valid_lease( self, mac, address, networks ):
#		registration_q = select( [obj.hosts] ).where( and_( obj.hosts.c.mac == mac, obj.hosts.c.expires < sqlalchemy.sql.func.now() ) )
#		registration = self._execute( registration_q )
#		registered = False
#
#		columns, valid = self.valid_addresses_q( networks, registered )
#		columns.append( (obj.leases.c.ends - sqlalchemy.sql.func.now()).label('remaining') )
#		lease_q = select( columns, from_obj = valid).where( or_( obj.leases.c.mac == mac, obj.addresses.c.mac == mac ) )
#		if address:
#			lease_q = lease_q.where( obj.addresses.c.address == address )
#		lease = self._execute( lease_q )
#		print lease
#		if lease:
#			x = lease[0]['remaining']
#			return make_lease_dict( lease[0], int(x.days * 86400 + x.seconds), hostname )
#		return None

	def valid_addresses_q( self, networks, registered ):
		# This innerjoin is okay because we don't know how to give leases on addresses that aren't in a network we know about.
		if registered is None:
			raise error.RequiredArgument("Must specify whether we are looking for registered addresses.")
		valid_addrs = obj.addresses.join(obj.networks, and_(obj.networks.c.network == obj.addresses.c.network, obj.networks.c.network.in_(networks))
			)
		columns = [obj.addresses.c.address, obj.addresses.c.mac, obj.networks.c.network, obj.networks.c.gateway, obj.pools.c.lease_time]
		if registered:
			addrs = valid_addrs.outerjoin(obj.pools, obj.pools.c.id == obj.addresses.c.pool )
		else:
			addrs = valid_addrs.join(obj.pools, and_(obj.pools.c.id == obj.addresses.c.pool) )
		addrs = addrs.outerjoin(obj.leases, obj.leases.c.address == obj.addresses.c.address)
		return (columns, addrs)

	def make_dhcp_lease(self, mac, gateway, requested_address, discover, server_address):
		"""
		Create a DHCP lease for the specific MAC in the proper network
		"""
		address = None
		lease_time = None
		#if discover:
		#	lease_time = 60 # Give the client lease_time seconds to respond to our offer
			
		# False for static addresses
		make_lease = True
		
		#debug = True
		if hasattr( self, '_trans_stack' ):
			raise Exception("Running make_dhcp_lease from inside a transaction!!")

		# First, get valid networks
		networks = self.get_valid_nets( gateway )

		if self.debug:
			print "valid networks for %s: %s" % (gateway,str(networks))

		# FIXME: check to see if there is an existing lease that works, since that is the easiest (and should be the most common) case
		# is this host registered?
		#registered = self.get_hosts(mac=mac, columns=[obj.hosts.c.mac,obj.hosts.c.hostname,], show_expired = False)
		registration_q = select([obj.hosts.c.mac,obj.hosts.c.hostname, (obj.hosts.c.expires < sqlalchemy.sql.func.now()).label('expired')]).where(obj.hosts.c.mac == mac)
		registration = self._execute(registration_q)

		# This is true for hosts that are either unknown to the system, or expired
		unregistered = True
		hostname = None
		if registration:
			registration = registration[0]
			unregistered = registration['expired']
			hostname = registration['hostname']

		disabled_q = select( [obj.disabled.c.mac,] ).where( obj.disabled.c.mac == mac )
		disabled = self._execute( disabled_q )

		if not unregistered and not disabled:
			is_static = False
			allowed_pools_q = select( [obj.hosts_to_pools.c.pool_id] ).where( obj.hosts_to_pools.c.mac == mac )
			ap = self._execute( allowed_pools_q )
			allowed_pools = []
			for p in ap:
				allowed_pools.append( p['pool_id'] )
			if self.debug:
				print "Found valid registration for this host."
			if not allowed_pools:
				is_static=True
			
			columns, registered_addrs = self.valid_addresses_q( networks, registered=True )

			registered_q = select( columns, from_obj = registered_addrs ).where( or_(
								and_( or_( or_( obj.leases.c.mac == mac, obj.leases.c.mac == None ), obj.leases.c.ends < sqlalchemy.sql.func.now() ), obj.addresses.c.pool.in_(allowed_pools) ),
							obj.addresses.c.mac == mac ) ).where(obj.addresses.c.reserved == False ) 
			registered_q = registered_q.where( or_( obj.leases.c.abandoned == False, obj.leases.c.abandoned == None ) )
			# check the requested address and see if it 'works'
			requested_q = registered_q

			# get allowable addresses/leases where the address is the one requested and is leased to the mac given or not leased to anyone
			# FIXME: we want static addresses to be first
			requested_q = requested_q.where( obj.addresses.c.address == requested_address )
			requested = self._execute(requested_q)

			if requested:
				if self.debug:
					print "Client is allowed to have requested address."
					print requested
				address = requested[0]
				if address['address'] != requested_address:
					print "(registered) This is really strange... %s != %s, but it should be." % (requested_address, address['address'])
				# FIXME: do lease thing here
				if address['mac']:
					# This is a static lease
					is_static = True
					if self.debug:
						print "lease is static"
					lease_time = self.dhcp.static_lease_time
					make_lease=False
				else:
					if self.debug:
						print "lease is dynamic"

			# check for any valid static leases
			if not address:
				static_q = select( columns, from_obj = registered_addrs).where(obj.addresses.c.mac == mac).where(obj.addresses.c.reserved == False )
				static_q = static_q.limit(1)
				static = self._execute(static_q)
				if static:
					is_static = True
					if self.debug:
						print "Found static lease for this host."
						print 'static = %s' % static
					# there could be multiple addresses here, but let's just give them the first
					address=static[0]
					lease_time = self.dhcp.static_lease_time
					make_lease=False

			# check for valid dynamic leases... this is our last chance
			# First, check for existing addresses or that aren't in the leases table
			if not address:
				addresses_q = registered_q.where( obj.leases.c.mac == mac )
				# addresses_q = addresses_q.order_by(obj.addresses.c.address.desc()).limit(1) # Adds ~ 11 seconds to this ~3 ms query
				addresses = self._execute( addresses_q )
				if addresses:
					if self.debug:
						print "Found existing (but not requested) dynamic lease for this host."
						print 'addresses = %s' % addresses
					address = addresses[0]

			if not address:
				addresses_q = registered_q.where( or_( obj.leases.c.ends == None, obj.leases.c.mac == mac ) ).limit(20)
				# addresses_q = addresses_q.order_by(obj.addresses.c.address.desc()).limit(1) # Adds ~ 11 seconds to this ~3 ms query
				addresses = self._execute( addresses_q )
				if addresses:
					if len(addresses) > 1:
						address = addresses[random.randrange(0,len(addresses)-1)]
					else:
						address = addresses[0]

					if self.debug:
						print "Found new (no existing lease) or existing dynamic lease for this host."
						print 'addresses = %s' % addresses
					address = addresses[0]

			# We have to re-use an address, let's get the LRU address
			if not address:
				addresses_q = registered_q.order_by( obj.leases.c.ends.asc() ).limit(1)
				# addresses_q = addresses_q.order_by(obj.addresses.c.address.desc()).limit(1) # Adds ~ 11 seconds to this ~3 ms query
				addresses = self._execute( addresses_q )
				if addresses:
					if self.debug:
						print "Reusing an expired dynamic lease for this host."
						print 'addresses = %s' % addresses
					address = addresses[0]

			if address:
				if not is_static and not discover:
					# Update the DNS records
					q = select( [obj.dhcp_dns_records], for_update=True ).where( or_( obj.dhcp_dns_records.c.ip_content == address['address'], obj.dhcp_dns_records.c.name == hostname ) )
					exists = False
					records = self._execute( q )
					for record in records:
						if record['ip_content'] == address['address'] and record['name'] == hostname:
							exists = True
						else:
							d = obj.dhcp_dns_records.delete( obj.dhcp_dns_records.c.id == record['id'] )
							self._execute_set( d )
					if not exists:
						dynamic_address_ttl = 120
						self.add_dhcp_dns_record( name=hostname, ip_content = address['address'], ttl = dynamic_address_ttl )
		if unregistered or disabled or (is_static and not address):
			if address:
				raise  Exception('FIXME: unregistered or disabled host got an address: %s' % address)
			if self.debug:
				print "Unregisterd host."
			# handle unregistered host
			# find addresses pools that allow unregistered hosts
			columns, unreg_addrs = self.valid_addresses_q( networks, registered=False )
			# check the requested address and see if it 'works'
			unregistered_q = select( columns, from_obj = unreg_addrs).where( or_( or_( obj.leases.c.mac == mac, obj.leases.c.mac == None ), obj.leases.c.ends < sqlalchemy.sql.func.now() ) )
			unregistered_q = unregistered_q.where(obj.addresses.c.reserved == False ) 
			unregistered_q = unregistered_q.where( or_( obj.leases.c.abandoned == False, obj.leases.c.abandoned == None ) ).where( obj.pools.c.allow_unknown == True )
			requested = None

			if requested_address:
				requested_q = unregistered_q
				requested_q = requested_q.where( obj.addresses.c.address == requested_address )
				requested = self._execute(requested_q)

			if requested:
				if self.debug:
					print "Using requested lease for this unregistered host."
				address = requested[0]
				if address['address'] != requested_address:
					print "(unregistered) This is really strange... %s != %s, but it should be." % (address, requested[0]['address'])

			if not address:
				leased_q = select( columns, from_obj = unreg_addrs ).where( obj.leases.c.mac == mac ).order_by(obj.leases.c.starts).where(obj.addresses.c.reserved == False ).where( obj.pools.c.allow_unknown == True ) 
				leased_q = leased_q.where( or_( obj.leases.c.abandoned == False, obj.leases.c.abandoned == None ) ).limit(1)
				leased = self._execute( leased_q )
				if leased:
					if self.debug:
						print "Found existing dynamic lease for this unregistered host."
					address = leased[0]

			if not address:
				# Look for unassigned lease
				addresses_q = unregistered_q.where( obj.leases.c.ends == None ).limit(20)
				addresses = self._execute( addresses_q )
				if addresses:
					if self.debug:
						print "Found new dynamic lease for this unregistered host."
					if len(addresses) > 1:
						address = addresses[random.randrange(0,len(addresses)-1)]
					else:
						address = addresses[0]

			if not address:
				# LRU lease
				addresses_q = unregistered_q.order_by( obj.leases.c.ends ).limit(1)
				addresses = self._execute( addresses_q )
				if addresses:
					if self.debug:
						print "Found new dynamic lease for this unregistered host."
					address = addresses[0]

		# get network info about the address we are giving out
		if not address:
			# FIXME: make an exception for this
			raise error.NotFound("No valid leases found for client %s from gateway %s" %(mac,gateway))
		elif make_lease:
			# Use the pool default...  We should probably get rid of this code/column at some point
			lease_time = address['lease_time']

			LEASE_TIME_OPTION=51

			lease_time_option = self.retrieve_dhcp_options( mac, address['address'], [LEASE_TIME_OPTION,] )
			if lease_time_option:
				new_lease_time = lease_time_option[-1]['value']
				lease_time = bytes_to_int(new_lease_time)
				if lease_time > MAX_LEASE_TIME:
					raise Exception("Bad lease time: %s (%s)" % (lease_time, dict(lease_time_option)))

			# FIXME: we should check lease_time here, but oh well
			self.update_or_create_lease_and_delete_conflicting(mac, address['address'], lease_time, server_address)
		
		# This probably doesn't gain us anything, since clients should renew at random intervals anyway
		#return make_lease_dict( address, random.randrange( lease_time*2/3, lease_time ), hostname )
		return make_lease_dict( address, lease_time, hostname )

	def mark_abandoned_lease(self, address=None, mac=None):
		whereclause = None
		if address:
			whereclause = obj.leases.c.address == address
		elif mac:
			if whereclause:
				whereclause = and_( whereclause, obj.leaces.c.mac == mac )
			else:
				whereclause = obj.leaces.c.mac == mac
		else:
			raise error.RequiredArgument("Must specify MAC or address.")
		values = { 'abandoned': True, 'mac': None, 'starts': sqlalchemy.sql.func.now(), 'ends':sqlalchemy.sql.func.now() + text("interval '3600 s'", ) }
		self._execute_set( obj.leases.update( whereclause, values=values ) )
		# FIXME: what if no lease exists?  Currently, this is only called after 1) getting a lease and 2) finding it used

	def retrieve_dhcp_options(self, mac, address, option_ids):
		'''return a list of DHCP options'''

		#debug = True

		global_grp = 1
		
		host_grp = self._execute( select( [obj.hosts.c.dhcp_group,] ).where(obj.hosts.c.mac == mac) )
		if host_grp: host_grp = host_grp[0][0]
		else: host_grp = None

		pool_grp = self._execute( select( [obj.pools.c.dhcp_group,], from_obj = obj.pools.join(obj.addresses,and_(obj.addresses.c.address == address, obj.addresses.c.pool==obj.pools.c.id) ) ) )
		if pool_grp: pool_grp = pool_grp[0][0]
		else: pool_grp = None
		
		#shared_net_grp = select( [obj.shared_networks.c.dhcp_group]
		shared_net_grp = None
		if shared_net_grp: shared_net_grp = shared_net_grp[0][0]
		else: shared_net_grp = None
		
		network_grp = self._execute( select( [obj.networks.c.dhcp_group,] ).where( obj.networks.c.network.op('>>')( address ) ) )
		if network_grp: network_grp = network_grp[0][0]
		else: network_grp = None

		# FIXME: if we want a 'global' group, it belongs at the beginning of this list
		grp_lst = [ global_grp, pool_grp, shared_net_grp, network_grp, host_grp ]

		if self.debug:
			print grp_lst

		grp_order_mapping = []
		new_grp_lst = []
		for i in range( len(grp_lst) ):
			if grp_lst[i]:
				grp_order_mapping.append( (grp_lst[i], i,) )
				new_grp_lst.append(grp_lst[i])
		grp_lst = new_grp_lst
		if self.debug:
			print grp_lst
			print grp_order_mapping


		options = select( [obj.dhcp_options_to_dhcp_groups.c.oid,obj.dhcp_options_to_dhcp_groups.c.value] ).where( obj.dhcp_options_to_dhcp_groups.c.gid.in_(grp_lst) )
		if option_ids:
			options = options.where( obj.dhcp_options_to_dhcp_groups.c.oid.in_( option_ids ) )

		# FIXME
		if grp_order_mapping:
			options = options.order_by(sqlalchemy.sql.case(grp_order_mapping,value=obj.dhcp_options_to_dhcp_groups.c.gid))
		else:
			raise Exception("FIXME: no DHCP groups found that apply to this mac/address (%s/%s)" % (mac, address) )

		return self._execute( options )

	def add_dhcp_dns_record(self, name, ip_content, ttl ):
		"""
		Adds a DNS records to dhcp_dns_records
		"""

		domains = self.get_domains( contains = name )
		if not domains:
			raise Exception( 'Could not find domain for %s' % name )
		
		did = domains[0]['id']

		query = obj.dhcp_dns_records.insert(values = {
											'did' : did,
											'name' : name,
											'ip_content' : ip_content,
											'ttl' : ttl
											})
		
		return self._execute_set(query)
	
def bytes_to_int( bytes ):
	bytes = str(bytes)
	val = 0
	for byte in bytes:
		val = ( val << 8 ) | ord( byte )
	return val

def int_to_bytes( num, min_len=1 ):
	lst = []
	while num:
		ch = num & 0xFF
		lst.insert(0, chr(ch) )
		num = num >> 8
	while len( lst ) < min_len:
		lst.insert(0,'\x00')
	return ''.join(lst)

def make_lease_dict( address, lease_time, hostname ):
		ret = {}
		ret['address'] = address['address']
		ret['router'] = address['gateway']
		ret['netmask'] = str(openipam.iptypes.IP(address['network']).netmask()) # FIXME
		ret['broadcast'] = str(openipam.iptypes.IP(address['network']).broadcast()) # FIXME
		ret['lease_time'] = lease_time
		ret['hostname'] = hostname
		return ret
		
		
