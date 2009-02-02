#!/usr/bin/env python

import psycopg2
import tempfile

# Set these as appropriate
ipamdb=None
dnsdb=None

ipam = psycopg2.connect(ipamdb)
dns = psycopg2.connect(dnsdb)

ipamcurs = ipam.cursor()
dnscurs = dns.cursor()

def check_update():
	dnscurs.execute('''SELECT t_name,last_change,last_id
			FROM last_update''')

	last = {}
	cur = {}
	for i in dnscurs.fetchall():
		last[i[0]] = (i[1],i[2])

	# This is probably NULL
	ipamcurs.execute('''SELECT max(change_date) FROM pdns_zone_xfer''')
	date = ipamcurs.fetchall()[0][0]
	ipamcurs.execute('''SELECT max(id) FROM pdns_zone_xfer''')
	id = ipamcurs.fetchall()[0][0]
	cur['pdns_zone_xfer'] = (date,id,)

	ipamcurs.execute('''SELECT max(changed) FROM dhcp_dns_records''')
	date = ipamcurs.fetchall()[0][0]
	ipamcurs.execute('''SELECT max(id) FROM dhcp_dns_records''')
	id = ipamcurs.fetchall()[0][0]
	cur['dhcp_dns_records'] = (date,id,)
	
	ipamcurs.execute('''SELECT max(changed) FROM dns_records''')
	date = ipamcurs.fetchall()[0][0]
	ipamcurs.execute('''SELECT max(id) FROM dns_records''')
	id = ipamcurs.fetchall()[0][0]
	cur['dns_records'] = (date,id,)

	changed = False
	for i in cur.keys():
		date,id = cur[i]
		if last.has_key(i):
			datechecked,idchecked = last[i]
		else:
			changed = True
			break
		if ((date and datechecked and date > datechecked) or
				(datechecked and not date)):
			changed = True
			break
		if ((id and idchecked and id > idchecked) or
				(idchecked and not id)):
			changed = True
			break
	return (changed, cur)

changed, cur = check_update()
print changed,cur

def copy_data(d):
	if d is None:
		return '\\N'
	new = str(d)
	return new.replace('\t','\\t')

if changed and __name__ == '__main__':
	print "Need update"
	cond = 'view_id=1 or view_id IS NULL'

	domain_fields = ['id','name','master','last_check','type','notified_serial','account']
	record_fields = ['domain_id','name','type','content','ttl','prio','change_date']

	clear_old = '''TRUNCATE TABLE domains, records, last_update;'''

	sqlfile = open('dns_data.sql','w')

	#dnscurs.execute(clear_old)
	sqlfile.write('BEGIN;\n')
	#sqlfile.write(clear_old)
	sqlfile.write('''
CREATE TABLE last_update_new (
        t_name varchar primary key,
        last_change timestamp,
        last_id bigint         
);      

CREATE TABLE domains_new (
 id              INT NOT NULL,
 name            VARCHAR(255) NOT NULL,
 master          VARCHAR(128) DEFAULT NULL,
 last_check      INT DEFAULT NULL,
 type            VARCHAR(6) NOT NULL,
 notified_serial INT DEFAULT NULL,
 account         VARCHAR(40) DEFAULT NULL
);

-- CREATE UNIQUE INDEX name_index ON domains(name);

CREATE TABLE records_new (
        id              SERIAL,
        domain_id       INT DEFAULT NULL,
        name            VARCHAR(255) DEFAULT NULL,
        type            VARCHAR(6) DEFAULT NULL,
        content         VARCHAR(255) DEFAULT NULL,
        ttl             INT DEFAULT NULL,
        prio            INT DEFAULT NULL,
        change_date     INT DEFAULT NULL
);

-- CREATE INDEX rec_name_index ON records(name);
-- CREATE INDEX nametype_index ON records(name,type);
-- CREATE INDEX domain_id ON records(domain_id);

create table supermasters_new (
          ip VARCHAR(25) NOT NULL,
          nameserver VARCHAR(255) NOT NULL,
          account VARCHAR(40) DEFAULT NULL
);

GRANT SELECT ON supermasters TO pdns;
GRANT SELECT ON domains TO pdns;
--GRANT SELECT ON domains_id_seq TO pdns;
GRANT SELECT ON records TO pdns;
--GRANT SELECT ON records_id_seq TO pdns;
''')
	sqlfile.write('\n')

	print 'getting domains'
	#domains = tempfile.TemporaryFile()
	#ipamcurs.copy_to(domains,'domains',columns=domain_fields)
	sqlfile.write('\nCOPY domains_new(%s) FROM STDIN;\n'%','.join(domain_fields))
	ipamcurs.copy_to(sqlfile,'domains',columns=domain_fields)
	sqlfile.write('\\.\n\n')
	print 'copying domains'
	#domains.seek(0)
	#dnscurs.copy_from(domains,'domains',columns=domain_fields)
	#domains.close()
	#ipamcurs.execute('''SELECT %s FROM domains;'''% ','.join(domain_fields))
	#domains = ipamcurs.fetchall()
	#dnscurs.executemany('''INSERT INTO domains(%s) VALUES (%s);''' % (','.join(domain_fields),','.join(['%s' for i in range(len(domain_fields))])), domains)

	print 'getting records'
	#records = tempfile.TemporaryFile()
	ipamcurs.execute('''SELECT %s FROM records WHERE %s'''% (','.join(record_fields),cond))
	record_list = ipamcurs.fetchall()
	sqlfile.write('COPY records_new(%s) FROM STDIN;\n'%','.join(record_fields))
	print 'formatting records'
	for i in range(len(record_list)):
		#records.write('\t'.join(map(copy_data,record_list[i])))
		sqlfile.write('\t'.join(map(copy_data,record_list[i])))
		#if i < (len(record_list)-1):
		#	records.write('\n')
		sqlfile.write('\n')
	sqlfile.write('\\.\n\n')
	print 'copying records'
	#records.seek(0)
	#dnscurs.copy_from(records,'records',columns=record_fields)
	#dnscurs.executemany('''INSERT INTO records(%s) VALUES (%s);''' %(','.join(record_fields),','.join(['%s' for i in range(len(record_fields))])), record_list)

	print 'updating status'
	new_checked = []
	for i in cur.keys():
		new_checked.append( (i,cur[i][0],cur[i][1],) )

	def quot(d):
		if d is None:
			return 'NULL'
		return "'%s'"%d
	for i in new_checked:
		#dnscurs.execute('''INSERT INTO last_update VALUES (%s,%s,%s);''',i)
		sqlfile.write('''INSERT INTO last_update_new VALUES (%s,%s,%s);\n''' % tuple(map(quot,i)))

	sqlfile.write('''\nDROP TABLE last_update, records, domains, supermasters CASCADE;\n''')
	for n in ['last_update', 'domains', 'supermasters', 'records']:
		sqlfile.write('''\nALTER TABLE %s_new RENAME TO %s;\n''' % (n,n))
	sqlfile.write('''
--CREATE UNIQUE INDEX name_index ON domains(name);
--CREATE INDEX rec_name_index ON records(name);
--CREATE INDEX nametype_index ON records(name,type);
--CREATE INDEX domain_id ON records(domain_id);
''')
	sqlfile.write('''COMMIT;\n\n-- END OF FILE''')
	dns.commit()
	ipam.commit()

