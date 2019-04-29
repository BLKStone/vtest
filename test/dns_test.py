#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Time    : 2019/4/26 10:56
# Author  : BLKStone
# Site    : http://wp.blkstone.me
# File    : dns_test.py
# Software: PyCharm


import struct


skt_server = None

try:
    import SocketServer
    skt_server = SocketServer
except Exception as e:
    import socketserver
    skt_server = socketserver

try:
    import thread
except Exception as e:
    import _thread
    thread = _thread


ROOT_DOMAIN = 'alida.club'
REBIND_CACHE = []
LOCAL_IP = '45.76.125.91'
PASSWORD = 'admin'



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




class DNSServer:
    A_map = {}
    def __init__(self):
        pass

    def add_record(self, name, ip):
        DNSServer.A_map[name] = ip

    def start(self):
        server = skt_server.UDPServer(("0.0.0.0", 53), DNSUDPHandler)
        server.serve_forever()




class DNSUDPHandler(skt_server.BaseRequestHandler):

    def handle(self):

        data = self.request[0].strip()
        dns = DNSFrame(data)
        socket_u = self.request[1]
        a_map = DNSServer.A_map

        if (dns.query_type == 1):
            domain = dns.get_query_domain()

            print("Query domain: {domain}".format(domain=domain))

            default_resolved_ip = '127.0.0.9'
            ip = default_resolved_ip

            # 确定 DNS 解析结果
            if domain in a_map:
                # 自定义的 dns 记录，保留着
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

            # 记录 DNS log
            if ROOT_DOMAIN in domain:
                name = domain.replace('.' + ROOT_DOMAIN, '')
                sql = "INSERT INTO dns_log (name, domain, ip, insert_time) VALUES(?, ?, ?, datetime(CURRENT_TIMESTAMP,'localtime'))"
                # DB.exec_sql(sql, name, domain, ip)
            else:
                name = domain

            print('%s: %s-->%s' % (self.client_address[0], name, ip))

            dns.set_ip(ip)
            socket_u.sendto(dns.get_bytes(), self.client_address)
        else:
            socket_u.sendto(data, self.client_address)

def dns():
    d = DNSServer()
    d.add_record('httplog.' + ROOT_DOMAIN, LOCAL_IP)
    d.add_record('x.' + ROOT_DOMAIN, LOCAL_IP)
    d.add_record('mock.' + ROOT_DOMAIN, LOCAL_IP)

    d.start()


if __name__ == '__main__':
    print("Starting UDP Server...")
    dns()
    # thread.start_new_thread(dns, ())
