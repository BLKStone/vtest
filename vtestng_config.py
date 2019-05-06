#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Time    : 2019/4/28 10:10
# Author  : BLKStone
# Site    : http://wp.blkstone.me
# File    : vtestng_config.py.py
# Software: PyCharm



class VTestNGConfig(object):

    # 数据库路径
    sqlite_path = 'db/vtest.db'

    # 生成随机子域名的长度
    dns_probe_domain_length = 12

    # 页面模板
    main_template_path = 'templates/main_page.html'

    # DNS 服务器 对于一般域名解析的地址
    default_resolve_ip = '127.0.0.1'

    def __init__(self):
        pass

