#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Time    : 5/7/2019 1:05 AM
# Author  : BLKStone
# Site    : http://wp.blkstone.me
# File    : load_url.py
# Software:  PyCharm


import requests




def load_file(path):
    url_list = []
    with open(path,'r') as f:
        for line in f.readlines():
            row = line.strip().split(' ')
            url = str(row[1]) + '://' + str(row[2])
            url_list.append(url)
    return url_list


def request_burp(url):
    # url = "https://www.icbcindia.com:443/"

    proxies = {
        'http': 'http://192.168.0.106:9090',
        'https': 'http://192.168.0.106:9090',
    }

    print("request {url}".format(url=url))
    # requests.get('http://example.org', proxies=proxies)
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:66.0) Gecko/20100101 Firefox/66.0",
                     "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                     "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
                     "Accept-Encoding": "gzip, deflate", "Connection": "close", "Upgrade-Insecure-Requests": "1"}
    requests.get(url, headers=headers, proxies=proxies, verify=False)


def main():
    path = 'D:\\pydev\\vtest\\test\\20190507.txt'
    url_list = load_file(path)
    for url in url_list:
        request_burp(url)


if __name__ == '__main__':
    main()