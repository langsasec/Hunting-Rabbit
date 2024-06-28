# -*- coding: utf-8 -*-
# @Time    : 2024/6/16  14:20
# @Author  : 浪飒
# @FileName: api.py
# @Software: PyCharm
import argparse
import sys
from scanner.web_scan import read_poc_files, scan_func


def Hunting_Rabbit_VulScanner():
    parser = argparse.ArgumentParser(description='Hunting Rabbit VulScanner       author:浪飒')
    parser.add_argument('-u', '--url', type=str, help='目标地址，例如 http://www.example.com 或 127.0.0.1:8080')
    parser.add_argument('-f', '--file', type=str, help='目标地址文件')
    parser.add_argument('-k', '--keyword', type=str, help='POC关键字，例如 "用友" 或"SQL注入",会自动使用相关POC，不使用则默认使用全部POC')
    parser.add_argument('-p', '--proxy', type=str, help='代理地址，例如 http://127.0.0.1:8080')
    parser.add_argument('-nua', '--no-ua', action='store_true', help='停用随机UA，默认为开启')
    parser.add_argument('-v', '--version', action='version', version='%(prog)s 1.0')
    args = parser.parse_args()
    # 如果没有参数，返回帮助信息
    if len(sys.argv) == 1:
        parser.print_help()
        exit()

    # f和u二选一，不能同时存在
    if args.file and args.url:
        print('-f和-u不能同时存在')
        exit()

    if args.file:
        if args.keyword:
            poc = read_poc_files('poc', keyword=args.keyword)
        else:
            poc = read_poc_files('poc')
        if args.no_ua:
            rua = False
        else:
            rua = True
        if args.proxy:
            proxies = {
                'http': args.proxy,
                'https': args.proxy
            }
        else:
            proxies = None
        with open(args.file, 'r') as f:
            urls = f.readlines()
            for url in urls:
                url = url.strip()
                if not url.startswith('http://') and not url.startswith('https://'):
                    url = 'http://' + url
                print('正在扫描目标地址：', url)
                scan_func(target=url, pocs=poc, proxy=proxies, rua=rua)

    if args.url:
        if args.keyword:
            poc = read_poc_files('poc', keyword=args.keyword)
        else:
            poc = read_poc_files('poc')
        if args.proxy:
            proxies = {
                'http': args.proxy,
                'https': args.proxy
            }
        else:
            proxies = None
        if args.no_ua:
            rua = False
        else:
            rua = True

        url = args.url
        if not url.startswith('http://') and not url.startswith('https://'):
            url = 'http://' + url
        print('正在扫描目标地址：', url)
        scan_func(target=url, pocs=poc, proxy=proxies, rua=rua)



