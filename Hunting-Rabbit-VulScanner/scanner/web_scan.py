# -*- coding: UTF-8 -*-
# @Author: 浪飒
# @Software: PyCharm
# @File: web_scan.py
import ast
import html
import json
import os
import re
import signal
import sys
import time
import warnings

import requests
from email.parser import HeaderParser
from tqdm import tqdm


# 读取文件夹内所有文件，附带关键词查询
from urllib3.exceptions import InsecureRequestWarning

from scanner.UserAgent import Random_UserAgents
from scanner.report import report_html


def read_poc_files(folder_path, keyword=None):
    pocs = []
    if keyword:
        for root, dirs, files in os.walk(folder_path):
            for file in files:
                if file.endswith('.json'):
                    file_path = os.path.join(root, file)
                    with open(file_path, 'r', encoding='utf-8') as f:
                        file_name = f.name.lower()
                        content = json.load(f)
                        # 忽略大小写
                        keyword = keyword.lower()
                        if keyword in file_name:
                            pocs.append(content)
                        else:
                            pass
                else:
                    pass

    else:
        for root, dirs, files in os.walk(folder_path):
            for file in files:
                if file.endswith('.json'):
                    file_path = os.path.join(root, file)
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = json.load(f)
                        pocs.append(content)
                else:
                    pass

    return pocs


# 响应体转换
def headers_to_dict(headers_str):
    # 使用email.parser.HeaderParser来解析头部信息
    parser = HeaderParser()
    headers = parser.parsestr(headers_str)

    # 将结果转换为字典
    header_dict = {k: v for k, v in headers.items()}
    return header_dict


def dict_to_headers(header_dict):
    headers_str = ''
    if header_dict:
        for key, value in header_dict.items():
            # 将字典中的键值对转换为HTTP头部格式
            headers_str += f'{key}: {value}\n'
    # 移除最后的多余行尾字符
    headers_str = headers_str.rstrip('\n')
    return headers_str


# target存活检测
def check_target(target, timeout=5):
    warnings.simplefilter('ignore', InsecureRequestWarning)
    try:
        response = requests.get(target, timeout=timeout, verify=False)
        if response.status_code:
            return True
    except (requests.RequestException, requests.HTTPError) as e:
        # 处理请求异常和状态码异常
        return False


# 发包函数
def send_http_request(method, url, proxy=None, headers=None, body=None, timeout=10):
    start_time = time.time()
    warnings.simplefilter('ignore', InsecureRequestWarning)
    try:
        response = requests.request(method, url, headers=headers, data=body, proxies=proxy,timeout=timeout, verify=False)
    except requests.exceptions.RequestException as e:
        return {
            'status_code': 'error',
            'status_reason': '',
            'headers_body': '',
            'headers': '',
            'body': '',
            'response_time': ''
        }

    # 计算响应时间
    end_time = time.time()
    response_time = end_time - start_time
    # 返回结果
    return {
        'status_code': str(response.status_code),
        'status_reason': str(response.reason),
        'headers_body': str(response.headers) + str(response.text),
        'headers': response.headers,
        'body': response.text,
        'response_time': response_time
    }


def signal_handler(sig, frame):
    sys.exit(0)

# 漏洞扫描函数
def scan_func(target, pocs, proxy= None,rua=True):
    if not check_target(target):
        print(f"\033[90m[错误] {target} 无法访问！\033[0m")
        return
    # 循环提取并发送poc
    # 定义颜色映射
    COLORS = {
        '高危': "\033[91m",  # 红色
        '中危': "\033[93m",  # 黄色
        '低危': "\033[92m"  # 绿色
    }
    RESET = "\033[0m"  # 重置颜色
    pbar = tqdm(total=len(pocs), desc="开始扫描")
    vuln_list = []
    num=0
    for poc in pocs:
        # 注册ctrl+c信号处理函数
        try:
            signal.signal(signal.SIGINT, signal_handler)
        # 捕捉异常
        except KeyboardInterrupt:
            print('程序已退出!')
            sys.exit(0)
        pbar.update(1)
        if not poc:
            pass
        else:
            vul_name = poc['vul_name']
            pbar.set_description(f"正在测试{vul_name}")
            rule = poc['rule']
            method = rule['method']
            path = rule['path']
            headers = headers_to_dict(rule['headers'])
            body = rule['body']
            status_code = rule['status_code']
            # 关键词用英文分号隔开
            if rule['keywords']:
                keywords = rule['keywords'].lower().split(';')
            else:
                keywords = []
            if rule['res_time']:
                res_time = int(rule['res_time'])
            else:
                res_time = ''
            url = target + path
            if rua:
                if headers:
                    headers['User-Agent'] = Random_UserAgents()
                else:
                    headers = {'User-Agent': Random_UserAgents()}

            response = send_http_request(method, url, proxy,headers, body)
            # 判断是否需要考虑响应时间，当前为不考虑
            if res_time == '':
                if keywords:
                    # 判断响应码正确且至少存在一个关键词
                    if response['status_code'] == status_code and any(
                            keyword in response['headers_body'].lower() for keyword in keywords):
                        vulnerability_exists = True
                    else:
                        vulnerability_exists = False
                else:
                    # 判断响应码正确且不存在关键词
                    if response['status_code'] == status_code:
                        vulnerability_exists = True
                        # 准确性提示：没有关键字可能误报
                    else:
                        vulnerability_exists = False

            else:
                if keywords:
                    # 考虑响应时间则真实响应时间大于等于设定时间即可
                    if response['status_code'] == status_code and response['response_time'] >= res_time and any(
                            keyword in response['headers_body'].lower() for keyword in keywords):
                        vulnerability_exists = True
                    else:
                        vulnerability_exists = False

                else:
                    # 考虑响应时间则真实响应时间大于等于设定时间即可
                    if response['status_code'] == status_code and response['response_time'] >= res_time:
                        vulnerability_exists = True
                    else:
                        vulnerability_exists = False

            # 存储漏洞判断依据
            if vulnerability_exists:
                host_pattern = re.compile(r'http[s]?://([^/]+)/?.*')
                match = host_pattern.search(target)
                host = match.group(1)
                if not keywords:
                    pbar.write(f'{COLORS[poc["level"]]}[{poc["level"]}] {vul_name}\033[96m(该漏洞POC无关键词验证，可能存在误报): {RESET}{url}')
                else:
                    pbar.write(f'{COLORS[poc["level"]]}[{poc["level"]}] {vul_name}: {RESET}{url}')

                req =f'{method} {path} HTTP/1.1\nHost: {host}\n{dict_to_headers(headers)}\r\n{body}'
                res =f'HTTP/1.1 {response["status_code"]} {response["status_reason"]}\n{dict_to_headers(response["headers"])}\r\n{response["body"]}'
                num += 1
                vuln_list.append([num,vul_name,poc['level'],url,poc['description'],poc['cve'],poc['reference'],poc['fixing'],req,res])
    report_html(target,vuln_list)
    pbar.set_description('扫描完毕')
    pbar.close()






