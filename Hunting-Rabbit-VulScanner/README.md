---
title: VulScanner
nav:
  title: 漏洞扫描
  path: /vulscanner
  order: 3
---

# Hunting-Rabbit-VulScanner

## 简介

Hunting-Rabbit-VulScanner（猎兔漏洞扫描器）： 一款简洁高效的漏洞扫描器。

## 安装

1.拉取代码：

```bash
git clone https://github.com/langsasec/Hunting-Rabbit-VulScanner
```

2.安装依赖

```
cd Hunting-Rabbit-VulScanner && pip install -r requirements.txt
```

## 使用

```bash
Hunting Rabbit VulScanner author:浪飒

options:
  -h, --help            show this help message and exit
  -u URL, --url URL     目标地址，例如 http://www.example.com 或 127.0.0.1:8080
  -f FILE, --file FILE  目标地址文件
  -k KEYWORD, --keyword KEYWORD
                        POC关键字，例如 "用友" 或"SQL注入",会自动使用相关POC，不使用则默认使用全部POC
  -p PROXY, --proxy PROXY
                        代理地址，例如 http://127.0.0.1:8080
  -nua, --no-ua         停用随机UA，默认为开启
  -v, --version         show program's version number and exit
```

## 示例

使用默认所有poc扫描单个目标

```
python Hunting-Rabbit-VulScanner.py -u http://www.example.com
```

扫描多个目标 ，指定poc名称关键词：用友

```
python Hunting-Rabbit-VulScanner.py -f target.txt -k 用友
```

扫描时将数据包发送至代理，如Burpsuite

```
python Hunting-Rabbit-VulScanner.py -u http://www.example.com -p http://127.0.0.1:8080
```

扫描示例：

![image-20240628170215154](https://img2024.cnblogs.com/blog/2411575/202406/2411575-20240628170219021-1320488176.png)

报告示例：

![image-20240628170613923](https://img2024.cnblogs.com/blog/2411575/202406/2411575-20240628170617671-1490530192.png)

![image-20240628170638299](https://img2024.cnblogs.com/blog/2411575/202406/2411575-20240628170642320-1011526617.png)

## 帮助

官方POC库：https://github.com/langsasec/Hunting-Rabbit-POC

用户可通过Hunting-Rabbit-POC-Generator（猎兔POC生成器）自定义POC。

