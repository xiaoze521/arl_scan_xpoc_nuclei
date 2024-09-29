#! /usr/bin/env python3
# -*- coding: utf-8 -*-
# author:Cedric1314

import requests, json, sys, time, socket
from time import strftime, gmtime
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import datetime
import os
Token = ''
ids = []

# 配置
arl_url = 'https://127.0.0.1:5003/'
username = 'admin'
password = '123456'
time_sleep = 1000
get_size = 500  #获取数量

def push_wechat_group(content):
    webhook_url = "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=XXXXXXXXXXXXXXXXXXXX"
    try:
        resp = requests.post(webhook_url,
                             json={"msgtype": "markdown",
                                   "markdown": {"content": content}})
        print(content)
        if 'invalid webhook url' in str(resp.text):
            print('企业微信key 无效,无法正常推送')
            sys.exit()
        if resp.json()["errcode"] != 0:
            raise ValueError("push wechat group failed, %s" % resp.text)
    except Exception as e:
        print(e)

def nuclei(scan_list):
    print(scan_list)
    with open("newurls.txtls", "w", encoding='utf-8') as f:
        for scan in scan_list:
            if scan != '':
                f.writelines(scan + "\n")
    
    os.system("echo \"开始使用 /opt/nuclei 对新增资产进行漏洞扫描\"")
    
    # 生成文件名的时间戳
    timestamp = str(datetime.datetime.now().strftime('%Y-%m-%d-%H:%M:%S'))
    output_file = f"res-all-vulnerability-results-{timestamp}.txt"
    
    # 执行nuclei扫描
    os.system(f"cat newurls.txtls | proxychains /opt/nuclei -rl 300 -bs 35 -c 30  -mhe 10 -ni -o {output_file} -stats -silent -severity critical,medium,high")
    os.system("echo \"/opt/nuclei 漏洞扫描结束\"")
    
    os.system(f"cat {output_file} >> temp1.txt")
    
    if os.path.getsize('temp1.txt') == 0:
        print('这是空文件')
    else:
        with open("temp1.txt", "r", encoding='utf-8') as f:
            data = f.read()
        push_wechat_group(str(data))  # 推送nuclei扫描结果
    
    # 删除临时文件
#    os.remove('temp1.txt')
    os.remove('newurls.txtls')
    os.remove(output_file)  # 删除nuclei输出结果文件

def xray(scan_list):
    print(scan_list)
    with open("newurls2.txtls", "w", encoding='utf-8') as f:
        for scan in scan_list:
            if scan != '':
                f.writelines(scan + "\n")
    
    os.system("echo \"开始使用 xray 对新增资产进行漏洞扫描\"")
    
    # 生成文件名的时间戳
    timestamp = str(datetime.datetime.now().strftime('%Y-%m-%d-%H:%M:%S'))
    json_output = f"xray-temp-{timestamp}.json"
    html_output = f"xray-new-{timestamp}.html"
    
    # 执行xray扫描
    os.system(f"proxychains /opt/xpoc -i newurls2.txtls -o {json_output} -o {html_output}")
    
    with open(json_output, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    for i in range(len(data)):
        current_date = str(strftime("%Y-%m-%d %H:%M:%S", gmtime()))
        message_push = "xray漏洞推送:" + '\n' + current_date + '\n'
        message_push += "漏洞类型:" + str(data[i]['plugin']) + '\n' + "目标:" + str(data[i]['target']) + '\n'
        message_push += "payload:" + str(data[i]['detail']['payload']) + '\n' + '\n'
        
        # 过滤掉一些无用的扫描结果
        if 'nginx-wrong-resolve' not in message_push and 'server-error' not in message_push and \
           'cors' not in message_push and 'dedecms' not in message_push and 'crossdomain' not in message_push:
            push_wechat_group(message_push)
    
    # 删除临时文件
#    os.remove(json_output)
#    os.remove(html_output)
    os.remove('newurls2.txtls')

# 主循环部分
while True:
    try:
        # 登录部分
        data = {"username": username, "password": password}
        headers = {'Content-Type': 'application/json; charset=UTF-8'}
        logreq = requests.post(url=arl_url + '/api/user/login', data=json.dumps(data), headers=headers, timeout=300, verify=False)
        result = json.loads(logreq.content.decode())
        
        # 登录状态检查
        if result['code'] == 401:
            print(data, '登录失败')
            sys.exit()
        elif result['code'] == 200:
            print(data, '登录成功', result['data']['token'])
            Token = result['data']['token']

        # 更新请求头部，包含Token
        headers = {'Token': Token, 'Content-Type': 'application/json; charset=UTF-8'}
        print('开始获取最近侦察资产')
 
        # 获取任务列表  page 为页数
        req = requests.get(url=arl_url + '/api/task/?page=1&size=' + str(get_size), headers=headers, timeout=30000, verify=False)
        result = json.loads(req.content.decode())

        # 清空 IDs 列表，并收集所有状态为 'done' 的任务 ID
        ids = []
        for xxx in result['items']:
            if xxx['status'] == 'done':
                ids.append(xxx['_id'])

        # 确保有任务 ID
        if ids:
            data = {"task_id": ids}
            req2 = requests.post(url=arl_url + '/api/batch_export/site/', data=json.dumps(data), headers=headers, timeout=300, verify=False)

            # 检查是否登录失效
            if '"not login"' in req2.text:
                ids = []  # 重置 ID 列表，重新登录
                continue

            # 处理扫描任务的结果
            target_list = req2.text.split()
            file_list = open('./cache.txt', 'r', encoding='utf-8').read().split('\n')
            add_list = set(file_list).symmetric_difference(set(target_list))
            current_time = str(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')).replace(' ', '-').replace(':', '-')

            for xxxx in add_list:
                if xxxx in target_list:
                    with open('./cache.txt', 'a', encoding='utf-8') as caches_file:
                        caches_file.write(xxxx + '\n')
                    print(xxxx)

            # 执行扫描
            nuclei(add_list)  # 启用 nuclei 扫描
            xray(add_list)    # 启用 xray 扫描

        # 每次循环后休眠
        time.sleep(int(time_sleep))

    except Exception as e:
        print(e, '出错了，请排查')
