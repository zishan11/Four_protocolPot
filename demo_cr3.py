# -*- coding: utf-8 -*-
# @Time    : 2018/9/6 下午2:13
# @Author  : shijie luan
# @Email   : lsjfy0411@163.com
# @File    : demo_protocol.py
# @Software: PyCharm

'''
本模块主要是为了和10个协议的仿真接轨，可以复用数据库模块、server模块、分类模块

鉴于FANUC蜜罐已经实现了各模块，所以此模块改动前可参照上述提到的几个模块

基本思路：
    1.筛选10个协议：需要 请求（最好是nmap脚本的，没有也可以标明功能）—— 应答对
    2.数据库存储：id-请求-应答-协议-功能，复用connect_database.py(用来连接数据库)、
                具体数据库的填充用人工还是自动化填充，看心情，如果自动化的就可以复用docker_mysql.py
    3.分类：复用classify.py，目前只做10个协议单一类的，所以在模版一侧添加的数据只需要一个协议一个dict即可
    4.切换：启动时，每个协议对应server端的一个socket，绑定一个端口，若存在多个协议对应一个端口，则复用该端口


注意：只有协议和端口都稳合才可以回复响应的回复
'''

import binascii
import socket
import threading
import time
import sys
#1111111111114675636b20596f7521205a68616e67205a6875616e677a6875616e672111

data = [{'request_data':'0004012b1b00',
'response_data':'111111111111526564204c696f6e20436f6e74726f6c7311',
# 'response_data':'1111111111114675636b20596f7521205a68616e67205a6875616e677a6875616e672111',
'function':'cotp','id':1},
{'request_data':'0004012a1a00',
'response_data':'11111111111147333130433211',
'function':'cotp','id':2}]
#70001c0001002a00000000000000000000000000000000000000000001000200a1000400224095ffb1000800e7000602208e2401
# 0300007d02f080320700000000000c0060000112081284010100000000ff09005c00110001001c0003000136455337203231352d31414734302d3058423020000000012020000636455337203231352d31414734302d3058423020000000012020000736455337203231352d31414734302d3058423020000056040000
# data = {id:1,
#  'request_data':'',
# 'response_data':'',
# 'protocol':'S7',
# 'functions':'get_info'}
def processRecv(strRecv):
    all = strRecv.split('030000')
    # print(all)
    for i in all:
        if i == '':
            all.remove(i)
    # if all[0] == '' and all[-1]:
    #     all.remove('')
    if all != []:
        for i in range(len(all)):
            all[i] = '030000' + all[i]
            # print(all[i])
    else:
        # 此处设置警报信息
        # 造成这种情况的包一般是'a0a0a0a0'或''
        pass
    # print(all)
    return all

def b2a_str(data_temp):
    # 将网络字节流转为ascii码
    data_recv = binascii.b2a_hex(data_temp)
    data_recv = data_recv.decode('utf-8')
    # print(type(str(data)))
    # 将字节流转为list
    # request_list = processRecv(data)

    return data_recv

def processRequest(request):
    return 0

def findresponse(request):
    #此处的request为ascii码格式
    for i in data:
        if i['request_data'] == request:
            return binascii.a2b_hex(i['response_data'])

def cr3link(sock,addr):
    time_now = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time()))
    print("{0} Accept new connection from {1}:{2}".format(time_now,addr[0],addr[1]))
    count = 0
    id = 0
    while True:
        if count <= 100:
            try:
                data_temp = sock.recv(1024)
                if data_temp != b'':
                    # print(data_temp)
                    # print(count)
                    # time.sleep(0.1)
                    data_recv = b2a_str(data_temp)
                    #打印时间
                    time_now = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time()))
                    print("%s request:%s"%(time_now,data_recv))
                    # if request_list[0]['function'] == 'cotp' and request_list[0]['id'] < 1:
                    #     id += 1
                    # else:
                    try:
                        response_data = findresponse(data_recv)
                        sock.send(response_data)
                        time_now = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time()))
                        print("%s response:%s" % (time_now, response_data))
                        count = 0
                    except:
                        time_now = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time()))
                        print('%s response cannot find!%s'%(time_now,data_recv))
                        sock.send(binascii.a2b_hex('0300001611d00005001000c0010ac1020100c2020200'))
                        print("%s response:%s" % (time_now, '0300001611d00005001000c0010ac1020100c2020200'))
                else:
                    count += 1

            except:
                count += 1
                # print(time_now,' no request!')
                # sock.send(binascii.a2b_hex('0300001611d00005001000c0010ac1020100c2020200'))

        else:
            sock.close()
            time_now = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time()))
            print("%s connection from %s:%s has been broken!" %(time_now,addr[0],addr[1]))
            break
        time.sleep(0.2)
    sock.close()

def opencr3(ip,port=789):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # s.bind(('127.0.0.1', 102))
    #s.bind(('192.168.127.94', 102))
    s.bind((ip, port))
    # 设置最大连接数
    s.listen(100)
    # s.setblocking(0)
    # s.setblocking(0)
    print('Waiting for connecting...')
    '''
    建立连接的server
    '''

    while True:
        sock, addr = s.accept()
        # 设置为非阻塞式
        sock.setblocking(False)
        t = threading.Thread(target=cr3link, args=(sock, addr))
        t.start()
    print("ok")


# 可以封装成函数，方便 Python 的程序调用
def get_host_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    finally:
        s.close()

    return ip


if __name__ == "__main__":
    ip_addr = get_host_ip()
    if ip_addr == '':
        # ip_port = sys.argv[1]
    # else:
        try:
            ip_addr = sys.argv[1]
            # ip_port = sys.argv[2]
        except:
            print("error, You have to input your ip address")

    # if sys.argv[1] != '':
    #     address = sys.argv[1]
    #     if sys.argv[2] != '':
    #         port = sys.argv[2]
    # else:
    #     print("error! You haven't input the ip address of your computer!")
    opencr3(ip_addr)


# print(find(data))




