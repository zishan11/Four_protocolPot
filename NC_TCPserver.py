# -*- coding: utf-8 -*-
# @Time    : 2018/8/20 下午9:32
# @Author  : shijie luan
# @Email   : lsjfy0411@163.com
# @File    : TCP_server.py
# @Software: PyCharm

import socket
import threading
import time

import pymysql
import sys
import binascii

# sys.path.append(r"/Users/luanshijie/研究生课程学习内容/深度学习与安全/website_fingerprinter/network_coding/")
import connect_database
import classify
import logging
# list_mysql = [{},{}]




# config = {
#     'host': '127.0.0.1',
#     'port': 3306,
#     # 'db': 'fanuc',
#     'db':'enmergency_program',
#     'user': 'fanuc',
#     'passwd': 'fanuc123',
#     'charset': 'utf8mb4',
#     'cursorclass': pymysql.cursors.DictCursor
# }

config = {
    'host': '127.0.0.1',
    'port': 3306,
    'db':'fanuc',
    # 'db':'enmergency_program',
    'user': 'fanuc',
    # 'user': 'root',
    'passwd': 'fanuc123',
    # 'passwd': 'lsj940411',
    'charset':'utf8mb4',
    'cursorclass':pymysql.cursors.DictCursor
    }

db = connect_database.connectDB(config)

'''
测试：
data = "a0a0a0a00001010100020001"
    #第一步：构建sql语句
request = connect_database.remakeResquest(data)
sql_clause = connect_database.createSql(request)
#第二步：连接数据库
db = connect_database.connectDB(config)

#第三步：查询返回数据
results = connect_database.searchData(db,sql_clause)
print(results[0]['response_data'])
'''


def processRecv(strRecv,protocol):
    '''
    此函数主要为了分割传入的流字节，在测试中发现机床是具有分割功能的，所以我们采用简单的方式，即以'a0a0a0a0'作分割
    :param strRecv: 传入的字节流，str类
    :return: 返回一个包含多个请求包的list
    :注意：如果该流正常，则第一个元素应当为空，所以我们也可做判断，是否为黑客的异常包，故我在这设一个3级警报，即疑似。
    如何设置？如何对全局进行影响，这是需要讨论的一点
    '''
    if protocol == 'fanuc':
        all = strRecv.split('a0a0a0a0')
        # print(all)
        for i in all:
            if i == '':
                all.remove(i)
        # if all[0] == '' and all[-1]:
        #     all.remove('')
        if all != []:
            for i in range(len(all)):
                all[i] = 'a0a0a0a0' + all[i]
                # print(all[i])
        else:
            # 此处设置警报信息
            # 造成这种情况的包一般是'a0a0a0a0'或''
            pass
        # print(all)
        return all
    else:
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


def classifyS(requestStr):
    '''
    此为分类模块，用来识别报文属于哪一功能
    可能用到的算法：字符串相似度匹配
    :return: 返回类别
    '''
    all_D = classify.calculateD(requestStr)
    function_R = classify.GetFunction(all_D)
    return function_R


def filter():
    '''
    过滤模块  用来用一些规则对请求报文处理，若无威胁->数据库交互模块
                                    若有威胁->数据捕获模块
                                          ->报文给报警模块
    :return:
    '''
    return 0

def messageLog(request_log,response_log,function_log):
    # if request_log!= '' and response_log!='' and function_log!='':
    message = 'request:{0},response:{1},function:{2}'.format(request_log,response_log,function_log)
    return message

def capture(messageUnknow):
    '''
    数据捕获模块：待讨论  ->日志模块
                     ->未知请求数据库
    :return:
    '''
    file = './Capture/captureUnknow.txt'
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s-%(message)s')
    handler = logging.FileHandler(file, 'a')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.info(messageUnknow)
    # logger.info(response_log)
    return 0



def alarm():
    '''
    报警模块：根据报文进行威胁分级 ->守护进程
    :return:返回等级
    '''
    return 0


def CNCLog(addr,message_log):
    '''
    日志模块：记录日志 收否需要根据等级去进行记录，还是什么都记录，这点需要讨论
    :return:
    '''
    # ip = addr[0]
    # port = addr[1]
    file = './MyLog/{0}:{1}_log.txt'.format(addr[0],addr[1])
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s-%(message)s')
    handler = logging.FileHandler(file,'a')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.info(message_log)
    # logger.info(response_log)
    return 0



def setSockRecvOverTime(s, maxtime):
    s.settimeout(maxtime)

def setTimeout(count,num):
        time.sleep(1)
        if count > num:
            sock.close()


# def


def b2a_str(data_temp,protocol):
    # 将网络字节流转为ascii码
    data = binascii.b2a_hex(data_temp)
    data = data.decode('utf-8')
    # print(type(str(data)))
    # 将字节流转为list
    request_list = processRecv(data,protocol)
    return request_list

def attackProcess(data_temp):
    data = binascii.b2a_hex(data_temp)
    data = data.decode('utf-8')
    return data

def tcplink(sock, addr):
    '''
    这是一对一的连接，多对多的，一对多的和多对一的之后再实现
    :param sock:
    :param addr:
    :return:
    '''
    # setSockRecvOverTime(sock,20)
    print("Accept new connection from %s:%s" % addr)
    # print(addr)
    # sock.send(b'Welcome!')
    count = 0
    # while binascii.b2a_hex(data_temp) != "":
    while True:
        # data_temp = sock.recv(1024)
        # time.sleep(1)
        # try:


        #此处用于处理没有数据包过来的情况
        #用于模拟超时
        count = count + 1
        # print(time.clock())
        try:
            data_temp = sock.recv(1024)
            print(data_temp)
            # CNCLog(addr,binascii.b2a_hex(data_temp).decode('utf-8'))
            # time.sleep(1)
            if count > 100:
                sock.close()
                break
        except BlockingIOError as e:
        # except:
            time.sleep(1)
            if count > 100:
                sock.close()
                break
            else:
                # print(count)
                continue
        # print('count:%d'%count)

        #当请求又来的时候，重置count
        # count = 0
        # print(time.clock())
        # if len(data_temp) == 0:
        #     sock.close()
        # except:
        #     time.sleep(1)
        #     count +=1
        #     data_temp = sock.recv(1024)
        #     if data_temp == 0 and count==10:
        #         break
        # except:
        #     break

        # 将网络字节流转为ascii码
        request_list = b2a_str(data_temp,protocol='fanuc')
        if request_list == [] and data_temp!= b'':
            '''
            此处有蹊跷，需更改测试
            '''
            print(data_temp)
        # 第一步：判断是否属于正常的FOCAS协议报文
        #是否用聚类算法或是分类算法
        if request_list != [] and data_temp!= b'':
            count = 0
            # 是则执行主流程
            # 此时分两种方法    1）一种简单的：直接搜数据库
            # 对每个进行处理成sql的形式
            # 此处应当模块化
            if len(request_list) >= 1:
                # 这里设置1的原因是：processRecv()函数分割字节流的时候以'a0a0a0a0'为标志。
                # 更改了，大于等于1
                for i in request_list:
                    #分类
                    i_function = classifyS(i)

                    request = connect_database.remakeResquest(i)
                    sql_clause = connect_database.createSql(request)
                    results = connect_database.searchData(db, sql_clause)
                    # print(sql_clause)
                    time_now = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time()))
                    print(results)

                    if results != ():
                        #非空时输出日志
                        '''
                        暂时不存
                        # messageL = messageLog(i, results[0]['response_data'], results[0]['functions'])
                        # CNCLog(addr,messageL)
                        '''

                        sock.send(binascii.a2b_hex(results[0]['response_data']))
                    elif i_function != '':
                        print(i_function)
                        #对于未知的包，统统抓取

                        if i != '':
                            # messageUnknow = messageLog(i, '', '')
                            capture(binascii.b2a_hex(data_temp).decode('utf-8'))
                        '''有该类的话查找，没有的话报警
                        '''
                        #如果没直接搜到结果，就选择该类的第一个报文回复
                        sql_clause = connect_database.createSql(connect_database.remakeResquest(i_function),flag=2)
                        print(sql_clause)
                        results = connect_database.searchData(db,sql_clause)
                        sock.send(binascii.a2b_hex(results[0]['response_data']))
                        print(results)

                        '''
                        当时是要干嘛？忘记了
                        # if results != () and i!='':
                        #      messageL = messageLog(i,results[0]['response_data'],i_function)
                        #     CNCLog(addr,messageL)
                        #     # print(results)
                        #     sock.send(binascii.a2b_hex(results[0]['response_data']))
                        '''
                        # else:
                        #     #有该类，但是没存数据，这种情况应该比较少见
                        #     alarm()
                            # if i!= '':
                            #     messageL = messageLog(i,'',i_function)
                            #     CNCLog(addr)
                            # capture()
                    # else:
                        '''
                        此处需要，但是分类还未完善，所以暂时注释
                        '''
                    #     #分类也找不到的话，说明没有见过该类的，异常级别应当设置高些
                    #     alarm()
                    #     messageL = messageLog(i,'NO response','Unknown Function')
                    #     CNCLog(addr,messageL)
                        # capture()
            # 2）第二种方法则是：先分类，再根据当前类中是否存在该请求对，存在则返回
            #                                               不存在则依解析，依策略回复该类的应答包
        # elif data_temp != '':
        #     #这是为空的，不属于fanuc协议的部分
        #     requestAttack = attackProcess(data_temp)
        #     print(requestAttack)
        #     messageAttack = messageLog(requestAttack,'NOT FANUC Protocol','NO FUNCTION')
        #     capture(messageAttack)
            #     # 否则
            #     request = connect_database.remakeResquest(request_list[0])
            #     sql_clause = connect_database.createSql(request)
            #     print(sql_clause)
            #     results = connect_database.searchData(db, sql_clause)
            #     print(results)
            #     if results != ():
            #         sock.send(binascii.a2b_hex(results[0]['response_data']))
            #     else:
            #         # sock.close()
            #         # 此时不发包,
            #         sock.send(binascii.a2b_hex("a0a0a0a0"))
            #         pass
                    # if sock

                    # while data_temp == 0:
                    #     data_temp = sock.recv(1024)
                    # 设置延迟
                    # a0a0a0a0000421020012000100100001000100050005000200000000
                    # time.sleep(0.2)

                    # 此处用于数据捕获
                    # data_temp = sock.recv(1024)
    try:
        sock.close()
    except:
        print('error')
    print('Connection from %s:%s closed.' % addr)

    # 什么时候关闭此时的会话连接呢？是设置时间还是。。
    # sock.close()
    # print('Connection from %s:%s closed.'%addr)


def openFanuc(ip,port=8193):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # s.bind(('192.168.127.94', 8193))
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
        t = threading.Thread(target=tcplink, args=(sock, addr))
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
    openFanuc(ip_addr)
    # 开启服务，8193端口



