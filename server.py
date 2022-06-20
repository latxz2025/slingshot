import socket,ssl,hashlib,threading,re,sys,getopt,time,datetime,random,signal
from concurrent.futures import ThreadPoolExecutor

class CreateServer:
    def __init__(self, ip, port, num, passwd, uname, t):
        self.ip = ip
        self.port = port
        self.conn = num    # 连接数
        self.passwd = passwd
        self.uname = uname
        self.stopflag = True
        self.teamlogfile = 'docs/teamlog/log - {}.txt'.format(t)
        self.user = {}  # 连接用户存放字典
        self.clientSocket = {}  # 存放{socket:不同线程的套接字}
        self.num = 1

    def run(self):
        try:
            # print(ip,str(self.port),str(self.conn),self.passwd,self.uname,self.teamlogfile)
            # 创建socket对象
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s = ssl.wrap_socket(s, keyfile='docs/chat.key', certfile='docs/chat.cer', server_side=True)
            addr = (self.ip, self.port)
            # addr = ('0.0.0.0', port)
            # 绑定端口和地址
            s.bind(addr)
            s.listen(self.conn)
            time = GetTime.getSystemTime4()
            print("{} TCP Server on {}:{}...".format(time, addr[0], str(addr[1])))
            self.saveTeamLog("{} TCP Server on {}:{}...".format(time, addr[0], str(addr[1])))
            while True:
                # self.updateResult.emit(1, "等待客户端的连接请求...")
                newClient, addr = s.accept()
                # 验证密码
                md5 = hashlib.md5()
                md5.update((self.passwd).encode("utf-8"))
                md5Passwd = md5.hexdigest()
                verifyPasswd = (newClient.recv(1024)).decode()
                # print(md5Passwd,verifyPasswd)
                if verifyPasswd == md5Passwd:
                    newClient.send("YES".encode("utf-8"))
                    time = GetTime.getSystemTime4()
                    print("{} 接收到客户端 {}:{} 的连接请求.".format(time, addr[0], str(addr[1])))
                    self.saveTeamLog("{} 接收到客户端 {}:{} 的连接请求.".format(time, addr[0], str(addr[1])))
                    data = newClient.recv(1024)
                    time = GetTime.getSystemTime4()
                    if data.decode() == 'error1':
                        print("{} 客户端 {}:{} 已断开连接.".format(time, addr[0], str(addr[1])))
                        self.saveTeamLog("{} 客户端 {}:{} 已断开连接.".format(time, addr[0], str(addr[1])))
                        continue
                    self.num = self.num + 1
                    self.clientSocket[addr] = newClient
                    # 如果addr不在user字典则执行以下代码：
                    if not addr in self.user:
                        uname = data.decode('utf-8').split(":")[0]
                        time = GetTime.getSystemTime4()
                        for client in self.clientSocket:
                            self.clientSocket[client].send(("[ {} ]进入聊天室，当前聊天人数：{}").format(uname,self.num).encode("utf-8"))
                        print("{} [ {} ]进入聊天室，当前聊天人数：{}".format(time,uname,self.num))
                        self.saveTeamLog("{} [ {} ]进入聊天室，当前聊天人数：{}".format(time,uname,self.num))
                        # 发送user字典的data和address到客户端
                        # 用户连接到服务器后就会发送一个 用户名 数据包
                        self.user[addr] = uname
                        self.clientSocket[addr] = newClient
                    # 为客户端连接分配线程
                    client = threading.Thread(target=self.chat, args=(newClient, addr))
                    client.start()
                else:
                    newClient.send("NO".encode("utf-8"))
                    newClient.close()
        except OSError as e:
            print(e)
        except KeyboardInterrupt as e:
            print(e)
            # print(self.port + "端口已被占用。")
            # self.updateResult.emit(1, self.port + "端口已被占用。")
        except Exception as e:
            print(e)

    def chat(self, newClient, addr):
        while True:
            d = newClient.recv(1024)
            # print(d)
            if (('exit' in d.decode('utf-8'))):
                name = self.user[addr]
                self.user.pop(addr)
                self.clientSocket.pop(addr)
                time = GetTime.getSystemTime4()
                self.num = self.num - 1
                for client in self.clientSocket:
                    self.clientSocket[client].send( '{} [ {} ]离开了聊天室，当前聊天人数：{}'.format(time, name, self.num).encode('utf-8'))
                print('{} [ {} ]离开了聊天室，当前聊天人数：{}'.format(time, name, self.num))
                self.saveTeamLog('{} [ {} ]离开了聊天室，当前聊天人数：{}'.format(time, name, self.num))

                break
            else:
                time = GetTime.getSystemTime4()
                message = d.decode("utf-8")
                print("{} [ {} ] : {}".format(time, message.split(":")[0], "".join((message.split(":")[1::]))))
                self.saveTeamLog("{} [ {} ] : {}".format(time, message.split(":")[0], "".join((message.split(":")[1::]))))
                # 向所有连接用户群发消息，除了发消息本身的用户
                for client in self.clientSocket:
                    if self.clientSocket[client] != newClient:
                        self.clientSocket[client].send(d)

    # def sendMessage(self, message):
    #     try:
    #         if message:
    #             message = '{}:{}'.format(self.uname, message)
    #             data = message.encode('utf-8')
    #             for client in self.clientSocket:
    #                 self.clientSocket[client].send(data)
    #             time = GetTime.getSystemTime4()
    #             self.updateResult.emit(1, "{} [ {} ] : {}".format(time, (data.decode('utf-8')).split(":")[0], "".join((data.decode('utf-8')).split(":")[1::])))
    #             self.updateTeamlog.emit("{} [ {} ] : {}".format(time, message.split(":")[0], "".join((data.decode('utf-8')).split(":")[1::])))
    #             # self.updateResult.emit(1, time + data.decode('utf-8'))
    #             # self.updateTeamlog.emit(time + data.decode('utf-8'))
    #     except Exception as e:
    #         print(e)

    def saveTeamLog(self, message):
        try:
            with open(self.teamlogfile, "a+" ,encoding='utf-8') as f:
                f.write(message + "\n")
            f.close()
        except Exception as e:
            print(e)

class GetTime:
    def __init__(self):
        pass

    # 时间格式 202241515578832
    def getSystemTime1():
        nowTime = datetime.datetime.now()
        t = str(nowTime.year)+str(nowTime.month)+str(nowTime.day)+str(nowTime.hour)+str(nowTime.minute)+str(nowTime.second)+str(random.randint(100,999))
        return t

    # 时间格式 2016-04-07 10:25:09
    def getSystemTime2():
        nowTime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        # print(nowTime)
        return nowTime

    # 时间格式 datetime.datetime(2022, 5, 26, 15, 24, 58, 427333)
    def getSystemTime3():
        nowTime = datetime.datetime.now()
        # 时间格式 202241515578832
        # t = str(nowTime.year)+str(nowTime.month)+str(nowTime.day)+str(nowTime.hour)+str(nowTime.minute)+str(nowTime.second)+str(random.randint(100,999))
        t = nowTime
        return t

    # 时间格式 2020-4-15-3 15点15分15秒
    def getSystemTime4():
        nowTime = time.localtime(time.time())
        t = ("{}-{}-{} {}点{}分{}秒".format(nowTime[0], nowTime[1], nowTime[2], nowTime[3], nowTime[4], nowTime[5]))
        return t

    # 时间格式 time.struct_time(tm_year=2022, tm_mon=4, tm_mday=18, tm_hour=13, tm_min=56, tm_sec=50, tm_wday=0, tm_yday=108, tm_isdst=0)
    def getSystemTime5():
        nowTime = time.localtime(time.time())
        t = ("{}{}{}".format(nowTime[0], nowTime[1], nowTime[2]))
        return t

if __name__ == "__main__":
    try:
        usage = '''
            用法：
                    参数            解释
                    -h,--help       查看帮助
                    -i,--ip          监听ip，默认 0.0.0.0
                    -p,--port       监听端口，默认 9999
                    -n,--num         连接数，默认 100
                    -u,--uname       用户名，默认 admin
                    -c,--code        连接密码，默认 admin123456@
            '''
        len_argv = len(sys.argv)
        argv = sys.argv[1:]
        pattern = re.compile('((2(5[0-5]|[0-4]\d))|[0-1]?\d{1,2})(\.((2(5[0-5]|[0-4]\d))|[0-1]?\d{1,2})){3}')
        opts, args = getopt.getopt(argv, "hi:p:n:u:c:", ["help", "ip=", "port=", "num=", "uname=", "code="])
        ip, port, num, uname, passwd = '', 0, 0, '', ''
        if len_argv == 1:
            ip,port,num,uname,passwd = "0.0.0.0",9999,100,'admin','admin123456@'
        elif len_argv == 2:
            for opt, arg in opts:
                if opt in ['-h']:
                    print(usage)
        elif len_argv == 11:
            for opt, arg in opts:
                if opt in ['-i']:
                    ip = pattern.search(arg).group()
                elif opt in ['-p']:
                    port = int(arg)
                elif opt in ['-n']:
                    num = int(arg)
                elif opt in ['-u']:
                    uname = arg
                elif opt in ['-c']:
                    passwd = arg
        else:
            print(usage)
        # print(len_argv)
        # print(ip, str(port), str(num), uname, passwd)
        if ip and port and num and uname and passwd:
            t = GetTime.getSystemTime5()
            server = CreateServer(ip, port, num, passwd, uname, t)
            server.run()
    except Exception as e:
        print(e)