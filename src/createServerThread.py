from PyQt5.QtCore import Qt,QThread,pyqtSignal
import socket,re,threading,hashlib,ssl
from src.getSystemTime import GetTime

class CreateServer(QThread):
    def __init__(self, ip, port, conn, passwd, uname, teamlogfile):
        super(CreateServer, self).__init__()
        self.ip = ip
        self.port = port
        self.conn = conn
        self.passwd = passwd
        self.uname = uname
        self.stopflag = True
        self.teamlogfile = teamlogfile
        self.user = {}  # 连接用户存放字典
        self.clientSocket = {}  # 存放{socket:不同线程的套接字}
        self.num = 1

    updateConnectSignal = pyqtSignal(int, str)
    updateResult = pyqtSignal(int, str)
    updateTeamlog =pyqtSignal(str)

    def run(self):
        try:
            pattern = re.compile('((2(5[0-5]|[0-4]\d))|[0-1]?\d{1,2})(\.((2(5[0-5]|[0-4]\d))|[0-1]?\d{1,2})){3}')
            ip = pattern.search(self.ip).group()
            port = int(self.port)
            conn = int(self.conn)
            if ip and port and conn:
                # 创建socket对象
                self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.s = ssl.wrap_socket(self.s, keyfile='docs/chat.key', certfile='docs/chat.cer', server_side=True)
                addr = (ip, port)
                # addr = ('0.0.0.0', port)
                # 绑定端口和地址
                self.s.bind(addr)
                self.s.listen(conn)
                time = GetTime.getSystemTime4()
                self.updateResult.emit(1, "{} TCP Server on {}:{}...".format(time, addr[0], str(addr[1])))
                while True:
                    # self.updateResult.emit(1, "等待客户端的连接请求...")
                    newClient, addr = self.s.accept()
                    # 验证密码
                    md5 = hashlib.md5()
                    md5.update((self.passwd).encode("utf-8"))
                    md5Passwd = md5.hexdigest()
                    verifyPasswd = (newClient.recv(1024)).decode()
                    # print(md5Passwd,verifyPasswd)
                    if verifyPasswd == md5Passwd:
                        newClient.send("YES".encode("utf-8"))
                        time = GetTime.getSystemTime4()
                        self.updateResult.emit(1, "{} 接收到客户端 {}:{} 的连接请求.".format(time, addr[0], str(addr[1])))
                        self.updateTeamlog.emit("{} 接收到客户端 {}:{} 的连接请求.".format(time, addr[0], str(addr[1])))
                        data = newClient.recv(1024)
                        time = GetTime.getSystemTime4()
                        if data.decode() == 'error1':
                            self.updateResult.emit(1, "{} 客户端 {}:{} 已断开连接.".format(time, addr[0], str(addr[1])))
                            self.updateTeamlog.emit("{} 客户端 {}:{} 已断开连接.".format(time, addr[0], str(addr[1])))
                            continue
                        self.num = self.num + 1
                        self.clientSocket[addr] = newClient
                        # 如果addr不在user字典则执行以下代码：
                        if not addr in self.user:
                            uname = data.decode('utf-8').split(":")[0]
                            time = GetTime.getSystemTime4()
                            for client in self.clientSocket:
                                self.clientSocket[client].send(("[ {} ]进入聊天室，当前聊天人数：{}").format(uname,self.num).encode("utf-8"))
                            self.updateResult.emit(1, ("{} [ {} ]进入聊天室，当前聊天人数：{}").format(time,uname,self.num))
                            self.updateTeamlog.emit(("{} [ {} ]进入聊天室，当前聊天人数：{}").format(time,uname,self.num))
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
            else:
                self.updateConnectSignal.emit(0, "请检查输入信息是否有误。")
        except OSError as e:
            print(e)
        except WindowsError as e:
            print(e)
            # print(self.port + "端口已被占用。")
            # self.updateResult.emit(1, self.port + "端口已被占用。")
        except Exception as e:
            print(e)

    def chat(self, newClient, addr):
        while True:
            d = newClient.recv(1024)
            print(d)
            if (('exit' in d.decode('utf-8'))):
                name = self.user[addr]
                self.user.pop(addr)
                self.clientSocket.pop(addr)
                time = GetTime.getSystemTime4()
                for client in self.clientSocket:
                    self.clientSocket[client].send( '{} [ {} ]离开了聊天室，当前聊天人数：{}'.format(time, name, self.num).encode('utf-8'))
                self.updateResult.emit(1, '{} [ {} ]离开了聊天室，当前聊天人数：{}'.format(time, name, self.num))
                self.updateTeamlog.emit('{} [ {} ]离开了聊天室，当前聊天人数：{}'.format(time, name, self.num))
                self.num = self.num - 1
                break
            else:
                time = GetTime.getSystemTime4()
                message = d.decode("utf-8")
                self.updateResult.emit(1, "{} [ {} ] : {}".format(time, message.split(":")[0], "".join((message.split(":")[1::]))))
                self.updateTeamlog.emit("{} [ {} ] : {}".format(time, message.split(":")[0], "".join((message.split(":")[1::]))))
                # 向所有连接用户群发消息，除了发消息本身的用户
                for client in self.clientSocket:
                    if self.clientSocket[client] != newClient:
                        self.clientSocket[client].send(d)

    def sendMessage(self, message):
        try:
            if message:
                message = '{}:{}'.format(self.uname, message)
                data = message.encode('utf-8')
                for client in self.clientSocket:
                    self.clientSocket[client].send(data)
                time = GetTime.getSystemTime4()
                self.updateResult.emit(1, "{} [ {} ] : {}".format(time, (data.decode('utf-8')).split(":")[0], "".join((data.decode('utf-8')).split(":")[1::])))
                self.updateTeamlog.emit("{} [ {} ] : {}".format(time, message.split(":")[0], "".join((data.decode('utf-8')).split(":")[1::])))
                # self.updateResult.emit(1, time + data.decode('utf-8'))
                # self.updateTeamlog.emit(time + data.decode('utf-8'))
        except Exception as e:
            print(e)

    def saveTeamLog(self, message):
        try:
            with open(self.teamlogfile, "a+" ,encoding='utf-8') as f:
                f.write(message + "\n")
            f.close()
        except Exception as e:
            print(e)

    def stop(self, message):
        self.stopflag = False
        self.s.close()
        time = GetTime.getSystemTime4()
        self.updateResult.emit(0, "{} {} 已断开连接。".format(time,message))
        self.updateTeamlog.emit("{} {} 已断开连接。".format(time, message))