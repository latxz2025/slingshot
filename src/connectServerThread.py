from PyQt5.QtCore import Qt,QThread,pyqtSignal
import socket,re,threading,hashlib,ssl
from src.getSystemTime import GetTime

class ConnectServer(QThread):
    def __init__(self, ip, port, passwd, uname, teamlogfile):
        super(ConnectServer, self).__init__()
        self.ip = ip
        self.port = port
        self.passwd = passwd
        self.uname = uname
        self.teamlogfile = teamlogfile
        self.stopflag = True
        self.is__running = True

    # updateConnectSignal 两个参数：第一个（0，1）表示是否连接成功。
    updateConnectSignal = pyqtSignal(int, str)
    # updateResult 有两个参数：第一个（0，1），断开连接时会发送0，更新连接界面；第二个为正常的message
    updateResult = pyqtSignal(int, str)
    updateTeamlog = pyqtSignal(str)

    def run(self):
        try:
            pattern = re.compile('((2(5[0-5]|[0-4]\d))|[0-1]?\d{1,2})(\.((2(5[0-5]|[0-4]\d))|[0-1]?\d{1,2})){3}')
            ip = pattern.search(self.ip).group()
            port = int(self.port)
            # print(ip, str(port), self.passwd, self.uname, self.teamlogfile)
            if ip and port:
                self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server = (ip, port)
                self.s = ssl.wrap_socket(self.s, keyfile='docs/chat.key', certfile='docs/chat.cer',server_side=False)
                # 建立连接
                self.s.connect(server)
                # 发送密码验证
                md5 = hashlib.md5()
                md5.update((self.passwd).encode("utf-8"))
                md5Passwd = md5.hexdigest()
                self.s.send(md5Passwd.encode('utf-8'))
                data = (self.s.recv(1024)).decode('utf-8')
                # print(data)
                if data == "YES":
                    self.updateConnectSignal.emit(1, "与服务器连接成功！现在可以使用团队聊天功能了。")
                    time = GetTime.getSystemTime4()
                    message = time + " 已连接服务器 {}".format(self.ip)
                    self.updateResult.emit(1, message)
                    self.updateTeamlog.emit(message)
                    # 开启一个接收消息守护线程
                    # daemon=True 表示创建的子线程守护主线程，主线程退出子线程直接销毁
                    self.recvThread = threading.Thread(target=self.recvMessage)
                    self.recvThread.start()
                else:
                    self.updateConnectSignal.emit(0, "请检查输入密码是否有误。")
                    self.s.close()
            else:
                self.updateConnectSignal.emit(0, "请检查输入信息是否有误。")
        except ConnectionRefusedError:
            print("与目标主机连接失败，请检查网络")
            self.updateConnectSignal.emit(0, "与目标主机连接失败，请检查网络！")
            pass
        except Exception as e:
            print(e)
            self.updateConnectSignal.emit(0, "与目标主机连接失败，请检查网络或输入信息是否有误。")

    def recvMessage(self):
        try:
            self.s.send(self.uname.encode('utf-8'))
            while True:
                if self.stopflag:
                    data = self.s.recv(1024)
                    if data:
                        time = GetTime.getSystemTime4()
                        message = data.decode('utf-8')
                        if ":" in message:
                            self.updateResult.emit(1, "{} [ {} ] : {}".format(time, message.split(":")[0], "".join((message.split(":")[1::]))))
                            self.updateTeamlog.emit("{} [ {} ] : {}".format(time, message.split(":")[0], "".join(message.split(":")[1::])))
                        else:
                            self.updateResult.emit(1, "{} {}".format(time, message))
                            self.updateTeamlog.emit("{} {}".format(time, message))
                    else:
                        self.stop("服务端")
                else:
                    break
        except Exception as e:
            print(e)

    def sendMessage(self, message):
        try:
            if message:
                message = '{}:{}'.format(self.uname, message)
                data = message.encode('utf-8')
                self.s.send(data)
                time = GetTime.getSystemTime4()
                self.updateResult.emit(1, "{} [ {} ] : {}".format(time, message.split(":")[0], "".join((message.split(":")[1::]))))
                self.updateTeamlog.emit("{} [ {} ] : {}".format(time, message.split(":")[0], "".join((message.split(":")[1::]))))
        except Exception as e:
            print(e)

    def stop(self, message):
        # try:
        #     if self.is__running:
        #         self.is__running = False
        #         self.terminate()
        # except Exception as e:
        #     print(e)
        self.stopflag = False
        self.s.send("exit".encode('utf-8'))
        self.s.close()
        time = GetTime.getSystemTime4()
        self.updateResult.emit(0, time + " {} 已断开连接。".format(message))
        self.updateTeamlog.emit(time + " {} 已断开连接。".format(message))

    def saveTeamLog(self, message):
        try:
            with open(self.teamlogfile, "a+" ,encoding='utf-8') as f:
                f.write(message + "\n")
            f.close()
        except Exception as e:
            print(e)


