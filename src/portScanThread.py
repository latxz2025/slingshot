from PyQt5.QtCore import Qt, QThread, pyqtSignal
import queue,socket,time,threading,select
from src.getSystemTime import GetTime
from concurrent.futures import ThreadPoolExecutor, as_completed

lock = threading.Lock()

class PortScan(QThread):
    def __init__(self, concurrency, timeout, scanIp, scanPort):
        super(PortScan, self).__init__()
        self.concurrency = concurrency
        self.timeout = timeout
        self.scanIp = scanIp
        self.scanPort = scanPort
        self.is__running = True
        self.scanPortList = []
        self.threads = []
        # self.scanResultQueue = queue.Queue()
        # self.endFlag = True

    updateResult = pyqtSignal(str, str, str, str)
    updateTipsInfo = pyqtSignal(int, str)

    def run(self):
        try:
            startTime = GetTime.getSystemTime3()
            self.concurrency = 10 if self.concurrency == '' else int(self.concurrency)
            self.timeout = 3000 if self.timeout == '' else int(self.timeout)

            # ip去除换行键 \n ，str -> list，得到单个IP
            ipList = (self.scanIp.replace('\n', ',')).split(',')
            # ip去除空字符串
            ipList = list(filter(None, ipList))
            # ip去除 http:// 或 https:// 如果存在
            ipList = [(i.replace('http://', '') if 'http://' in i else i.replace('https://', '')) for i in ipList]
            # ip去重
            newIpList = list(set(ipList))
            newIpList.sort(key=ipList.index)
            # 将ip列表写进队列
            ipQueue = queue.Queue()
            for line in ipList:
                ipQueue.put(line)

            # 处理端口 str -> list ，去空
            portList = self.scanPort.split(",")
            portList = list(filter(None, portList))
            for port in portList:
                if "-" in port :
                    pl = port.split("-")
                    for i in range(int(pl[0]), int(pl[1]) + 1):
                        self.scanPortList.append(str(i))
                else:
                    self.scanPortList.append(port)
            # port去重
            l = self.scanPortList
            self.scanPortList = list(set(l))
            self.scanPortList.sort(key=l.index)
            del l
            # 多线程扫描
            # while not ipQueue.empty():
            #     ip = ipQueue.get()
            #     if ip:
            #         for port in self.scanPortList:
            #             thread_ = threading.Thread(target=self.useSocketScan, args=(ip, port,))
            #             self.threads.append(thread_)
            # for thread in self.threads:
            #     thread.start()
            # for thread in self.threads:
            #     thread.join()
            # 线程池
            with ThreadPoolExecutor(max_workers=self.concurrency) as pool:
                self.t_list = []
                while not ipQueue.empty():
                    ip = ipQueue.get()
                    if ip:
                        for port in self.scanPortList:
                            t = pool.submit(self.useSocketScan, ip, port)
                            self.t_list.append(t)

                for future in as_completed(self.t_list):
                    data = future.result()
                    if data:
                        time = GetTime.getSystemTime4()
                        # print("{}:{}".format(time,data))
                        self.updateResult.emit(data[0], data[1], data[2], data[3])
            pool.shutdown()
            endTime = GetTime.getSystemTime3()
            self.updateTipsInfo.emit(1, '{} 已完成端口扫描，用时 {} 秒。'.format(GetTime.getSystemTime4(), (endTime - startTime).seconds))
        except Exception as e:
            print(e)

    def stop(self):
        self.is__running = False
        self.terminate()
        for t in self.t_list:
            t.cancel()

    def useSocketScan(self, host, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((host,int(port)))
            socket.timeout(self.timeout/1000)
            s.send('hello\r\n'.encode())
            result = (s.recv(1024)).decode()
            if "HTTP" in result or "<title>" in result:
                self.updateTipsInfo.emit(0, '{} {} 开放 {} 端口。'.format(GetTime.getSystemTime4(), host, port))
                return (host, port, port, 'open')
            # self.updateResult.emit(host, port, 'open')
            self.updateTipsInfo.emit(0, '{} {} 开放 {} 端口。'.format(GetTime.getSystemTime4(), host, port))
            return (host, port, '', 'open')
        except Exception as e:
            # print(e)
            self.updateTipsInfo.emit(0, '{} {} 未开放 {} 端口。'.format(GetTime.getSystemTime4(), host, port))
            pass
        finally:
            s.close()
