from PyQt5.QtCore import Qt, QThread, pyqtSignal
import requests,queue,socket
from src.getSystemTime import GetTime
from concurrent.futures import ThreadPoolExecutor,as_completed

class DomainScan(QThread):

    def __init__(self, concurrency, timeout, domainList, domaindic):
        super(DomainScan, self).__init__()
        self.dic = domaindic
        self.concurrency = concurrency
        self.timeout = timeout
        self.domainList = domainList
        self.is__running = True

    updateResult = pyqtSignal(str, str)
    updateTipsInfo = pyqtSignal(str)


    def run(self):
        startTime = GetTime.getSystemTime3()
        self.concurrency = int(self.concurrency) if self.concurrency else 10
        self.timeout = int(self.timeout) if self.timeout else 3000
        # 去除换行键 \n ，str -> list，得到单个域名
        domainList = (self.domainList.replace('\n', ',')).split(',')
        # 去除空字符串
        domainList = list(filter(None, domainList))
        # 去除 http:// 或 https:// 如果存在
        domainList = [(i.replace('http://', '') if 'http://' in i else i.replace('https://', '')) for i in domainList]
        # 如果有 www，则去除
        domainList = [(i.replace('www', '') if 'www' in i else i) for i in domainList]
        # 去重
        newDomainList = list(set(domainList))
        newDomainList.sort(key=domainList.index)
        del domainList

        domainQueue = queue.Queue()
        # 使用队列
        for domain in newDomainList:
            dictList = open(self.dic, 'r')
            for line in dictList.readlines():
                domainQueue.put(line.strip() + '.' + domain)
            dictList.close()
        try:
            with ThreadPoolExecutor(max_workers=self.concurrency) as pool:
                self.t_list = []
                while not domainQueue.empty():
                    domain = domainQueue.get()
                    t = pool.submit(self.getDomainAndIp, domain)
                    self.t_list.append(t)

                # for future in as_completed(self.t_list):
                #     data = future.result()
                #     if data[1]:
                #         time = GetTime.getSystemTime4()
                #         print("[+]{}".format(time))
                #         self.updateResult.emit(data[0], data[1])
            pool.shutdown()
            endTime = GetTime.getSystemTime3()
            self.updateTipsInfo.emit(1, '{} 已完成域名扫描，用时 {} 秒。'.format(GetTime.getSystemTime4(),(endTime - startTime).seconds))
        except Exception as e:
            print(e)

    def stop(self):
        self.is__running = False
        self.terminate()
        for t in self.t_list:
            t.cancel()

    def getDomainAndIp(self,domain):
        try:
            ip = ''
            rep = requests.head("http://{}".format(domain), timeout=self.timeout/1000)
            if rep.status_code == 301:
                pass
            else:
                ip = socket.gethostbyname(domain)
                self.updateResult.emit(domain, ip)
                print(domain,ip)
            # return (domain, ip)
        except Exception as e:
            # print(e)
            pass