from PyQt5.QtCore import Qt, QThread, pyqtSignal
import requests,queue,threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.adapters import HTTPAdapter
from src.getSystemTime import GetTime
from  urllib.parse import urlparse


class DirScan(QThread):

    def __init__(self, concurrency, timeout, frequency, method, suffix, statuscode, url, proxy, useragent):
        super(DirScan, self).__init__()
        self.concurrency = concurrency
        self.timeout = int(timeout)
        self.frequency = frequency
        self.method = method
        self.suffix = suffix
        self.statuscode = statuscode
        self.url = url
        self.proxies = {"http" : "http://{}".format(proxy), "https" : "https://{}".format(proxy)} if proxy else ''
        self.header = {"User-Agent" : useragent}
        self.is__running = True
        self.dirname = "docs/dirscan/{}.txt"

    updateResult = pyqtSignal(str, str, str)
    updateTipsInfo = pyqtSignal(str)

    def run(self):
        try:
            startTime = GetTime.getSystemTime3()
            self.concurrency = 10 if self.concurrency == '' else int(self.concurrency)
            self.timeout = 3000 if self.timeout == '' else int(self.timeout)
            self.frequency = 3 if self.frequency == '' else int(self.frequency)
            # 去除换行键 \n ，str -> list，得到单个域名
            urlList = (self.url.replace('\n', ',')).split(',')
            # 去除空字符串
            urlList = list(filter(None, urlList))
            # 去重
            newUrlList = list(set(urlList))
            newUrlList.sort(key=urlList.index)
            self.urlList = newUrlList

            # print(self.concurrency, self.timeout, self.frequency, self.method, self.suffix, self.statuscode, self.url, self.proxies, self.header)
            requestQueue = self.getRequestQueue()
            with ThreadPoolExecutor(max_workers=self.concurrency) as pool:
                self.t_list = []
                while not requestQueue.empty():
                    r = requestQueue.get()
                    t = pool.submit(self.req, r)
                    self.t_list.append(t)
                    # if self.method == "GET":
                    #     t = pool.submit(self.getReq, r)
                    #     t_list.append(t)
                    # else:
                    #     t = pool.submit(self.headReq, r)
                    #     t_list.append(t)
                for future in as_completed(self.t_list):
                    data = future.result()
                    time = GetTime.getSystemTime4()
                    if data:
                        # print("{}:{}".format(time, data))
                        if data[2] in self.statuscode:
                            self.updateResult.emit(data[0], data[1], data[2])
                        self.updateTipsInfo.emit("{} {} - 状态码 {}。".format(time, data[1], data[2]))
            pool.shutdown()
            endTime = GetTime.getSystemTime3()
            self.updateTipsInfo.emit('{} 已完成目录扫描，用时 {} 秒。'.format(GetTime.getSystemTime4(),(endTime - startTime).seconds))
        except Exception as e:
            print(e)

    def req(self, r):
        try:
            requests.adapters.DEFAULT_RETRIES = self.frequency
            if self.proxies:
                rep = requests.request(self.method, url=r, headers=self.header, proxies=self.proxies, timeout=self.timeout / 1000, verify=False)
            else:
                rep = requests.request(self.method, url=r, headers=self.header, timeout=self.timeout / 1000, verify=False)
            # if str(rep.status_code) in self.statuscode:
            up = urlparse(r)
            return (up.scheme+ "://" + up.netloc, r, str(rep.status_code))
        except Exception as e:
            # print(e)
            pass

    def getRequestQueue(self):
        try:
            requestQueue = queue.Queue()
            for url in self.urlList:
                if url.endswith('/'):
                    url = url[:-1]
                if url.startswith('http'):
                    pass
                else:
                    url = 'http://' + url
                for name in self.suffix:
                    with open(self.dirname.format(name), "r", encoding='UTF-8-sig') as f:
                        for line in f.readlines():
                            if line.strip("\n"):
                                requestQueue.put('{}{}'.format(url, line.strip("\n")))
                            # print('{}{}'.format(url, line.strip("\n")))
                    f.close()
        except Exception as e:
            print(e)
        finally:
            return requestQueue

    def stop(self):
        self.is__running = False
        self.terminate()
        for t in self.t_list:
            t.cancel()
