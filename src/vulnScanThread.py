from PyQt5.QtCore import Qt, pyqtSignal, QThread
from lxml import etree
import requests,re,random
from  urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor,as_completed
from src.getSystemTime import GetTime

class VulnScan(QThread):
    def __init__(self, concurrency, timeout, scanMode, method, urlText, cookie, para, proxy, useragent):
        super(VulnScan, self).__init__()
        self.concurrency = concurrency
        self.timeout = timeout
        self.scanMode = scanMode
        self.method = method
        self.urlText = urlText
        self.cookie = cookie
        self.para = para
        self.proxy = {"http": "http://{}".format(proxy), "https": "https://{}".format(proxy)} if proxy else ''
        self.header = {"User-Agent": useragent}
        self.urlList = []
        self.DBMS_ERRORS = {# regular expressions used for DBMS recognition based on error message response
            "MySQL": (r"SQL syntax.*MySQL", r"Warning.*mysql_.*", r"valid MySQL result", r"MySqlClient\."),
            "PostgreSQL": (r"PostgreSQL.*ERROR", r"Warning.*\Wpg_.*", r"valid PostgreSQL result", r"Npgsql\."),
            "Microsoft SQL Server": (r"Driver.* SQL[\-\_\ ]*Server", r"OLE DB.* SQL Server", r"(\W|\A)SQL Server.*Driver", r"Warning.*mssql_.*", r"(\W|\A)SQL Server.*[0-9a-fA-F]{8}", r"(?s)Exception.*\WSystem\.Data\.SqlClient\.", r"(?s)Exception.*\WRoadhouse\.Cms\."),
            "Microsoft Access": (r"Microsoft Access Driver", r"JET Database Engine", r"Access Database Engine"),
            "Oracle": (r"\bORA-[0-9][0-9][0-9][0-9]", r"Oracle error", r"Oracle.*Driver", r"Warning.*\Woci_.*", r"Warning.*\Wora_.*"),
            "IBM DB2": (r"CLI Driver.*DB2", r"DB2 SQL error", r"\bdb2_\w+\("),
            "SQLite": (r"SQLite/JDBCDriver", r"SQLite.Exception", r"System.Data.SQLite.SQLiteException", r"Warning.*sqlite_.*", r"Warning.*SQLite3::", r"\[SQLITE_ERROR\]"),
            "Sybase": (r"(?i)Warning.*sybase.*", r"Sybase message", r"Sybase.*Server message.*"),
        }
        self.xssPayloadFile = "docs/xssPayload.txt"
        self.xssPayloadList = []

    updateSignal = pyqtSignal(str)
    updateSignal2 = pyqtSignal(int, str)

    def run(self):
        try:
            startTime = GetTime.getSystemTime3()
            self.concurrency = int(self.concurrency) if self.concurrency else 10
            self.timeout = int(self.timeout) if self.timeout else 3000
            f = open(self.xssPayloadFile,encoding="utf-8")
            for line in f:
                self.xssPayloadList.append(line.strip())
            f.close()
            # ??????????????? \n ???str -> list???????????????url
            urlList = (self.urlText.replace('\n', ',')).split(',')
            # ??????????????????
            urlList = list(filter(None, urlList))
            # ??????
            newUrlList = list(set(urlList))
            newUrlList.sort(key=urlList.index)
            for i, url in zip(range(len(newUrlList)), newUrlList):
                if url.endswith('/'):
                    newUrlList[i] = url[:-1]
                if url.startswith('http://') or url.startswith('https://'):
                    pass
                else:
                    newUrlList[i] = 'http://' + url
            # print(self.scanMode)
            with ThreadPoolExecutor(max_workers=self.concurrency) as pool:
                self.t_list = []
                for url in newUrlList:
                    urlList = self.spider(url)
                    for u in urlList:
                        # print(u)
                        if len(self.scanMode) == 2:
                            t1 = pool.submit(self.sqlVulnScan, u)
                            self.t_list.append(t1)
                            t2 = pool.submit(self.xssVulnScan, u)
                            self.t_list.append(t2)
                        else:
                            if 1 in self.scanMode:
                                t = pool.submit(self.sqlVulnScan, u)
                            if 2 in self.scanMode:
                                t = pool.submit(self.xssVulnScan, u)
                            self.t_list.append(t)
                for future in as_completed(self.t_list):
                    data = future.result()
                    time = GetTime.getSystemTime4()
                    if data:
                        # print("{}:{}".format(time, data))
                        if data[0]:
                            self.updateSignal.emit("{}::{}::{}::{}".format(data[1], data[2], data[3], data[4]))
                            self.updateSignal2.emit(0, "{} ????????? {} ?????? {} ?????????".format(GetTime.getSystemTime4(), data[1], data[2]))
                        else:
                            self.updateSignal2.emit(0, "{} ????????? {} ????????? {} ?????????".format(GetTime.getSystemTime4(), data[1], data[2]))
            endTime = GetTime.getSystemTime3()
            self.updateSignal2.emit(1, "{} ?????????????????????????????? {} ??????".format(GetTime.getSystemTime4(), (endTime - startTime).seconds))
        except Exception as e:
            print(e)

    # sql??????????????????url???????????????????????????????????????????????????
    def sqlVulnScan(self, url):
        try:
            parameters = (urlparse(url).query).split("&")
            parameters = list(filter(None, parameters))
            if parameters:
                pass
            else:
                payload = "id={}".format(random.randint(1,1000))
                parameters.append(payload)
                if url.endswith("/"):
                    pass
                else:
                    url = url + "/"
                url = url + "?{}".format(payload)
            for para in parameters:
                u = url.replace(para, para + "%29%28%22%27")     # )("'
                if self.method == "GET":
                    if self.proxy:
                        r = requests.get(u, headers=self.header, proxies=self.proxy, timeout=self.timeout/1000, verify=False)
                    else:
                        r = requests.get(u, headers=self.header, timeout=self.timeout / 1000, verify=False)
                else:
                    if self.proxy:
                        r = requests.post(u, headers=self.header, proxies=self.proxy, para=self.para, timeout=self.timeout / 1000, verify=False)
                    else:
                        r = requests.post(u, headers=self.header, para=self.para, timeout=self.timeout / 1000, verify=False)
                content = r.text
                for (dbms, regex) in ((dbms, regex) for dbms in self.DBMS_ERRORS for regex in self.DBMS_ERRORS[dbms]):
                    if (re.search(regex, content)):
                        return (1, url, "sql??????", para.split("=")[0], "%29%28%22%27")
            return (0, url, "sql??????")
        except Exception as e:
            print(e)
            # pass

    def xssVulnScan(self, url):
        try:
            parameters = (urlparse(url).query).split("&")
            parameters = list(filter(None, parameters))
            if parameters:
                pass
            else:
                payload = "id={}".format(random.randint(1,1000))
                parameters.append(payload)
                if url.endswith("/"):
                    pass
                else:
                    url = url + "/"
                url = url + "?{}".format(payload)
            for para in parameters:
                for payload in self.xssPayloadList:
                    u = url.replace(para, para + payload)
                    if self.method == "GET":
                        if self.proxy:
                            r = requests.get(u, headers=self.header, proxies=self.proxy, timeout=self.timeout / 1000,verify=False)
                        else:
                            r = requests.get(u, headers=self.header, timeout=self.timeout / 1000, verify=False)
                    else:
                        if self.proxy:
                            r = requests.post(u, headers=self.header, proxies=self.proxy, para=self.para,timeout=self.timeout / 1000, verify=False)
                        else:
                            r = requests.post(u, headers=self.header, para=self.para, timeout=self.timeout / 1000, verify=False)
                    content = r.text
                    if r.status_code != 200:
                        break
                    content = r.text
                    if content is None:
                        break
                    if (content.find(payload) != -1):
                        print("[*] XSS Found: ", u)
                        return (1, url, "xss??????", para.split("=")[0], payload)
            return (0, url, "xss??????")
        except Exception as e:
            print(e)
            # pass

    # ??????????????????href????????????
    def spider(self, url):
        try:
            newUrlList = []
            newUrlList.append(url)
            domain = urlparse(url).netloc
            if urlparse(url).query:  # url?????????????????????????????????
                return newUrlList
            r = requests.get(url, headers=self.header, timeout=self.timeout)
            text = r.content
            parse_html = etree.HTML(text,etree.HTMLParser())
            urlList = parse_html.xpath("//*/@href")
            # print(urlList)
            urlList = list(set(urlList))    # ??????
            for u in urlList:   # ??????js???css??????
                if u.endswith(".js") or u.endswith(".css"):
                    continue
                if "https://" in u or "http://" in u:
                    if u.startswith("https://") or u.startswith("http://"):
                        domain2 = urlparse(u).netloc
                        if domain != domain2:   # ???????????????????????????
                            pass
                        else:
                            newUrlList.append(u)
                    else:   # ??????????????????
                        pass
                else:
                    if u.startswith("/"):
                        newUrlList.append(url + u)
                    else:
                        newUrlList.append(url + "/" + u)
            # newUrlList = list(set(newUrlList))
            return newUrlList
        except Exception as e:
            print(e)
            # pass

    def stop(self):
        self.is__running = False
        self.terminate()
        for t in self.t_list:
            t.cancel()

