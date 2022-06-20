from PyQt5.QtCore import Qt, QThread, pyqtSignal
import hashlib, time, requests, os
import random, ssl, getopt, queue
import threading, datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.adapters import HTTPAdapter
import sys, re, sqlite3, lxml, urllib3
from bs4 import BeautifulSoup as BS
from src.getSystemTime import GetTime

# Ignore warning
urllib3.disable_warnings()
# Ignore ssl warning info.
try:
    _create_unverified_https_context = ssl._create_unverified_context
except AttributeError:
    # Legacy Python that doesn't verify HTTPS certificates by default
    pass
else:
    # Handle target environment that doesn't support HTTPS verification
    ssl._create_default_https_context = _create_unverified_https_context


class FingerScan(QThread):
    def __init__(self, concurrency, timeout, scanMode, urlText, proxy, useragent):
        super(FingerScan, self).__init__()
        self.concurrency = concurrency
        self.timeout = timeout
        self.scanMode = scanMode
        self.urlText = urlText
        self.proxy = {"http" : "http://{}".format(proxy), "https" : "https://{}".format(proxy)} if proxy else ''
        self.header = {"User-Agent" : useragent}
        self.pwd = os.getcwd()

    updateSignal = pyqtSignal(str)
    updateSignal2 = pyqtSignal(int, str)

    def run(self):
        try:
            startTime = GetTime.getSystemTime3()
            self.concurrency = int(self.concurrency) if self.concurrency else 10
            self.timeout = int(self.timeout) if int(self.timeout) else 3000
            # 去除换行键 \n ，str -> list，得到单个url
            urlList = (self.urlText.replace('\n', ',')).split(',')
            # 去除空字符串
            urlList = list(filter(None, urlList))
            # 去重
            newUrlList = list(set(urlList))
            newUrlList.sort(key=urlList.index)
            for i, url in zip(range(len(newUrlList)), newUrlList):
                if url.endswith('/'):
                    newUrlList[i] = url[:-1]
                if url.startswith('http://') or url.startswith('https://'):
                    pass
                else:
                    newUrlList[i] = 'http://' + url
            count = 0
            with ThreadPoolExecutor(max_workers=self.concurrency) as pool:
                self.t_list = []
                for url in newUrlList:
                    if self.scanMode:   # 启用fofa指纹库一次探测
                        cmsScan = FofaScan(url, self.header, self.timeout, self.proxy)
                        t = pool.submit(cmsScan.run)
                    else:   # 启用目录匹配模式指纹探测
                        whatCms = WhatCms(url, self.header, self.timeout, self.proxy)
                        t = pool.submit(whatCms.run)
                    self.t_list.append(t)

                for future in as_completed(self.t_list):
                    data = future.result()
                    count = count + 1
                    percentage = "{:.2%}".format(count / len(self.t_list))
                    if data:
                        time = GetTime.getSystemTime4()
                        print("{}:{}".format(time,data))
                        self.updateSignal.emit("{}::{}::{}::{}::{}".format(data[0], data[1], data[2], data[3], data[4]))
                        self.updateSignal2.emit(0, '{} 已识别 {} ，完成进度 {}({}/{})。'.format(GetTime.getSystemTime4(), data[0], percentage, count, len(self.t_list)))

                # for url in newUrlList:
                #                 #     whatcms = WhatCms(url, os.getcwd() + '/docs/cms_finger.db')
                #                 #     whatcms.run()
                #                 #     finger = whatcms.getResult()
                #                 #     self.updateResult.emit(finger)

            pool.shutdown()
            endTime = GetTime.getSystemTime3()
            self.updateSignal2.emit(1, '{} 已完成web指纹识别，用时 {} 秒。'.format(GetTime.getSystemTime4(), (endTime - startTime).seconds))
        except Exception as e:
            print(e)
        # finally:
        #     self.updateSignal2.emit("finished")

    def stop(self):
        self.is__running = False
        self.terminate()
        for t in self.t_list:
            t.cancel()

# fofa指纹库一次探测
class FofaScan:
    def __init__(self, url, header, timeout, proxy):
        self.target = url
        self.start = time.time()
        self.finger = []
        self.pwd = os.getcwd()
        self.header = header
        self.timeout = timeout
        self.proxy = proxy
        self.statusCode = ''
        self.title = ''
        self.server = ''

        # re
        self.rtitle = re.compile(r'title="(.*)"')
        self.rheader = re.compile(r'header="(.*)"')
        self.rbody = re.compile(r'body="(.*)"')
        self.rbracket = re.compile(r'\((.*?)\)')
        # self.rbracket = re.compile(r'(\|\|)?(\&\&)?\((.*)\)')

    # 获取response返回包信息
    def getResponseInfo(self):
        try:
            if self.proxy:
                r = requests.get(url=self.target, headers=self.header, proxies = self.proxy, timeout=self.timeout / 1000, verify=False)
            else:
                r = requests.get(url=self.target, headers=self.header,timeout=self.timeout/1000, verify=False)
            encoding = r.encoding
            content = r.text
            self.statusCode = r.status_code
            self.server = r.headers['Server']
            try:
                title = BS(content.encode(encoding), 'lxml').title.text.strip()
                self.title = title
                return str(r.headers), content, title.strip('\n')
            except:
                return str(r.headers), content, ''
        except Exception as e:
            pass

    # 进行指纹比对
    def checkRule(self, key, header, body, title):
        try:
            if 'title="' in key:
                if re.findall(self.rtitle, key)[0].lower() in title.lower():
                    return True
            elif 'body="' in key:
                if re.findall(self.rbody, key)[0] in body:
                    return True
            else:   # 'header="'
                if re.findall(self.rheader, key)[0] in header:
                    return True
        except Exception as e:
            pass

    # 将请求的header、body、title与数据库的keys匹配
    def handle(self, _id, header, body, title):
        name, key = self.check(_id)
        # keys存在 || ，至少有header、title、body中的两项，只要匹配中一项就break
        if '||' in key and '&&' not in key and '(' not in key:
            for rule in key.split('||'):
                if self.checkRule(rule, header, body, title):
                    self.finger.append(name)
                    break
        # keys只有header、title、body中的一项
        elif '||' not in key and '&&' not in key and '(' not in key:
            if self.checkRule(key, header, body, title):
                self.finger.append(name)
        # keys存在 && ，需匹配所有项才结束
        elif '&&' in key and '||' not in key and '(' not in key:
            num = 0
            for rule in key.split('&&'):
                if self.checkRule(rule, header, body, title):
                    num += 1
            if num == len(key.split('&&')):
                self.finger.append(name)
        else:
            # 与条件下存在并条件: 1||2||(3&&4)
            if '&&' in re.findall(self.rbracket, key)[0]:
                for rule in key.split('||'):
                    if '&&' in rule:    # 进一步拆分
                        num = 0
                        for _rule in rule.split('&&'):
                            if self.checkRule(_rule, header, body, title):
                                num += 1
                        if num == len(rule.split('&&')):
                            self.finger.append(name)
                            break
                    else:
                        if self.checkRule(rule, header, body, title):
                            self.finger.append(name)
                            break
            else:
                # 并条件下存在与条件： 1&&2&&(3||4)
                for rule in key.split('&&'):
                    num = 0
                    if '||' in rule:    # 进一步拆分
                        for _rule in rule.split('||'):
                            if self.checkRule(_rule, title, body, header):
                                num += 1
                                break
                    else:
                        if self.checkRule(rule, title, body, header):
                            num += 1
                if num == len(key.split('&&')):
                    self.finger.append(name)

    # 读取cms库数据
    def check(self,_id):
        with sqlite3.connect(self.pwd + '/docs/cms_finger.db') as conn:
            cursor = conn.cursor()
            result = cursor.execute('SELECT name, keys FROM `tide` WHERE id=\'{}\''.format(_id))
            for row in result:
                return row[0], row[1]

    # 读取cms条数
    def count(self):
        with sqlite3.connect(self.pwd + '/docs/cms_finger.db') as conn:
            cursor = conn.cursor()
            result = cursor.execute('SELECT COUNT(id) FROM `tide`')
            for row in result:
                return row[0]

    # 启动
    def run(self):
        try:
            header, body, title = self.getResponseInfo()
            for _id in range(1, int(self.count()), 1):
                try:
                    self.handle(_id, header, body, title)
                except Exception as e:
                    pass
        except Exception as e:
            print(e)
        finally:
            f = ''
            for i in self.finger:
                f+= i + ","
            return (self.target,self.statusCode,self.title,f,self.server)

# 目录匹配模式指纹探测
class WhatCms:
    def __init__(self, url, header, timeout, proxy):
        self.target = url
        self.header = header
        self.timeout = timeout
        self.proxy = proxy
        self.cms = []
        self.diction = {}
        self.is_finish = False
        self.g_index = 0
        self.info = {}
        self.file_path = os.getcwd() + '/docs/cms_finger.db'
        self.statusCode = ''
        self.title = ''
        self.server = ''

    def getResponse(self, target):
        try:
            if self.proxy:
                r = requests.get(url=target, headers=self.header, proxies = self.proxy, timeout=self.timeout / 1000, verify=False)
            else:
                r = requests.get(url=target, headers=self.header,timeout=self.timeout/1000, verify=False)
            r.encoding = 'utf-8'
            print(target, r.status_code)
            if r.status_code == 200:
                self.statusCode = r.status_code
                self.server = r.headers["Server"]
                self.title = BS(content, 'lxml').title.text.strip()
                return r.text, r.content
            else:
                return '', ''
        except Exception as e:
            return '', ''

    # 探测文件来检测cms
    def findCmsWithFile(self):
        while True:
            if self.is_finish:
                break
            if self.g_index >= len(self.cms):
                self.is_finish = True
                self.info['cms_name'] = "Not Found"
                self.info['path'] = "nothing"
                self.info['match_pattern'] = "nothing"
                break
            try:
                eachline = self.cms[self.g_index]
            except Exception as e:
                break
            self.g_index += 1

            finger_id, cms_name, path, match_pattern, options, hit = eachline[0], eachline[1], eachline[2], eachline[3], eachline[4], eachline[5]
            url = self.target + path
            response_html, response_content = self.getResponse(url)

            if options == "md5":
                if match_pattern == self.getMD5(response_content):
                    self.is_finish = True
                    self.info['finger_id'] = finger_id
                    self.info['cms_name'] = cms_name
                    self.info['path'] = path
                    self.info['match_pattern'] = match_pattern
                    self.info['options'] = options
                    self.info['hit'] = hit
                    break
            elif options == "keyword":
                if match_pattern.lower() in response_html.lower():
                    self.is_finish = True
                    self.info['finger_id'] = finger_id
                    self.info['cms_name'] = cms_name
                    self.info['path'] = path
                    self.info['match_pattern'] = match_pattern
                    self.info['options'] = options
                    self.info['hit'] = hit
                    break
            elif options == "regx":
                r = re.search(match_pattern, response_html)
                if r:
                    self.is_finish = True
                    self.info['finger_id'] = finger_id
                    self.info['cms_name'] = cms_name
                    self.info['path'] = path
                    self.info['match_pattern'] = match_pattern
                    self.info['options'] = options
                    self.info['hit'] = hit
                    break

    def run(self):
        try:
            # print("in whatcms run")
            sqlconn1 = sqlite3.connect(self.file_path)
            sqlcursor1 = sqlconn1.cursor()
            sqlcursor1.execute('select * from cms order by hit')
            self.cms = sqlcursor1.fetchall()
            sqlcursor1.close()
            sqlconn1.close()
            self.findCmsWithFile()
        except Exception as e:
            print(e)
        finally:
            info = self.getResult()
            if info:
                finger = info["cms_name"]
            return (self.target,self.statusCode,self.title,finger,self.server)

    def getResult(self):
        while True:
            if self.is_finish:
                # print "self.info:",self.info
                if self.info['cms_name'] != 'Not Found':
                    try:
                        sqlconn = sqlite3.connect(self.file_path)
                        sqlcursor = sqlconn.cursor()
                        sqlcursor.execute('update cms set hit =? where finger_id = ?',
                                          (self.info['hit'] + 1, self.info['finger_id']))
                        sqlcursor.close()
                        sqlconn.commit()
                        sqlconn.close()
                    except Exception as e:
                        return False
                return self.info
            else:
                return False

    def getMD5(self, c):
        md5 = hashlib.md5()
        md5.update(c.encode('utf-8'))
        return md5.hexdigest()
