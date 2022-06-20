from PyQt5.QtCore import Qt, QThread, pyqtSignal
import json,re


class AvIdentify(QThread):
    def __init__(self, tasklist, antivirusdic, wafdic):
        super(AvIdentify, self).__init__()
        self.tasklist = tasklist
        self.antivirusdic = antivirusdic
        self.wafdic = wafdic

    updateResult = pyqtSignal(str)

    def run(self):
        # 去除换行，str 转换为 list，得到进程列表
        tasklist = (self.tasklist.replace('\n', ',')).split(',')
        # 去除空字符串
        tasklist = list(filter(None, tasklist))
        # 提取进程名 + PID
        avlist,newtasklist = [],[]
        avdict,wafdict = {},{}
        pattern1 = re.compile(r'\w+.exe')
        # pattern2 = re.compile(r'\d+')
        pattern3 = re.compile(r'\d+ \w+')
        for i in tasklist:
            task = pattern1.search(i)
            ps = pattern3.search(i)
            if task and ps:
                pid = (ps.group()).split(" ")[0]
                service = (ps.group()).split(" ")[1]
                newtasklist.append(task.group()+":"+pid+":"+service)
        # print(newtasklist)
        try:
            with open(self.antivirusdic, encoding="utf-8") as avdic:
                avJsonData = json.load(avdic)
                avdict = avJsonData
            with open(self.wafdic, encoding="utf-8") as wafdic:
                wafJsonData = json.load(wafdic)
                wafdict = wafJsonData
            wafdic.close()
            avdic.close()
            # print(avdict)
            # print(wafdict)
            for task in newtasklist:
                # 不可直接匹配，出现大小写、缺少后缀情况匹配不成功。
                # avname = avdict.get(task.split(":")[0])
                # wafname = wafdict.get(task.split(":")[0])
                pattern4 = re.compile('^%s' % task.split(":")[0], re.I)

                # 检索进程名

                # 在av.json中检索进程名
                for item in list(avdict.items()):
                    avname = pattern4.search(item[0])
                    if avname:
                        avlist.append(task+":"+item[1])
                # 在waf.json中检索进程名
                for item in list(wafdict.items()):
                    wafname = pattern4.search(item[0])
                    if wafname:
                        avlist.append(task+":"+item[1])

                # 检索服务名

                if task.split(":")[2] not in '暂缺':
                    # print(task.split(":")[2])
                    pattern5 = re.compile('^%s' % task.split(":")[2], re.I)
                    # 在av.json中检索服务名
                    for item in list(avdict.items()):
                        avname = pattern5.search(item[0])
                        if avname:
                            avlist.append(task + ":" + item[1])
                    # 在waf.json中检索服务名
                    for item in list(wafdict.items()):
                        wafname = pattern5.search(item[0])
                        if wafname:
                            avlist.append(task + ":" + item[1])
            # 去重
            avlist = list(set(avlist))
            # print(avlist)
            # avlist中每一项：进程名+pid+服务名+杀软名
            # 回传
            for i in avlist:
                self.updateResult.emit(i)
        except Exception as e:
            print(e)