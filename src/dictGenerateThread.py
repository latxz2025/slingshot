from PyQt5.QtCore import Qt, QThread, pyqtSignal
from src.getSystemTime import GetTime

class DictGenerate(QThread):
    def __init__(self, combin, path, aItem, bItem, cItem, multiterm, removeduplicate):
        super(DictGenerate, self).__init__()
        self.combin = combin
        self.path = path
        self.aItem = aItem
        self.bItem = bItem
        self.cItem = cItem
        self.multiterm = multiterm
        self.removeduplicate = removeduplicate
        self.aItemList = []
        self.bItemList = []
        self.cItemList = []
        self.finalList = []

    updateResult = pyqtSignal(str)

    def run(self):
        # 处理A B C项的数据
        # 去 \n、空，得到单个项
        if self.aItem:
            self.aItemList = (self.aItem.replace('\n', ',')).split(',')
            self.aItemList = list(filter(None, self.aItemList))
        if self.bItem:
            self.bItemList = (self.bItem.replace('\n', ',')).split(',')
            self.bItemList = list(filter(None, self.bItemList))
        if self.cItem:
            self.cItemList = (self.cItem.replace('\n', ',')).split(',')
            self.cItemList = list(filter(None, self.cItemList))

        try:
            # 根据组合生成字典
            # 是否按A项生成多个字典
            if self.multiterm:
                resultList = []
                a = 1
                for i in self.combin:
                    # 满足两种条件：组合中要有A且A项不为空
                    if "A" in list(i) and self.aItemList:
                        for j in self.aItemList:
                            if len(i) == 2:
                                resultList2 = self.combin2a(list(i), j)
                                self.saveFile(j, self.combin2a(list(i), j))
                                # print(resultList2)
                            else:
                                resultList2 = self.combin3a(list(i), j)
                                self.saveFile(j, self.combin3a(list(i), j))
                                # print(resultList2)
                    # 只要两个条件一个为空，按A项的行生成多个文件不成立
                    else:
                        if len(i) == 2:
                            resultList.extend(self.combin2(list(i)))
                        else:
                            resultList.extend(self.combin3(list(i)))
                self.saveFile('', resultList)
            else:
                for i in self.combin:
                    if len(i) == 2:
                        self.finalList.extend(self.combin2(list(i)))
                    else:
                        self.finalList.extend(self.combin3(list(i)))
                self.saveFile('', self.finalList)
            self.updateResult.emit('字典生成完毕，是否打开目录？')
        except Exception as e:
            print(e)

    def combin2a(self, itemList, item):
        resultList = []
        firstList = self.schedulea(itemList[0], item)
        secondList = self.schedulea(itemList[1], item)
        for i in firstList:
            for j in secondList:
                resultList.append(i + j)
        return resultList

    def combin3a(self, itemList, item):
        resultList = []
        firstList = self.schedulea(itemList[0], item)
        secondList = self.schedulea(itemList[1], item)
        thirdList = self.schedulea(itemList[2], item)
        for i in firstList:
            for j in secondList:
                for k in thirdList:
                    resultList.append(i + j + k)
        return resultList

    #  由于要根据A项的行生成多个文件，所以A项的行要单独作为 一个排列组合的list
    # 这里 str -> list 不可直接用list()方法，要赋值给一个空list再返回,否则将str拆分组合成list返回
    def schedulea(self, item, a):
        if item == 'A':
            al = []
            al.append(a)
            return al
        elif item == "B":
            return self.bItemList
        else:
            return self.cItemList

    def combin2(self, item):
        resultList = []
        firstList = self.schedule(item[0])
        secondList = self.schedule(item[1])
        for i in firstList:
            for j in secondList:
                resultList.append(i+j)
        return resultList

    def combin3(self, item):
        resultList = []
        firstList = self.schedule(item[0])
        secondList = self.schedule(item[1])
        thirdList = self.schedule(item[2])
        for i in firstList:
            for j in secondList:
                for k in thirdList:
                    resultList.append(i+j+k)
        return resultList

    def schedule(self, item):
        if item == 'A':
            return self.aItemList
        elif item == "B":
            return self.bItemList
        else:
            return self.cItemList

    def saveFile(self, item, resultList):
        try:
            if self.removeduplicate:    # 去重
                newList = list(set(resultList))
                newList.sort(key=resultList.index)
            if item:
                filename = item + ".txt"
            else:
                filename = "dic-" + GetTime.getSystemTime1() + ".txt"
            f = open(self.path + r"/" + filename, 'a+', encoding="utf-8")
            for i in newList:
                f.write(i + "\n")
            f.close()
        except Exception as e:
            print(e)