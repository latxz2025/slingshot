from PyQt5 import uic,QtGui
# from PyQt5.QtWidgets import QApplication,QTableWidgetItem,QAbstractItemView
# from PyQt5.QtCore import QObject, pyqtSignal
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
import connectDialog
from src.domainScanThread import DomainScan
from src.portScanThread import PortScan
from src.avIdentifyThread import AvIdentify
from src.dictGenerateThread import DictGenerate
from src.connectServerThread import ConnectServer
from src.createServerThread import CreateServer
from src.dirScanThread import DirScan
from src.codeConvertThread import CodeConvert
from src.FingerScanThread import FingerScan
from src.getSystemTime import GetTime
from src.vulnScanThread import VulnScan
from src.bruteThread import Brute
import threading,sys,os,queue,http.client,platform,json,socket


class Ss:
    def __init__(self):

        self.domaindic = 'docs/domainburst/dict.txt'
        self.antivirusdic = 'docs/antivirus/av.json'
        self.wafdic = 'docs/antivirus/waf.json'
        self.combindic = 'docs/dictgenerate/config.ini'
        self.b1txtdic = 'docs/dictgenerate/Dic/B1.txt'
        self.b2txtdic = 'docs/dictgenerate/Dic/B2.txt'
        self.c1txtdic = 'docs/dictgenerate/Dic/C1.txt'
        self.c2txtdic = 'docs/dictgenerate/Dic/C2.txt'
        self.teamlogfile = 'docs/teamlog/log - {}.txt'
        self.defaultBruteUserDict = 'docs/bruteDict/dict_{}/dic_username_{}.txt'
        self.defaultBrutePassDict = 'docs/bruteDict/dict_{}/dic_password_{}.txt'

        # 导入ui文件
        self.ui = uic.loadUi(r"main.ui")
        self.moduleName = {'信息收集': ['域名扫描', '端口扫描', '暴力破解', '目录扫描', 'web指纹识别','扩展选项'],
                           '漏洞扫描': ['扫描', '选项'],
                           '漏洞利用': [''],
                           '选项': ['更新日志', '备忘录', '使用日志'],
                           '辅助工具' : ['杀软识别', 'IP解析', '字典生成'],
                           '团队' : ['聊天', '日志信息', '管理']}
        self.clearCss()

        # # 添加检测窗口变化的 slot 槽函数
        # self.ui.tabWidget.currentChanged.connect(lambda : self.tableChanged(self.ui.tabWidget.currentIndex(), 1, 0))
        # self.ui.tabWidget_2.currentChanged.connect(lambda : self.tableChanged(self.ui.tabWidget_2.currentIndex(), 2, 0))
        # self.ui.tabWidget_3.currentChanged.connect(lambda : self.tableChanged(self.ui.tabWidget_3.currentIndex(), 3, 5))
        # self.ui.tabWidget_4.currentChanged.connect(lambda : self.tableChanged(self.ui.tabWidget_4.currentIndex(), 4, 4))
        # self.ui.tabWidget_5.currentChanged.connect(lambda : self.tableChanged(self.ui.tabWidget_5.currentIndex(), 5, 1))
        # self.ui.tabWidget_6.currentChanged.connect(lambda : self.tableChanged(self.ui.tabWidget_6.currentIndex(), 6, 6))

        # 多项设置
        self.defaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36 Edg/89.0.774.50"
        self.ui.plainTextEdit_7.textChanged.connect(self.setUA)
        self.infoCollectEncodeList = ["utf-8", "gbk"]
        self.dirScanMethodList = ["HEAD", "GET"]
        # self.setInfoCollectProxy()
        self.infoCollectProxy = ''
        self.ui.checkBox_23.stateChanged.connect(self.setInfoCollectProxy) # 检测 复选框 状态
        self.ui.plainTextEdit_12.textChanged.connect(self.memo)
        self.ui.plainTextEdit_13.textChanged.connect(self.updateLog)
        self.ui.avTipsInfo.setVisible(False)

        # 菜单栏添加slot函数
        self.ui.openDir.triggered.connect(self.openDir)
        self.ui.exitApp.triggered.connect(self.exitApp)
        # self.ui.setBurstDict.triggered.connect(self.setBurstDict)
        self.ui.setBackgroundBlack.triggered.connect(self.setBackgroundBlack)
        self.ui.setBackgroundWhite.triggered.connect(self.setBackgroundWhite)
        self.ui.clearCss.triggered.connect(self.clearCss)
        self.ui.showDialog.triggered.connect(self.showDialog)
        self.ui.about.triggered.connect(self.about)
        self.ui.rebootApp.triggered.connect(self.rebootApp)

        # ######################子域名扫描模块################################
        # 设立域名扫描结果队列
        self.domainScanQueue = queue.Queue()
        self.domainScanList = []
        self.domainScanQueue.put("序号,子域名,IP")
        self.ui.domainStopScanButton.setEnabled(False)
        # 添加点击事件
        self.ui.domainStartScanButton.clicked.connect(self.domainStartScan)
        self.ui.domainStopScanButton.clicked.connect(self.domainStopScan)
        self.ui.domainScanOutput.clicked.connect(self.domainScanSave)
        self.ui.sendToPortScan.clicked.connect(self.sendToPortScan)
        self.ui.pushButton_12.clicked.connect(lambda : self.clearContent(self.ui.domainScanResult))
        self.domainScanTable = self.ui.domainScanResult
        # 限制输入整型
        self.ui.domainConcurrent.setValidator(QtGui.QIntValidator())
        self.ui.domainScanTimeout.setValidator(QtGui.QIntValidator())
        # 初始化域名扫描表格。
        self.initTable(self.domainScanTable, ['序号', '子域名', 'IP'])


        # ######################端口扫描模块#################################
        # 添加点击事件的slot函数
        self.portScanList = []
        self.portScanQueue = queue.Queue()
        self.portScanQueue.put("序号,IP,端口,端口状态")
        self.ui.portStopScanButton.setEnabled(False)
        self.ui.portStartScanButton.clicked.connect(self.portStartScan)
        self.ui.portStopScanButton.clicked.connect(self.portStopScan)
        self.ui.portScanOutput.clicked.connect(self.portScanSave)
        self.ui.sendToWebFingerScan.clicked.connect(self.sendToWebFingerScan)
        self.ui.pushButton_16.clicked.connect(lambda : self.clearContent(self.ui.portScanResultTable))
        self.ui.portScanConcurrent.setValidator(QtGui.QIntValidator())
        self.ui.portScanTimeout.setValidator(QtGui.QIntValidator())
        self.httpPort = "80,8080,443"
        self.allPort = "1-65535"
        self.commonPort = "21,22,23,25,53,69,80,81-89,110,135,139,143,443,445,465,993,995,1080,1158,1433,1521,1863,2100,3128,3306,3389,7001,8080,8081-8088,8888,9080,9090"
        self.ui.portToScan.setText(self.commonPort)
        self.ui.buttonGroup.buttonClicked[int].connect(self.setScanPort)
        self.ui.ipInputButton.clicked.connect(self.ipInput)
        self.portScanResultTable = self.ui.portScanResultTable
        # 初始化端口扫描列表。
        self.initTable(self.portScanResultTable, ['序号', 'IP', '端口', '端口状态'])


        # ######################杀软识别模块#################################
        # 添加点击事件的slot函数
        self.ui.antivirusIdentifyButton.clicked.connect(self.antivirusIdentify)
        self.ui.pushButton_27.clicked.connect(lambda: self.clearContent(self.ui.identifyResultTable))
        self.identifyResultTable = self.ui.identifyResultTable
        self.identifyResultTable.setColumnCount(5)
        self.identifyResultTable.setHorizontalHeaderLabels(['序号', '进程名称', 'PID', '服务名', '杀软名称'])
        # 设置表格内容不允许编辑
        self.identifyResultTable.setEditTriggers(QAbstractItemView.NoEditTriggers)
        # 设置表格的自适应伸缩模式
        self.identifyResultTable.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        # 去除左侧的序号
        self.identifyResultTable.verticalHeader().setVisible(False)
        # 标题头加粗
        identifyResultTableTitleFont = self.identifyResultTable.horizontalHeader().font()
        identifyResultTableTitleFont.setBold(True)
        self.identifyResultTable.horizontalHeader().setFont(identifyResultTableTitleFont)

        # ######################字典生成模块#################################
        # 添加点击事件的slot函数
        self.ui.pushButton_35.clicked.connect(self.setGeneratePath)
        self.ui.pushButton_34.clicked.connect(self.dictGenerate)
        self.ui.buttonGroup_4.buttonClicked[int].connect(self.setBItem)
        self.ui.buttonGroup_5.buttonClicked[int].connect(self.setCItem)
        # self.ui.plainTextEdit_19.setPlainText("AC,CA")
        self.setCombination()
        self.allCombin = ['AA', 'AB', 'AC', 'BA', 'BB', 'BC', 'CA', 'CB', 'CC',
                          'AAA', 'AAB', 'AAC', 'ABA', 'ABB', 'ABC', 'ACA', 'ACB', 'ACC',
                          'BAA', 'BAB', 'BAC', 'BBA', 'BBB', 'BBC', 'BCA', 'BCB', 'BCC',
                          'CAA', 'CAB', 'CAC', 'CBA', 'CBB', 'CBC', 'CCA', 'CCB', 'CCC']
        self.ui.checkBox.setChecked(True)
        self.savePath = os.getcwd()
        self.ui.lineEdit_27.setText(self.savePath + r"\result")
        self.ui.radioButton_19.setChecked(True)
        self.ui.radioButton_21.setChecked(True)
        self.setBItem(-2)
        self.setCItem(-2)

        # ######################团队模块#################################
        # 添加点击事件的slot函数
        self.getIP()
        self.Cs(self.ui.comboBox_13.currentIndex())
        self.ui.pushButton.clicked.connect(self.getIP)
        self.ui.comboBox_13.currentIndexChanged.connect(self.Cs)
        self.ui.pushButton_5.clicked.connect(self.breakNet)
        self.ui.pushButton_6.clicked.connect(self.sendMessage)
        self.ui.pushButton_7.clicked.connect(self.clearMessage)
        self.ui.lineEdit_2.setText("9999")
        self.ui.lineEdit_2.setValidator(QtGui.QIntValidator())
        # 限制输入整型
        self.ui.lineEdit_2.setValidator(QtGui.QIntValidator())

        # ######################目录扫描模块#################################
        # 添加点击事件的slot函数
        self.ui.pushButton_2.clicked.connect(self.dirStartScan)
        self.ui.pushButton_4.clicked.connect(self.dirStopScan)
        self.ui.pushButton_19.clicked.connect(self.importUrl)
        self.ui.pushButton_18.clicked.connect(self.dirScanOutput)
        self.ui.pushButton_29.clicked.connect(lambda: self.clearContent(self.ui.dirScanResult))
        self.ui.lineEdit_12.setValidator(QtGui.QIntValidator())
        self.ui.lineEdit_13.setValidator(QtGui.QIntValidator())
        self.ui.lineEdit_15.setValidator(QtGui.QIntValidator())
        self.suffix = ["ASP", "ASPX", "DIR", "MDB", "PHP", "JSP", "springboot"]
        self.statuscode = ["200", "3xx", "403"]
        # self.ui.buttonGroup_2.buttonClicked.connect(self.getSuffix)
        self.ui.buttonGroup_2.setExclusive(False)
        self.ui.buttonGroup_3.setExclusive(False)
        self.ui.pushButton_4.setEnabled(False)
        self.dirScanResultTable = self.ui.dirScanResult
        self.initTable(self.dirScanResultTable, ['序号', '目标', '地址', '响应状态码'])


        # ######################编码转换模块#################################
        # 添加点击事件的slot函数
        self.ui.pushButton_8.clicked.connect(self.exchange)
        self.ui.pushButton_32.clicked.connect(self.convert)
        self.ui.pushButton_33.clicked.connect(self.saveCodeResult)
        self.ui.pushButton_10.clicked.connect(self.clearString)
        self.ui.comboBox_6.clear()
        self.ui.comboBox_2.clear()
        self.ui.comboBox_7.clear()
        self.ui.comboBox_8.clear()
        self.ui.comboBox_9.clear()
        self.ui.comboBox_10.clear()
        self.ui.comboBox_11.clear()
        self.ui.comboBox_12.clear()
        self.ui.comboBox_11.setEnabled(False)
        self.ui.comboBox_12.setEnabled(False)
        self.ui.comboBox_11.setCurrentIndex(1)
        self.ui.comboBox_12.setCurrentIndex(1)
        self.ui.lineEdit_6.setEnabled(False)
        self.ui.lineEdit_7.setEnabled(False)
        self.coding = ["UTF-8", "GBK"]
        self.ui.comboBox_6.addItems(self.coding)
        self.status = [[0, 0, 0, '', 0, 0, 0, ''], [0, 0, 0, '', 0, 0, 0, ''], [0, 0, 0, '', 0, 0, 0, '']]
        self.codeStatus = ["1", "2", "3"]
        self.binhexoct = ["16", "10", "8", "2"]
        self.ui.comboBox_2.addItems(self.codeStatus)
        self.coding2 = ["char", "cmd", "crypto", "进制"]
        self.ui.comboBox_9.addItems(self.coding2)
        self.ui.comboBox_10.addItems(self.coding2)
        self.coding21 = [["aDefault", "Ascii", "Base64", "Html", "Reverse", "Unicode", "UnicodeBase64", "Url"], ["JavaRuntimeExec", "Normal"], ["MD5_32", "MD5_16", "SHA256"], ["16", "10", "8", "2"]]
        self.ui.comboBox_7.addItems(self.coding21[0])
        self.ui.comboBox_8.addItems(self.coding21[0])
        self.coding22 = ["JavaRuntimeExec", "Normal"]
        self.coding23 = ["MD5_32", "MD5_16", "SHA256"]
        self.coding24 = ["Bash", "Powershell", "Python", "Perl"]
        # self.coding231 = ["CBC+Base64", "CBC+HEX", "CFB+HEX"]
        self.ui.comboBox_6.currentIndexChanged.connect(self.codingChanged)
        self.ui.comboBox_2.currentIndexChanged.connect(self.statusChanged)
        self.ui.comboBox_9.currentIndexChanged.connect(self.inputCodingChanged)
        self.ui.comboBox_7.currentIndexChanged.connect(self.inputCodingChanged2)
        self.ui.comboBox_10.currentIndexChanged.connect(self.outputCodingChanged)
        self.ui.comboBox_8.currentIndexChanged.connect(self.outputCodingChanged2)
        self.ui.lineEdit_14.setText("0 Bytes")
        self.ui.lineEdit_26.setText("0 Bytes")
        self.ui.checkBox_26.stateChanged.connect(self.autoConvert)
        self.ui.plainTextEdit_16.textChanged.connect(lambda : self.setByte(self.ui.lineEdit_14, len(self.ui.plainTextEdit_16.toPlainText())))
        self.ui.plainTextEdit_17.textChanged.connect(lambda : self.setByte(self.ui.lineEdit_26, len(self.ui.plainTextEdit_17.toPlainText())))

        # ######################web指纹识别模块#################################
        # 添加点击事件的slot函数
        self.ui.pushButton_21.clicked.connect(self.fingerStartScan)
        self.ui.pushButton_20.clicked.connect(self.fingerStopScan)
        self.ui.pushButton_22.clicked.connect(self.importUrl2)
        self.ui.pushButton_23.clicked.connect(self.fingerScanOutput)
        self.ui.pushButton_11.clicked.connect(lambda : self.clearContent(self.ui.tableWidget_7))
        self.ui.buttonGroup_6.buttonClicked[int].connect(self.setScanMode)
        self.ui.lineEdit_16.setValidator(QtGui.QIntValidator())
        self.ui.lineEdit_17.setValidator(QtGui.QIntValidator())
        self.scanMode = 1
        self.ui.pushButton_20.setEnabled(False)
        self.fingerQueue = queue.Queue()
        self.fingerQueue.put('序号,URL,状态码,标题,web指纹,Server')
        self.fingerScanResultTable = self.ui.tableWidget_7
        self.initTable(self.fingerScanResultTable, ['序号', 'URL', '状态码', '标题', 'web指纹', 'Server'])


        # ######################暴力破解模块#################################
        # 添加点击事件的slot函数
        self.ui.pushButton_13.clicked.connect(self.startBrute)
        self.ui.pushButton_9.clicked.connect(self.stopBrute)
        self.ui.pushButton_15.clicked.connect(self.importUser)
        self.ui.pushButton_17.clicked.connect(self.importPass)
        self.ui.pushButton_14.clicked.connect(self.bruteResultOutput)
        self.ui.pushButton_37.clicked.connect(lambda: self.clearContent(self.ui.burstResultTable))
        self.ui.checkBox_2.stateChanged.connect(self.setDefaultDict)
        self.ui.checkBox_3.stateChanged.connect(self.setBruteMode)
        self.ui.lineEdit_9.setValidator(QtGui.QIntValidator())
        self.ui.lineEdit_8.setValidator(QtGui.QIntValidator())
        self.bruteMode = 0 # 尽可能爆破所有账户
        self.bruteUserDict = ''
        self.brutePassDict = ''
        self.ui.pushButton_9.setEnabled(False)
        self.ui.buttonGroup_7.setExclusive(False)
        self.ui.buttonGroup_8.setExclusive(False)
        self.bruteItem = ["ftp", "mysql", "mssql", "redis", "ssh", "telnet"]   # {"ftp": 21, "Mysql": 3306, "Mssql": 1433, "Redis": 6379, "ssh": 22, "Telnet": 23}
        self.bruteQueue = queue.Queue()
        self.bruteQueue.put('序号,IP,端口,端口类型,账号,密码')
        self.bruteResultTable = self.ui.burstResultTable
        self.initTable(self.bruteResultTable, ['序号', 'IP', '端口', '端口类型', '账号', '密码'])


        # ######################漏洞扫描模块#################################
        # 添加点击事件的slot函数
        self.ui.pushButton_30.clicked.connect(self.vulnStartScan)
        self.ui.pushButton_28.clicked.connect(self.vulnStopScan)
        self.ui.pushButton_26.clicked.connect(self.importUrl3)
        self.ui.pushButton_25.clicked.connect(self.vulnResultOutput)
        self.ui.pushButton_36.clicked.connect(lambda: self.clearContent(self.ui.tableWidget_10))
        self.ui.lineEdit_20.setValidator(QtGui.QIntValidator())
        self.ui.lineEdit_21.setValidator(QtGui.QIntValidator())
        self.ui.comboBox_4.currentIndexChanged.connect(self.getVulnScanMethod)
        # self.ui.buttonGroup_9.buttonClicked[int].connect(self.setScanMode2)
        self.ui.buttonGroup_9.setExclusive(False)
        self.ui.pushButton_28.setEnabled(False)
        self.ui.label_16.setVisible(False)
        self.ui.lineEdit_18.setVisible(False)
        self.VulnScanMethod = "GET"
        self.vulnQueue = queue.Queue()
        self.vulnQueue.put('序号,目标,漏洞,注入点,payload')
        self.vulnResultTable = self.ui.tableWidget_10
        self.initTable(self.vulnResultTable, ['序号', '目标', '漏洞', '注入点', 'payload'])


    ############################### 域名扫描 #########################################

    def domainStartScan(self):
        try:
            # 表格内容清除
            self.ui.domainScanResult.setRowCount(0)
            self.ui.domainStartScanButton.setEnabled(False)
            self.ui.domainStopScanButton.setEnabled(True)
            concurrency = self.ui.domainConcurrent.text()
            timeout = self.ui.domainScanTimeout.text()
            domainList = self.ui.domainAdd.toPlainText() if self.ui.domainAdd.toPlainText() is not "" else "baidu.com"
            # 创建子进程
            self.domainScanThread_ = DomainScan(concurrency, timeout, domainList, self.domaindic)
            # 将子进程中的信号与printdomainresult槽函数绑定
            self.domainScanThread_.updateResult.connect(self.printDomainScanResult)
            self.domainScanThread_.updateTipsInfo.connect(self.printTipsInfo)
            # 启动域名扫描子进程
            self.domainScanThread_.start()
            self.ui.domainTipsInfo.append("{} {}".format(GetTime.getSystemTime4(),"正在进行域名扫描，请稍等。"))
        except Exception as e:
            print(e)

    def domainStopScan(self):
        self.domainScanThread_.stop()
        self.ui.domainStartScanButton.setEnabled(True)
        time = GetTime.getSystemTime4()
        self.ui.domainTipsInfo.append("{} 已停止域名扫描。".format(time))
        print("{} 已停止域名扫描。".format(time))

    def printDomainScanResult(self, domain, ip):
        try:
            # 获取域名扫描表格的行数、列数
            rowNum = self.domainScanTable.rowCount()
            colNum = self.domainScanTable.columnCount()
            # 添加一行
            self.domainScanTable.insertRow(rowNum)
            # 添加数据，坑点一：添加 int型 数据后获取不到，值为null。
            # 坑点二：添加的数据行为 rowCount - 1 行，而不是 rowCount行
            numItem = QTableWidgetItem(str(rowNum + 1))
            self.domainScanTable.setItem(self.domainScanTable.rowCount() - 1, 0, numItem)
            domainItem = QTableWidgetItem(domain)
            self.domainScanTable.setItem(self.domainScanTable.rowCount() - 1, 1, domainItem)
            ipItem = QTableWidgetItem(ip)
            self.domainScanTable.setItem(self.domainScanTable.rowCount() - 1, 2, ipItem)
            # 将结果写入队列
            self.domainScanQueue.put(str(rowNum+1)+","+domain+","+ip)
            self.domainScanList.append(ip)
        except Exception as e:
            print(e)
            # pass

    def printTipsInfo(self, message):
        self.ui.domainTipsInfo.append(message)
        self.ui.domainTipsInfo.ensureCursorVisible()

    def domainScanSave(self):
        try:
            localPath = os.getcwd()
            saveDirPath = QFileDialog.getSaveFileName(None, "选择保存路径", localPath, "CSV Files(*.csv);;All Files (*)")
            # 将队列结果写入文件
            resultFile = open(saveDirPath[0],"a+",encoding="utf-8")
            while not self.domainScanQueue.empty():
                line = self.domainScanQueue.get()
                if line:
                    resultFile.write(line + "\n")
            self.ui.domainTipsInfo.append("{} {}{}".format(GetTime.getSystemTime4(),"扫描结果已保存至：", saveDirPath[0]))
            resultFile.close()
            # del self.domainScanQueue
        except Exception as e:
            print(e)

    def sendToPortScan(self):
        # 去重
        newDomainList = list(set(self.domainScanList))
        newDomainList.sort(key=(self.domainScanList).index)
        a = "\n".join(newDomainList)
        # print(a)
        self.ui.ipToScan.appendPlainText(a)
        self.ui.domainTipsInfo.append("{} {}".format(GetTime.getSystemTime4(),"已将扫描结果中的ip信息发送至端口扫描模块。"))
        print("{} {}".format(GetTime.getSystemTime4(),"已将扫描结果中的ip信息发送至端口扫描模块。"))

    ############################### 端口扫描 #########################################

    def setScanPort(self, id):
        try:
            if id == -2:
                scanPort = self.httpPort
            elif id == -3:
                scanPort = self.commonPort
            else:
                scanPort = self.allPort
            self.ui.portToScan.setText(scanPort)
        except Exception as e:
            # print(e)
            pass

    def portStartScan(self):
        try:
            self.ui.portStartScanButton.setEnabled(False)
            self.ui.portStopScanButton.setEnabled(True)
            # 表格清除内容
            self.ui.portScanResultTable.setRowCount(0)
            concurrency = self.ui.portScanConcurrent.text()
            timeout = self.ui.portScanTimeout.text()
            scanPort = self.ui.portToScan.text() if self.ui.portToScan.text() is not '' else self.commonPort
            scanIp = self.ui.ipToScan.toPlainText()
            # 创建子进程
            self.portScanThread_ = PortScan(concurrency, timeout, scanIp, scanPort)
            self.portScanThread_.updateResult.connect(self.printPortScanResult)
            self.portScanThread_.updateTipsInfo.connect(self.portScanTipsInfo)
            self.portScanThread_.start()
            self.ui.portScanTipsInfo.append("{} {}".format(GetTime.getSystemTime4(),"正在进行端口扫描，请稍等。"))
        except Exception as e:
            print(e)
            # pass

    def portStopScan(self):
        try:
            self.portScanThread_.stop()
            self.portScanThread_.quit()
            self.portScanThread_.wait()
            self.ui.portStartScanButton.setEnabled(True)
            self.ui.portStopScanButton.setEnabled(False)
            self.ui.portScanTipsInfo.append("{} {}".format(GetTime.getSystemTime4(),"已停止端口扫描。"))
            print("{} {}".format(GetTime.getSystemTime4(),"已停止端口扫描。"))
        except Exception as e:
            print(e)

    def ipInput(self):
        try:
            localPath = os.getcwd()
            ipFilePath = QFileDialog.getOpenFileName(None, "选择文件", localPath, "Txt Files(*.txt);;All Files (*)")
            ipFile = open(ipFilePath[0], 'r', encoding="utf-8")
            ipFileContent = ipFile.read()
            self.ui.ipToScan.appendPlainText(str(ipFileContent))
            ipFile.close()
        except Exception as e:
            # print(e)
            pass

    def printPortScanResult(self, host, port, hport, status):
        try:
            # print("[+] {},{} is {}.".format(host,port,status))
            # 获取端口扫描表格的行数、列数
            rowNum = self.portScanResultTable.rowCount()
            colNum = self.portScanResultTable.columnCount()
            # 添加一行
            self.portScanResultTable.insertRow(rowNum)
            # 添加数据，坑点一：添加 int型 数据后获取不到，值为null，需添加 str 类型
            # 坑点二：添加的数据行为 rowCount - 1 行，而不是 rowCount行
            numItem = QTableWidgetItem(str(rowNum + 1))
            self.portScanResultTable.setItem(self.portScanResultTable.rowCount() - 1, 0, numItem)
            domainItem = QTableWidgetItem(host)
            self.portScanResultTable.setItem(self.portScanResultTable.rowCount() - 1, 1, domainItem)
            ipItem = QTableWidgetItem(port)
            self.portScanResultTable.setItem(self.portScanResultTable.rowCount() - 1, 2, ipItem)
            statusItem = QTableWidgetItem(status)
            self.portScanResultTable.setItem(self.portScanResultTable.rowCount() - 1, 3, statusItem)
            # bannerItem = QTableWidgetItem(banner)
            # self.portScanResultTable.setItem(self.portScanResultTable.rowCount() - 1, 4, bannerItem)
            # 将结果写入队列
            self.portScanQueue.put(str(rowNum + 1) + "," + host + "," + port + "," + status)
            if hport:
                self.portScanList.append("{}:{}".format(host,hport))
        except Exception as e:
            print(e)
            # pass

    def portScanTipsInfo(self, code, status):
        if code:
            self.ui.portStartScanButton.setEnabled(True)
            self.ui.portStopScanButton.setEnabled(False)
        self.ui.portScanTipsInfo.append(status)
        self.ui.portScanTipsInfo.ensureCursorVisible()

    def portScanSave(self):
        try:
            localPath = os.getcwd()
            saveDirPath = QFileDialog.getSaveFileName(None, "选择保存路径", localPath, "CSV Files(*.csv);;All Files (*)")
            # 将队列结果写入文件
            resultFile = open(saveDirPath[0],"a+",encoding="utf-8")
            while not self.portScanQueue.empty():
                line = self.portScanQueue.get()
                if line:
                    resultFile.write(line + "\n")
            self.ui.portScanTipsInfo.append("{} {}{}".format(GetTime.getSystemTime4(),"扫描结果已保存至：",saveDirPath[0]))
            resultFile.close()
            # del self.portScanQueue
        except Exception as e:
            print(e)

    def sendToWebFingerScan(self):
        try:
            a = "\n".join(self.portScanList)
            # print(a)
            self.ui.plainTextEdit_2.appendPlainText(a)
            self.ui.portScanTipsInfo.append(GetTime.getSystemTime4()+" 已将扫描结果中的ip信息发送至Web指纹识别模块。")
            print(GetTime.getSystemTime4()+" 已将扫描结果中的ip信息发送至Web指纹识别模块。")
        except Exception as e:
            print(e)

    ############################### 暴力破解 #########################################

    def startBrute(self):
        try:
            text = self.ui.plainTextEdit_3.toPlainText()
            if text :
                self.ui.pushButton_13.setEnabled(False)
                self.ui.pushButton_9.setEnabled(True)
                concurrency = self.ui.lineEdit_9.text()
                timeout = self.ui.lineEdit_8.text()
                ipText = self.ui.plainTextEdit_3.toPlainText()
                proxy = self.infoCollectProxy
                bruteItem = self.setBruteItem()
                bruteMode = self.bruteMode
                userDict = self.ui.lineEdit_10.text() if self.ui.lineEdit_10.text() else self.bruteUserDict
                passDict = self.ui.lineEdit_11.text() if self.ui.lineEdit_11.text() else self.brutePassDict
                self.Brute_ = Brute(concurrency, timeout, ipText, proxy, bruteItem, bruteMode, userDict, passDict)
                self.Brute_.start()
                self.Brute_.updateSignal.connect(self.brutePrint)
                self.Brute_.updateSignal2.connect(self.bruteTipsInfo)
                self.bruteStartTime = GetTime.getSystemTime3()
                self.ui.textBrowser_3.append("{} 正在进行暴力破解，请稍等。".format(GetTime.getSystemTime4()))
            else:
                pass
        except Exception as e:
            print(e)

    def stopBrute(self):
        self.Brute_.stop()
        self.ui.pushButton_13.setEnabled(True)
        self.ui.pushButton_9.setEnabled(False)
        time = GetTime.getSystemTime4()
        self.ui.textBrowser_3.append("{} 已停止暴力破解。".format(time))
        print("{} 已停止暴力破解。".format(time))

    def importUser(self):
        try:
            localPath = os.getcwd()
            ipFilePath = QFileDialog.getOpenFileName(None, "选择用户字典", localPath, "Txt Files(*.txt);;All Files (*)")
            # ipFile = open(ipFilePath[0], 'r', encoding="utf-8")
            # ipFileContent = ipFile.read()
            # self.ui.plainTextEdit_11.appendPlainText(str(ipFileContent))
            # ipFile.close()
            self.ui.lineEdit_10.setText(ipFilePath[0])
            self.bruteUserDict = ipFilePath[0]
        except Exception as e:
            # print(e)
            pass

    def importPass(self):
        try:
            localPath = os.getcwd()
            ipFilePath = QFileDialog.getOpenFileName(None, "选择密码字典", localPath, "Txt Files(*.txt);;All Files (*)")
            # ipFile = open(ipFilePath[0], 'r', encoding="utf-8")
            # ipFileContent = ipFile.read()
            # self.ui.plainTextEdit_11.appendPlainText(str(ipFileContent))
            # ipFile.close()
            self.ui.lineEdit_11.setText(ipFilePath[0])
            self.brutePassDict = ipFilePath[0]
        except Exception as e:
            # print(e)
            pass

    def brutePrint(self, para):
        try:
            ip = para.split("::")[0]
            port = para.split('::')[1]
            portType = para.split('::')[2]
            username = para.split('::')[3]
            password = para.split('::')[4]
            # 获取表格的行数、列数
            rowNum = self.bruteResultTable.rowCount()
            colNum = self.bruteResultTable.columnCount()
            # 添加一行
            self.bruteResultTable.insertRow(rowNum)
            # 添加数据
            numItem = QTableWidgetItem(str(rowNum + 1))
            self.bruteResultTable.setItem(self.bruteResultTable.rowCount() - 1, 0, numItem)
            ipItem = QTableWidgetItem(ip)
            self.bruteResultTable.setItem(self.bruteResultTable.rowCount() - 1, 1, ipItem)
            portItem = QTableWidgetItem(port)
            self.bruteResultTable.setItem(self.bruteResultTable.rowCount() - 1, 2, portItem)
            portTypeItem = QTableWidgetItem(portType)
            self.bruteResultTable.setItem(self.bruteResultTable.rowCount() - 1, 3, portTypeItem)
            userItem = QTableWidgetItem(username)
            self.bruteResultTable.setItem(self.bruteResultTable.rowCount() - 1, 4, userItem)
            passItem = QTableWidgetItem(password)
            self.bruteResultTable.setItem(self.bruteResultTable.rowCount() - 1, 5, passItem)
            self.bruteQueue.put('{},{},{},{},{},{}'.format(str(rowNum + 1),ip,port,portType,username,password))
        except Exception as e:
            print(e)
            # pass

    def bruteResultOutput(self):
        try:
            localPath = os.getcwd()
            saveDirPath = QFileDialog.getSaveFileName(None, "选择保存路径", localPath, "CSV Files(*.csv);;All Files (*)")
            # 将队列结果写入文件
            resultFile = open(saveDirPath[0],"a+",encoding="utf-8")
            while not self.bruteQueue.empty():
                line = self.bruteQueue.get()
                if line:
                    resultFile.write(line + "\n")
            self.ui.textBrowser_3.append("{} 结果已保存至：{}".format(GetTime.getSystemTime4(), saveDirPath[0]))
        except Exception as e:
            print(e)
        finally:
            resultFile.close()

    def bruteTipsInfo(self, code, message):
        if code:
            self.ui.pushButton_13.setEnabled(True)
            self.ui.pushButton_9.setEnabled(False)
        self.ui.textBrowser_3.append(message)

    def setBruteMode(self):
        if self.ui.checkBox_3.isChecked():
            self.bruteMode = 1
        else:
            self.bruteMode = 0

    def setDefaultDict(self):
        if self.ui.checkBox_2.isChecked():
            self.ui.lineEdit_10.setEnabled(False)
            self.ui.lineEdit_10.clear()
            self.ui.lineEdit_11.setEnabled(False)
            self.ui.lineEdit_11.clear()
            self.ui.pushButton_15.setEnabled(False)
            self.ui.pushButton_17.setEnabled(False)
            self.bruteUserDict = self.defaultBruteUserDict
            self.brutePassDict = self.defaultBrutePassDict
        else:
            self.ui.lineEdit_10.setEnabled(True)
            self.ui.lineEdit_11.setEnabled(True)
            self.ui.pushButton_15.setEnabled(True)
            self.ui.pushButton_17.setEnabled(True)
            self.bruteUserDict = self.ui.lineEdit_10.text()
            self.brutePassDict = self.ui.lineEdit_11.text()

    def setBruteItem(self):
        s = []
        if self.ui.checkBox_4.isChecked():
            s.append(self.bruteItem[0])
        if self.ui.checkBox_5.isChecked():
            s.append(self.bruteItem[1])
        if self.ui.checkBox_6.isChecked():
            s.append(self.bruteItem[2])
        if self.ui.checkBox_7.isChecked():
            s.append(self.bruteItem[3])
        if self.ui.checkBox_9.isChecked():
            s.append(self.bruteItem[4])
        if self.ui.checkBox_10.isChecked():
            s.append(self.bruteItem[5])
        return s

    ############################### 目录扫描 #########################################

    def dirStartScan(self):
        try:
            url = self.ui.plainTextEdit_5.toPlainText()
            if url:
                self.ui.pushButton_2.setEnabled(False)
                self.ui.pushButton_4.setEnabled(True)
                self.dirScanQueue = queue.Queue()
                self.dirScanQueue.put("序号,目标,地址,响应状态码")
                # 表格清除内容
                self.ui.dirScanResult.setRowCount(0)
                concurrency = self.ui.lineEdit_13.text()
                timeout = self.ui.lineEdit_12.text()
                frequency = self.ui.lineEdit_15.text()
                method = self.getDirScanMethod()
                suffix = self.getSuffix()
                statuscode = self.getStatusCode()
                proxy = self.infoCollectProxy
                self.setUA()
                useragent = self.defaultUserAgent
                # 创建子进程
                self.dirScanThread_ = DirScan(concurrency, timeout, frequency, method, suffix, statuscode, url, proxy, useragent)
                # self.dirScanThread_.setDaemon(True)
                self.dirScanThread_.updateResult.connect(self.printDirScanResult)
                self.dirScanThread_.updateTipsInfo.connect(self.dirScanTipsInfo)
                self.dirScanThread_.start()
                time = GetTime.getSystemTime4()
                self.ui.textBrowser_4.append(time + "正在进行目录扫描，请稍等。")
                print(time + "正在进行目录扫描，请稍等。")
            else:
                time = GetTime.getSystemTime4()
                self.ui.textBrowser_4.append(time + "请输入待扫描的域名")
        except Exception as e:
            print(e)
            # pass

    def dirStopScan(self):
        try:
            self.dirScanThread_.stop()
            self.ui.pushButton_2.setEnabled(True)
            time = GetTime.getSystemTime4()
            self.ui.textBrowser_4.append(time + " 已停止目录扫描。")
            print(time + " 已停止目录扫描。")
        except Exception as e:
            print(e)

    def importUrl(self):
        try:
            localPath = os.getcwd()
            urlFilePath = QFileDialog.getOpenFileName(None, "选择文件", localPath, "Txt Files(*.txt);;All Files (*)")
            urlFile = open(urlFilePath[0], 'r', encoding="utf-8")
            urlFileContent = urlFile.read()
            self.ui.plainTextEdit_5.appendPlainText(str(urlFileContent))
            urlFile.close()
        except Exception as e:
            print(e)

    def printDirScanResult(self, url, path, statuscode):
        try:
            # print("[+]" + url + "," + path +","+ statuscode)
            # 获取目录扫描表格的行数、列数
            rowNum = self.dirScanResultTable.rowCount()
            colNum = self.dirScanResultTable.columnCount()
            # 添加一行
            self.dirScanResultTable.insertRow(rowNum)
            # 添加数据，坑点一：添加 int型 数据后获取不到，值为null，需添加 str 类型
            # 坑点二：添加的数据行为 rowCount - 1 行，而不是 rowCount行
            numItem = QTableWidgetItem(str(rowNum + 1))
            self.dirScanResultTable.setItem(self.dirScanResultTable.rowCount() - 1, 0, numItem)
            urlItem = QTableWidgetItem(url)
            self.dirScanResultTable.setItem(self.dirScanResultTable.rowCount() - 1, 1, urlItem)
            pathItem = QTableWidgetItem(path)
            self.dirScanResultTable.setItem(self.dirScanResultTable.rowCount() - 1, 2, pathItem)
            statusItem = QTableWidgetItem(statuscode)
            self.dirScanResultTable.setItem(self.dirScanResultTable.rowCount() - 1, 3, statusItem)
            # 将结果写入队列
            self.dirScanQueue.put(str(rowNum + 1) + "," + url + "," + path + "," + statuscode)
        except Exception as e:
            print(e)

    def dirScanOutput(self):
        try:
            if not self.dirScanQueue.empty():
                localPath = os.getcwd()
                saveDirPath = QFileDialog.getSaveFileName(None, "选择保存路径", localPath, "CSV Files(*.csv);;All Files (*)")
                # 将队列结果写入文件
                resultFile = open(saveDirPath[0],"a+",encoding="utf-8")
                while not self.dirScanQueue.empty():
                    line = self.dirScanQueue.get()
                    if line:
                        resultFile.write(line + "\n")
                time = GetTime.getSystemTime4()
                self.ui.textBrowser_4.append(time + "扫描结果已保存至：" + saveDirPath[0])
                resultFile.close()
        except Exception as e:
            print(e)

    def getDirScanMethod(self):
        index = self.ui.comboBox.currentIndex()
        method = self.dirScanMethodList[index]
        # method = "GET" if index else "HEAD"
        # print(method)
        return(method)

    def getSuffix(self):
        s = []
        if self.ui.checkBox_11.isChecked():
            s.append(self.suffix[0])
        if self.ui.checkBox_12.isChecked():
            s.append(self.suffix[1])
        if self.ui.checkBox_13.isChecked():
            s.append(self.suffix[2])
        if self.ui.checkBox_14.isChecked():
            s.append(self.suffix[3])
        if self.ui.checkBox_15.isChecked():
            s.append(self.suffix[4])
        if self.ui.checkBox_16.isChecked():
            s.append(self.suffix[5])
        if self.ui.checkBox_17.isChecked():
            s.append(self.suffix[6])
        return s

    def getStatusCode(self):
        s = []
        if self.ui.checkBox_18.isChecked():
            s.append(self.statuscode[0])
        if self.ui.checkBox_19.isChecked():
            # s.append(self.statuscode[1])
            s.extend([str(i) for i in range(300, 400)])
        if self.ui.checkBox_20.isChecked():
            s.append(self.statuscode[2])
        return s

    def dirScanTipsInfo(self, status):
        self.ui.textBrowser_4.append(status)
        self.ui.textBrowser_4.ensureCursorVisible()

    ############################### web指纹识别 #########################################

    def fingerStartScan(self):
        try:
            self.ui.tableWidget_7.setRowCount(0)
            text = self.ui.plainTextEdit_2.toPlainText()
            if text :
                self.ui.pushButton_21.setEnabled(False)
                self.ui.pushButton_20.setEnabled(True)
                concurrency = self.ui.lineEdit_17.text()
                timeout = self.ui.lineEdit_16.text()
                urlText = self.ui.plainTextEdit_2.toPlainText()
                proxy = self.infoCollectProxy
                self.setUA()
                useragent = self.defaultUserAgent
                self.FingerScan_ = FingerScan(concurrency, timeout, self.scanMode, urlText, proxy, useragent)
                self.FingerScan_.start()
                self.FingerScan_.updateSignal.connect(self.fingerScanPrint)
                self.FingerScan_.updateSignal2.connect(self.fingerScanTipsInfo)
                self.ui.textBrowser_5.append("{} 正在进行web指纹识别，请稍等。".format(GetTime.getSystemTime4()))
        except Exception as e:
            print(e)

    def fingerStopScan(self):
        self.FingerScan_.stop()
        self.ui.pushButton_21.setEnabled(True)
        time = GetTime.getSystemTime4()
        self.ui.textBrowser_5.append("{} 已停止web指纹识别。".format(time))
        print("{} 已停止web指纹识别。".format(time))

    def importUrl2(self):
        try:
            localPath = os.getcwd()
            ipFilePath = QFileDialog.getOpenFileName(None, "选择文件", localPath, "Txt Files(*.txt);;All Files (*)")
            ipFile = open(ipFilePath[0], 'r', encoding="utf-8")
            ipFileContent = ipFile.read()
            self.ui.plainTextEdit_2.appendPlainText(str(ipFileContent))
            ipFile.close()
        except Exception as e:
            # print(e)
            pass

    def fingerScanPrint(self, para):
        try:
            url = para.split("::")[0]
            statusCode = para.split('::')[1]
            title = para.split('::')[2]
            finger = (para.split('::')[3]).strip(",")
            server = para.split('::')[4]
            # 获取表格的行数、列数
            rowNum = self.fingerScanResultTable.rowCount()
            colNum = self.fingerScanResultTable.columnCount()
            # 添加一行
            self.fingerScanResultTable.insertRow(rowNum)
            # 添加数据
            numItem = QTableWidgetItem(str(rowNum + 1))
            self.fingerScanResultTable.setItem(self.fingerScanResultTable.rowCount() - 1, 0, numItem)
            urlItem = QTableWidgetItem(url)
            self.fingerScanResultTable.setItem(self.fingerScanResultTable.rowCount() - 1, 1, urlItem)
            statusCodeItem = QTableWidgetItem(statusCode)
            self.fingerScanResultTable.setItem(self.fingerScanResultTable.rowCount() - 1, 2, statusCodeItem)
            titleItem = QTableWidgetItem(title)
            self.fingerScanResultTable.setItem(self.fingerScanResultTable.rowCount() - 1, 3, titleItem)
            fingerItem = QTableWidgetItem(finger)
            self.fingerScanResultTable.setItem(self.fingerScanResultTable.rowCount() - 1, 4, fingerItem)
            serverItem = QTableWidgetItem(server)
            self.fingerScanResultTable.setItem(self.fingerScanResultTable.rowCount() - 1, 5, serverItem)
            self.fingerQueue.put('{},{},{},{},{}'.format(str(rowNum + 1),url,statusCode,title,finger,server))
        except Exception as e:
            print(e)
            # pass

    def fingerScanOutput(self):
        try:
            localPath = os.getcwd()
            saveDirPath = QFileDialog.getSaveFileName(None, "选择保存路径", localPath, "CSV Files(*.csv);;All Files (*)")
            # 将队列结果写入文件
            resultFile = open(saveDirPath[0],"a+",encoding="utf-8")
            while not self.fingerQueue.empty():
                line = self.fingerQueue.get()
                if line:
                    resultFile.write(line + "\n")
            self.ui.textBrowser_5.append("{} 识别结果已保存至：{}".format(GetTime.getSystemTime4(), saveDirPath[0]))
            resultFile.close()
        except Exception as e:
            print(e)

    def fingerScanTipsInfo(self, code, message):
        if code:
            self.ui.pushButton_21.setEnabled(True)
            self.ui.pushButton_20.setEnabled(False)
        self.ui.textBrowser_5.append(message)

    def setScanMode(self, id):
        try:
            if id == -2:
                self.scanMode = 1
            elif id == -3:
                self.scanMode = 0
            else:
                self.scanMode = 1
            # print(id)
        except Exception as e:
            # print(e)
            pass

    ############################### 漏洞扫描 #########################################

    def vulnStartScan(self):
        try:
            text = self.ui.plainTextEdit_11.toPlainText()
            scanMode = self.setScanMode2()
            self.ui.tableWidget_10.setRowCount(0)
            if text and scanMode:
                self.ui.pushButton_30.setEnabled(False)
                self.ui.pushButton_28.setEnabled(True)
                concurrency = self.ui.lineEdit_21.text()
                timeout = self.ui.lineEdit_20.text()
                urlText = self.ui.plainTextEdit_11.toPlainText()
                cookie = self.ui.lineEdit_28.text()
                para = self.ui.lineEdit_18.text()
                proxy = self.infoCollectProxy
                self.setUA()
                useragent = self.defaultUserAgent
                method = self.VulnScanMethod
                self.VulnScan_ = VulnScan(concurrency, timeout, scanMode, method, urlText, cookie, para, proxy, useragent)
                self.VulnScan_.start()
                self.VulnScan_.updateSignal.connect(self.vulnScanPrint)
                self.VulnScan_.updateSignal2.connect(self.vulnScanTipsInfo)
                self.ui.textBrowser_8.append("{} 正在进行漏洞扫描，请稍等。".format(GetTime.getSystemTime4()))
            else:
                time = GetTime.getSystemTime4()
                if not text:
                    self.ui.textBrowser_8.append(time + " 请输入待扫描的url。")
                if not scanMode:
                    self.ui.textBrowser_8.append(time + " 请选择扫描模式。")
        except Exception as e:
            print(e)

    def vulnStopScan(self):
        self.VulnScan_.stop()
        self.ui.pushButton_30.setEnabled(True)
        self.ui.pushButton_28.setEnabled(False)
        time = GetTime.getSystemTime4()
        self.ui.textBrowser_8.append("{} 已停止漏洞扫描。".format(time))
        print("{} 已停止漏洞扫描。".format(time))

    def vulnScanPrint(self, para):
        try:
            url = para.split("::")[0]
            vuln = para.split('::')[1]
            injectPoint = para.split('::')[2]
            payload = para.split('::')[3]
            # 获取表格的行数、列数
            rowNum = self.vulnResultTable.rowCount()
            colNum = self.vulnResultTable.columnCount()
            # 添加一行
            self.vulnResultTable.insertRow(rowNum)
            # 添加数据
            numItem = QTableWidgetItem(str(rowNum + 1))
            self.vulnResultTable.setItem(self.vulnResultTable.rowCount() - 1, 0, numItem)
            urlItem = QTableWidgetItem(url)
            self.vulnResultTable.setItem(self.vulnResultTable.rowCount() - 1, 1, urlItem)
            vulnItem = QTableWidgetItem(vuln)
            self.vulnResultTable.setItem(self.vulnResultTable.rowCount() - 1, 2, vulnItem)
            injectPointItem = QTableWidgetItem(injectPoint)
            self.vulnResultTable.setItem(self.vulnResultTable.rowCount() - 1, 3, injectPointItem)
            payloadItem = QTableWidgetItem(payload)
            self.vulnResultTable.setItem(self.vulnResultTable.rowCount() - 1, 4, payloadItem)
            self.vulnQueue.put('{},{},{},{},{}'.format(str(rowNum + 1),url,vuln,injectPoint,payload))
        except Exception as e:
            print(e)
            # pass

    def importUrl3(self):
        try:
            localPath = os.getcwd()
            ipFilePath = QFileDialog.getOpenFileName(None, "选择文件", localPath, "Txt Files(*.txt);;All Files (*)")
            ipFile = open(ipFilePath[0], 'r', encoding="utf-8")
            ipFileContent = ipFile.read()
            self.ui.plainTextEdit_11.appendPlainText(str(ipFileContent))
            ipFile.close()
        except Exception as e:
            # print(e)
            pass

    def vulnResultOutput(self):
        try:
            localPath = os.getcwd()
            saveDirPath = QFileDialog.getSaveFileName(None, "选择保存路径", localPath, "CSV Files(*.csv);;All Files (*)")
            # 将队列结果写入文件
            resultFile = open(saveDirPath[0],"a+",encoding="utf-8")
            while not self.vulnQueue.empty():
                line = self.vulnQueue.get()
                if line:
                    resultFile.write(line + "\n")
            self.ui.textBrowser_8.append("{} 识别结果已保存至：{}".format(GetTime.getSystemTime4(), saveDirPath[0]))
            resultFile.close()
        except Exception as e:
            print(e)

    def setScanMode2(self):
        s = []
        if self.ui.checkBox_21.isChecked():
            s.append(1)
        if self.ui.checkBox_22.isChecked():
            s.append(2)
        return s

    def getVulnScanMethod(self):
        index = self.ui.comboBox_4.currentIndex()
        if index:
            self.ui.label_16.setVisible(True)
            self.ui.lineEdit_18.setVisible(True)
            self.VulnScanMethod = "POST"
        else:
            self.ui.label_16.setVisible(False)
            self.ui.lineEdit_18.setVisible(False)
            self.VulnScanMethod = "GET"

    def vulnScanTipsInfo(self, code, message):
        if code:
            self.ui.pushButton_30.setEnabled(True)
            self.ui.pushButton_28.setEnabled(False)
        self.ui.textBrowser_8.append(message)

    ############################### 编码转换 #########################################

    def exchange(self):
        index1 = self.ui.comboBox_9.currentIndex()
        index2 = self.ui.comboBox_7.currentIndex()
        index3 = self.ui.comboBox_11.currentIndex()
        lineEdit_6 = self.ui.lineEdit_6.text()
        # label_56 = self.ui.label_56.text()
        # label_29 = self.ui.label_29.text()

        index4 = self.ui.comboBox_10.currentIndex()
        index5 = self.ui.comboBox_8.currentIndex()
        index6 = self.ui.comboBox_12.currentIndex()
        lineEdit_7 = self.ui.lineEdit_7.text()
        # label_57 = self.ui.label_57.text()
        # label_67 = self.ui.label_67.text()

        self.ui.comboBox_9.setCurrentIndex(index4)
        self.ui.comboBox_7.clear()
        self.ui.comboBox_7.addItems(self.coding21[index4])
        self.ui.comboBox_7.setCurrentIndex(index5)

        self.ui.comboBox_10.setCurrentIndex(index1)
        self.ui.comboBox_8.clear()
        self.ui.comboBox_8.addItems(self.coding21[index1])
        self.ui.comboBox_8.setCurrentIndex(index2)

    def convert(self):
        try:
            text = self.ui.plainTextEdit_16.toPlainText()
            if text :
                coding = self.ui.comboBox_6.currentText()
                inputCoding = self.ui.comboBox_7.currentText()
                optionLeft1 = self.ui.comboBox_11.currentText()
                optionLeft2 = self.ui.lineEdit_6.text()
                outputCoding = self.ui.comboBox_8.currentText()
                optionRight1 = self.ui.comboBox_12.currentText()
                optionRight2 = self.ui.lineEdit_7.text()
                self.CodeConvert_ = CodeConvert(coding, inputCoding, optionLeft1, optionLeft2, outputCoding, optionRight1, optionRight2, text, self.coding21)
                self.CodeConvert_.start()
                self.CodeConvert_.updateSignal.connect(self.printCodingResult)
            else:
                self.clearString()
            # self.saveStatus()
        except Exception as e:
            print(e)

    def printCodingResult(self, result):
        self.ui.plainTextEdit_17.setPlainText(result)
        self.saveStatus()

    def saveCodeResult(self):
        text = self.ui.plainTextEdit_17.toPlainText()
        try:
            if self.CodeConvert_:
                localPath = os.getcwd()
                saveDirPath = QFileDialog.getSaveFileName(None, "选择保存路径", localPath, "TXT Files(*.txt);;All Files (*)")
                self.CodeConvert_ .saveResult(text, saveDirPath[0])
                self.CodeConvert_.updateSignal.connect(self.tips)
        except Exception as e:
            print(e)

    def tips(self, message, path):
        try:
            reply = QMessageBox.information(None, '提示', message, QMessageBox.Yes | QMessageBox.No)
            if reply == QMessageBox.Yes:
                # event.accept()
                platformVersion = platform.system()
                if platformVersion == 'Windows':
                    os.system("start explorer %s" % path)
                elif platformVersion == 'Linux':
                    os.system("nautilus .")
                else:
                    pass
            else:
                # event.ignore()
                pass
        except Exception as e:
            print(e)
            # pass

    def codingChanged(self):
        index = self.ui.comboBox_6.currentIndex()
        # print(index)

    def saveStatus(self):
        try:
            # self.status = [[0, 0, 0, '', 0, 0, 0, ''], [0, 0, 0, '', 0, 0, 0, ''], [0, 0, 0, '', 0, 0, 0, '']]

            index = self.ui.comboBox_2.currentIndex()
            # print(index)
            index1 = self.ui.comboBox_9.currentIndex()
            index2 = self.ui.comboBox_7.currentIndex()
            index3 = self.ui.comboBox_11.currentIndex()
            # lineEdit_6 = self.ui.lineEdit_6.text()
            plainTextEdit_16 = self.ui.plainTextEdit_16.toPlainText()
            # label_56 = self.ui.label_56.text()
            # label_29 = self.ui.label_29.text()

            index4 = self.ui.comboBox_10.currentIndex()
            index5 = self.ui.comboBox_8.currentIndex()
            index6 = self.ui.comboBox_12.currentIndex()
            # lineEdit_7 = self.ui.lineEdit_7.text()
            plainTextEdit_17 = self.ui.plainTextEdit_17.toPlainText()
            # label_57 = self.ui.label_57.text()
            # label_67 = self.ui.label_67.text()

            self.status[index] = [index1, index2, index3, plainTextEdit_16, index4, index5, index6, plainTextEdit_17]
            # print(self.status[index])
        except Exception as e:
            print(e)

    def statusChanged(self):
        try:
            index = self.ui.comboBox_2.currentIndex()
            # print(index)
            # 注意一定要先修改输出编码的格式（右边）再修改输入编码的格式（左边）
            # 因为如果点击了自动转换，那么检测到输入文本的变动就会立即进行转码，而这时右边的输出编码格式还未修改，沿用之前状态的。
            self.ui.comboBox_10.setCurrentIndex(self.status[index][4])
            self.ui.comboBox_8.clear()
            self.ui.comboBox_8.addItems(self.coding21[self.status[index][4]])
            self.ui.comboBox_8.setCurrentIndex(self.status[index][5])

            self.ui.comboBox_9.setCurrentIndex(self.status[index][0])
            self.ui.comboBox_7.clear()
            self.ui.comboBox_7.addItems(self.coding21[self.status[index][0]])
            self.ui.comboBox_7.setCurrentIndex(self.status[index][1])
            self.ui.plainTextEdit_16.setPlainText(self.status[index][3])

            # self.ui.plainTextEdit_17.setPlainText(self.status[index][7])

            if not self.ui.checkBox_26.isChecked():
                self.convert()
        except Exception as e:
            print(e)

    def inputCodingChanged(self):
        index = self.ui.comboBox_9.currentIndex()
        self.ui.comboBox_7.clear()
        self.ui.comboBox_7.addItems(self.coding21[index])

    def outputCodingChanged(self):
        index = self.ui.comboBox_10.currentIndex()
        self.ui.comboBox_8.clear()
        self.ui.comboBox_8.addItems(self.coding21[index])

    def inputCodingChanged2(self):
        index = self.ui.comboBox_7.currentIndex()
        index1 = self.ui.comboBox_9.currentIndex()
        if index == 1 and index1 == 0:  # ascii
            self.ui.comboBox_11.clear()
            self.ui.lineEdit_6.clear()
            self.ui.comboBox_11.setEnabled(True)
            self.ui.lineEdit_6.setEnabled(True)
            self.ui.label_56.setText("进制：")
            self.ui.label_29.setText("分隔符：")
            self.ui.comboBox_11.addItems(self.binhexoct)
            self.ui.comboBox_11.setCurrentIndex(1)
        elif index == 2 and index1 == 0:    # base64
            self.ui.comboBox_11.clear()
            self.ui.lineEdit_6.setEnabled(True)
            self.ui.comboBox_11.setEnabled(False)
            self.ui.label_56.setText("选项：")
            self.ui.label_29.setText("字母表：")
            self.ui.lineEdit_6.setText("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
        elif index == 7 and index1 == 0:    # unicodebase64
            self.ui.comboBox_11.clear()
            self.ui.lineEdit_6.setEnabled(True)
            self.ui.comboBox_11.setEnabled(False)
            self.ui.label_56.setText("选项：")
            self.ui.label_29.setText("字母表：")
            self.ui.lineEdit_6.setText("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 + /")
        elif index1 == 1:
            self.ui.comboBox_11.clear()
            self.ui.comboBox_11.setEnabled(True)
            self.ui.comboBox_11.addItems(self.coding24)
            self.ui.lineEdit_6.clear()
            self.ui.lineEdit_6.setEnabled(False)
            self.ui.label_56.setText("选项：")
            self.ui.label_29.setText("选项1：")
        else:
            self.ui.lineEdit_6.clear()
            self.ui.comboBox_11.clear()
            self.ui.lineEdit_6.setEnabled(False)
            self.ui.comboBox_11.setEnabled(False)
            self.ui.label_56.setText("选项：")
            self.ui.label_29.setText("选项1：")

    def outputCodingChanged2(self):
        index = self.ui.comboBox_8.currentIndex()
        index1 = self.ui.comboBox_10.currentIndex()
        if index == 1 and index1 == 0:  # ascii
            self.ui.comboBox_12.clear()
            self.ui.lineEdit_7.clear()
            self.ui.comboBox_12.setEnabled(True)
            self.ui.lineEdit_7.setEnabled(True)
            self.ui.label_57.setText("进制：")
            self.ui.label_67.setText("分隔符：")
            self.ui.comboBox_12.addItems(["16", "10", "8", "2"])
            self.ui.comboBox_12.setCurrentIndex(1)
        elif index == 2 and index1 == 0:    # base64
            self.ui.comboBox_12.clear()
            self.ui.lineEdit_7.setEnabled(True)
            self.ui.comboBox_12.setEnabled(False)
            self.ui.label_57.setText("选项：")
            self.ui.label_67.setText("字母表：")
            self.ui.lineEdit_7.setText("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
        elif index == 7 and index1 == 0:    # unicodebase64
            self.ui.comboBox_12.clear()
            self.ui.lineEdit_7.setEnabled(True)
            self.ui.comboBox_12.setEnabled(False)
            self.ui.label_57.setText("选项：")
            self.ui.label_67.setText("字母表：")
            self.ui.lineEdit_7.setText("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 + /")
        elif index1 == 1:
             self.ui.comboBox_12.clear()
             self.ui.comboBox_12.setEnabled(True)
             self.ui.comboBox_12.addItems(self.coding24)
             self.ui.lineEdit_7.clear()
             self.ui.lineEdit_7.setEnabled(False)
             self.ui.label_57.setText("选项：")
             self.ui.label_67.setText("选项1：")
        else:
            self.ui.lineEdit_7.clear()
            self.ui.comboBox_12.clear()
            self.ui.lineEdit_7.setEnabled(False)
            self.ui.comboBox_12.setEnabled(False)
            self.ui.label_57.setText("选项：")
            self.ui.label_67.setText("选项1：")

    def autoConvert(self):
        if self.ui.checkBox_26.isChecked():
            self.ui.plainTextEdit_16.textChanged.connect(self.convert)
        else:
            self.ui.plainTextEdit_16.textChanged.disconnect(self.convert)

    def setByte(self, obj, num):
        obj.setText("{} Bytes".format(str(num)))

    def clearString(self):
        if self.ui.plainTextEdit_16.toPlainText():
            self.ui.plainTextEdit_16.clear()
        if self.ui.plainTextEdit_17.toPlainText():
            self.ui.plainTextEdit_17.clear()

    ############################### 杀软识别 #########################################

    def antivirusIdentify(self):
        try:
            # 清除表格内容
            # self.ui.identifyResultTable.clearContents()
            self.ui.identifyResultTable.setRowCount(0)
            tasklist = self.ui.antivirusAdd.toPlainText()
            # 创建子进程
            self.antivirusIdentifyThread_ = AvIdentify(tasklist, self.antivirusdic, self.wafdic)
            # 将子进程中的信号与printavresult槽函数绑定
            self.antivirusIdentifyThread_.updateResult.connect(self.printAvResult)
            # 启动杀软识别子进程
            self.antivirusIdentifyThread_.start()
        except Exception as e:
            print(e)

    def printAvResult(self, para):
        try:
            # avlist中每一项：进程名+pid+服务名+杀软名
            process = para.split(":")[0]
            pid = para.split(':')[1]
            service = para.split(':')[2]
            avName = para.split(':')[3]
            # 获取表格的行数、列数
            rowNum = self.identifyResultTable.rowCount()
            colNum = self.identifyResultTable.columnCount()
            # 添加一行
            self.identifyResultTable.insertRow(rowNum)
            # 添加数据，坑点一：添加 int型 数据后获取不到，值为null，需添加 str 类型
            # 坑点二：添加的数据行为 rowCount - 1 行，而不是 rowCount行
            numItem = QTableWidgetItem(str(rowNum + 1))
            self.identifyResultTable.setItem(self.identifyResultTable.rowCount() - 1, 0, numItem)
            processItem = QTableWidgetItem(process)
            self.identifyResultTable.setItem(self.identifyResultTable.rowCount() - 1, 1, processItem)
            pidItem = QTableWidgetItem(pid)
            self.identifyResultTable.setItem(self.identifyResultTable.rowCount() - 1, 2, pidItem)
            serviceItem = QTableWidgetItem(service)
            self.identifyResultTable.setItem(self.identifyResultTable.rowCount() - 1, 3, serviceItem)
            avNameItem = QTableWidgetItem(avName)
            self.identifyResultTable.setItem(self.identifyResultTable.rowCount() - 1, 4, avNameItem)
        except Exception as e:
            print(e)
            # pass

    ############################### 字典生成 #########################################

    def setGeneratePath(self):
        localPath = os.getcwd()
        savePath = QFileDialog.getExistingDirectory(None, "选择字典生成路径", localPath)
        self.savePath = savePath
        self.ui.lineEdit_27.setText(self.savePath)
        print(self.savePath)

    def dictGenerate(self):
        # 组合方式
        combin = self.getCombination()
        # 生成路径
        path = self.ui.lineEdit_27.text()
        # A项内容
        aItem = self.ui.plainTextEdit_26.toPlainText()
        # B项内容
        bItem = self.ui.plainTextEdit_27.toPlainText()
        # C项内容
        cItem = self.ui.plainTextEdit_28.toPlainText()
        # 是否生成多个文件
        multiterm = self.ui.checkBox_31.isChecked()
        # 去重
        removeduplicate = self.ui.checkBox.isChecked()
        try:
            if path:
                # 创建子进程
                self.dictGenerateThread_ = DictGenerate(combin, path, aItem, bItem, cItem, multiterm, removeduplicate)
                self.dictGenerateThread_.start()
                # 字典生成完成提示
                self.dictGenerateThread_.updateResult.connect(self.dictGenerOver)
            else:
                QMessageBox.warning(self.ui,'提示','请输入生成路径！')
        except Exception as e:
            print(e)

    def setBItem(self, id):
        try:
            bcontent = ''
            if id == -2:
                b = open(self.b1txtdic, encoding='utf-8')
                bcontent = b.read()
            elif id == -3:
                b = open(self.b2txtdic, encoding='utf-8')
                bcontent = b.read()
            else:
                b = open(self.b1txtdic, encoding='utf-8')
                bcontent = b.read()
            self.ui.plainTextEdit_27.setPlainText(bcontent)
            # print(id)
            b.close()
        except Exception as e:
            print(e)
            # pass

    def setCItem(self, id):
        try:
            ccontent = ''
            if id == -2:
                c = open(self.c1txtdic, encoding='utf-8')
                ccontent = c.read()
            elif id == -3:
                c = open(self.c2txtdic, encoding='utf-8')
                ccontent = c.read()
            else:
                c = open(self.c1txtdic, encoding='utf-8')
                ccontent = c.read()
            self.ui.plainTextEdit_28.setPlainText(ccontent)
            c.close()
            # print(id)
        except Exception as e:
            print(e)
            # pass

    def setCombination(self):
        try:
            combindic = open(self.combindic, 'r', encoding="utf-8")
            text = combindic.read()
            combindic.close()
            self.ui.plainTextEdit_19.setPlainText(text)
        except Exception as e:
            print(e)

    def getCombination(self):
        try:
            combindic = open(self.combindic, 'w', encoding="utf-8")
            text = self.ui.plainTextEdit_19.toPlainText()
            # 去 \n , str -> list
            combin = (text.replace('\n', ',')).split(',')
            # 去空
            combin = list(filter(None, combin))
            newcombin = []
            # 组合方式必须是 allCombin中的36种
            for i in combin:
                if i in self.allCombin:
                    newcombin.append(i)
                    combindic.write(i+",")
            combindic.close()
            return newcombin
        except Exception as e:
            print(e)

    def dictGenerOver(self, info):
        print(info)
        try:
            reply = QMessageBox.question(None, '提示', info, QMessageBox.Yes | QMessageBox.No)
            if reply == QMessageBox.Yes:
                platformVersion = platform.system()
                if platformVersion == 'Windows':
                    # os.startfile(filepath)
                    os.system("start %s" % self.ui.lineEdit_27.text())
                elif platformVersion == 'Linux':
                    os.system("nautilus .")
                else:
                    pass
            else:
                # event.ignore()
                pass
        except Exception as e:
            print(e)
            # pass

    ############################### 团队 #########################################

    def getIP(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((("8.8.8.8"), 80))
            ip = s.getsockname()[0]
            self.ui.lineEdit.setText(ip)
        except Exception as e:
            print(e)
        finally:
            s.close()

    def Cs(self, index):
        try:
            # 0 - tcp客户端    1 - tcp服务端
            index = index if index else self.ui.comboBox_13.currentIndex()
            # print(index)
            if index:
                self.ui.label_59.setText("设置连接数")
                self.ui.lineEdit_3.setText("100")
                self.ui.label_6.setVisible(True)
                self.ui.lineEdit.setVisible(True)
                self.ui.pushButton.setVisible(True)
                self.ui.pushButton_3.setText("开启监听")
                self.ui.showDialog.setEnabled(False)
                if self.isSignalConnected(self.ui.pushButton_3, "clicked()"):
                    self.ui.pushButton_3.clicked.disconnect(self.connectServer2)
                self.ui.pushButton_3.clicked.connect(self.createServer)
            else:
                self.ui.label_6.setVisible(False)
                self.ui.lineEdit.setVisible(False)
                self.ui.pushButton.setVisible(False)
                self.ui.label_59.setText("目标IP")
                self.ui.lineEdit_3.setVisible(True)
                self.ui.showDialog.setEnabled(True)
                self.ui.pushButton_3.setText("连接服务器")
                if self.isSignalConnected(self.ui.pushButton_3, "clicked()"):
                    self.ui.pushButton_3.clicked.disconnect(self.createServer)
                self.ui.pushButton_3.clicked.connect(self.connectServer2)
        except Exception as e:
            print(e)

    def createServer(self):
        try:
            self.ui.pushButton_3.setEnabled(False)
            self.ui.pushButton_3.setText("正在开启监听...")
            ip = self.ui.lineEdit.text()    # 监听ip
            port = self.ui.lineEdit_2.text()    # 监听端口
            conn = self.ui.lineEdit_3.text()    # 连接数
            passwd = self.ui.lineEdit_4.text()  # 连接密码
            uname = self.ui.lineEdit_5.text()   # 连接用户名
            # 创建子进程
            self.createServerThread_ = CreateServer(ip, port, conn, passwd, uname, self.teamlogfile.format(GetTime.getSystemTime5()))
            # 将子进程中的信号与槽函数绑定
            self.createServerThread_.updateConnectSignal.connect(self.showSuccessDialog)
            self.createServerThread_.updateResult.connect(self.updateMessage)
            self.createServerThread_.updateTeamlog.connect(self.updateTeamLog)
            # 启动子进程
            self.createServerThread_.start()
        except Exception as e:
            print(e)

    def connectServer(self):
        try:
            self.ui.pushButton_3.setEnabled(False)
            self.ui.showDialog.setEnabled(False)
            self.ui.pushButton_3.setText("正在连接到服务器...")
            self.ui.showDialog.setText("正在连接到服务器...")
            serverip = self.d.lineEdit.text()
            port = self.d.lineEdit_2.text()
            passwd = self.d.lineEdit_3.text()
            uname = self.d.lineEdit_4.text()
            # 创建子进程
            self.connectServerThread_ = ConnectServer(serverip, port, passwd, uname, self.teamlogfile.format(GetTime.getSystemTime5()))
            # 将子进程中的信号与槽函数绑定
            self.connectServerThread_.updateConnectSignal.connect(self.showSuccessDialog)
            self.connectServerThread_.updateResult.connect(self.updateMessage)
            self.connectServerThread_.updateTeamlog.connect(self.updateTeamLog)
            # 启动子进程
            self.connectServerThread_.start()
        except Exception as e:
            print(e)

    def connectServer2(self):
        try:
            self.ui.pushButton_3.setEnabled(False)
            self.ui.showDialog.setEnabled(False)
            self.ui.pushButton_3.setText("正在连接到服务器...")
            self.ui.showDialog.setText("正在连接到服务器...")
            serverip = self.ui.lineEdit_3.text()
            port = self.ui.lineEdit_2.text()
            passwd = self.ui.lineEdit_4.text()
            uname = self.ui.lineEdit_5.text()
            # 创建子进程
            self.connectServerThread_ = ConnectServer(serverip, port, passwd, uname, self.teamlogfile.format(GetTime.getSystemTime5()))
            # 将子进程中的信号与槽函数绑定
            self.connectServerThread_.updateConnectSignal.connect(self.showSuccessDialog)
            self.connectServerThread_.updateResult.connect(self.updateMessage)
            self.connectServerThread_.updateTeamlog.connect(self.updateTeamLog)
            # 启动子进程
            self.connectServerThread_.start()
        except Exception as e:
            print(e)

    def breakNet(self):
        try:
            if self.ui.comboBox_13.currentIndex():
                self.ui.showDialog.setText("连接服务器")
                self.ui.pushButton_3.setText("开启监听")
                self.ui.showDialog.setEnabled(False)
                self.ui.pushButton_3.setEnabled(True)
                self.createServerThread_.stop('服务端')
            else:
                self.ui.showDialog.setText("连接服务器")
                self.ui.pushButton_3.setText("连接服务器")
                self.ui.pushButton_3.setEnabled(True)
                self.ui.showDialog.setEnabled(True)
                self.connectServerThread_.stop('客户端')
        except Exception as e:
            print(e)

    def sendMessage(self):
        try:
            message = self.ui.plainTextEdit.toPlainText()
            if self.ui.comboBox_13.currentIndex():
                self.createServerThread_.sendMessage(message)
            else:
                self.connectServerThread_.sendMessage(message)
        except Exception as e:
            print(e)

    def clearMessage(self):
        self.ui.textBrowser_2.clear()

    def showSuccessDialog(self, status, message):
        if status:
            QMessageBox.information(self.ui, '提示', message)
            self.ui.showDialog.setText("已连接服务器")
            self.ui.pushButton_3.setText("已连接服务器")
            # self.ui.showDialog.setEnabled(False)
        else:
            QMessageBox.information(self.ui, '提示', message)
            self.ui.showDialog.setText("连接服务器")
            self.ui.pushButton_3.setText("连接服务器")
            self.ui.pushButton_3.setEnabled(True)
            self.ui.showDialog.setEnabled(True)

    def updateMessage(self, flag, message):
        self.ui.textBrowser_2.append(message)
        self.ui.textBrowser_2.ensureCursorVisible()
        if flag:
            pass
        else:
            if self.ui.comboBox_13.currentIndex():
                self.ui.showDialog.setText("连接服务器")
                self.ui.pushButton_3.setText("开启监听")
                self.ui.showDialog.setEnabled(False)
                self.ui.pushButton_3.setEnabled(True)
            else:
                self.ui.showDialog.setText("连接服务器")
                self.ui.pushButton_3.setText("连接服务器")
                self.ui.pushButton_3.setEnabled(True)
                self.ui.showDialog.setEnabled(True)

    def updateTeamLog(self, message):
        self.ui.textBrowser_29.append(message)
        self.ui.textBrowser_29.ensureCursorVisible()
        try:
            if self.ui.comboBox_13.currentIndex():
                self.createServerThread_.saveTeamLog(message)
            else:
                self.connectServerThread_.saveTeamLog(message)
        except Exception as e:
            print(e)

    def isSignalConnected(self, obj, name):
        # 判断对象是否连接信号，obj - 对象名，name - 信号名（如 clicked）
        index = obj.metaObject().indexOfMethod(name)
        if index > -1:
            method = obj.metaObject().method(index)
            if method:
                return obj.isSignalConnected(method)
        return False

    ########################### 其他 ##################################

    def tableChanged(self, index, tabNo, moduleNo):
        # 检测窗口(table)变化，index值为窗口序号，tabNo为tableWidget序号，moduleNo指 tabNo对应的模块序号
        try:
            index2 = moduleNo
            if index == 2 or index == 3:
                index2 = 0
            else:
                submoduleName = list(self.moduleName.items())[index][1][moduleNo]
            print("当前在 {} 的 {} 模块。".format(list(self.moduleName.items())[index][0], submoduleName if index2 != 0 else "-"))
        except Exception as e:
            print(e)

    def setUA(self):
        # index = self.ui.comboBox_3.currentIndex()
        text = self.ui.plainTextEdit_7.toPlainText()
        if text:
            self.defaultUserAgent = text

    def setInfoCollectProxy(self):
        if self.ui.checkBox_23.isChecked():
            if self.ui.lineEdit_23.text():
                self.infoCollectProxy = self.ui.lineEdit_23.text()
        else:
            self.infoCollectProxy = ''

    def setInfoCollectEncode(self):
        try:
            index = self.ui.comboBox_3.currentIndex()
            self.infoCollectEncode = self.infoCollectEncodeList[index]
        except Exception as e:
            print(e)

    def updateLog(self):
        text = self.ui.plainTextEdit_13.toPlainText()
        # print(text)
        # self.ui.plainTextEdit_13.setPlainText(text)

    def memo(self):
        text = self.ui.plainTextEdit_12.toPlainText()
        # self.ui.plainTextEdit_12.setPlainText(text)

    # 传入表格对象，进行数据清除
    def clearContent(self, table):
        try:
            table.setRowCount(0)
        except Exception as e:
            print(e)

    # 初始化表格 header为表头，类型为list
    def initTable(self, table, header):
        try:
            # 表格不设置行数，并设置表头
            # table.setRowCount(0)
            table.setColumnCount(len(header))
            table.setHorizontalHeaderLabels(header)
            # 设置表格内容不允许编辑
            table.setEditTriggers(QAbstractItemView.NoEditTriggers)
            # 设置表格的自适应伸缩模式
            table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
            # 去除左侧的序号
            table.verticalHeader().setVisible(False)
            # 标题头加粗
            tableTitleFont = table.horizontalHeader().font()
            tableTitleFont.setBold(True)
            table.horizontalHeader().setFont(tableTitleFont)
        except Exception as e:
            print(e)

    def openDir(self):
        try:
            platformVersion = platform.system()
            if platformVersion == 'Windows':
                # os.startfile(filepath)
                os.system("start explorer %s" % os.getcwd())
            elif platformVersion == 'Linux':
                os.system("nautilus .")
            else:
                pass
        except Exception as e:
            print(e)

    def exitApp(self, event):
        try:
            reply = QMessageBox.question(None, '提示', '是否退出程序？', QMessageBox.Yes | QMessageBox.No)
            if reply == QMessageBox.Yes:
                # event.accept()
                app = QApplication.instance()
                app.quit()
            else:
                # event.ignore()
                pass
        except Exception as e:
            print(e)
            # pass

    # def setBurstDict(self):
    #     pass

    def clearCss(self):
        self.ui.setBackgroundWhite.setChecked(False)
        self.ui.setBackgroundBlack.setChecked(False)
        self.ui.clearCss.setChecked(True)
        self.ui.setStyleSheet("*{background-color:none;}")
        pass

    def setBackgroundWhite(self):
        self.ui.setBackgroundWhite.setChecked(True)
        self.ui.setBackgroundBlack.setChecked(False)
        self.ui.clearCss.setChecked(False)
        self.ui.setStyleSheet("*{background-color:rgb(86, 150, 182);}")
        print("white")

    def setBackgroundBlack(self):
        self.ui.setBackgroundWhite.setChecked(False)
        self.ui.setBackgroundBlack.setChecked(True)
        self.ui.clearCss.setChecked(False)
        self.ui.setStyleSheet("*{background-color:rgb(160, 160, 160);}")  # 43, 43, 43   # 80, 94, 100
        print("black")

    def showDialog(self):
        try:
            self.di = QDialog()
            self.d = connectDialog.Ui_Dialog()
            self.d.setupUi(self.di)
            self.di.show()
            self.d.buttonBox.accepted.connect(self.connectServer)
        except Exception as e:
            print(e)

    def about(self):
        try:
            reply = QMessageBox.about(None,'关于','本程序为Python辅助安全测试项目。')
            if reply == QMessageBox.Yes:
                # event.accept()
                app = QApplication.instance()
                app.quit()
            else:
                # event.ignore()
                pass
        except Exception as e:
            print(e)
            # pass

    def rebootApp(self):
        pass

if __name__ == "__main__":
    # Check py version
    pyVersion = sys.version.split()[0]
    if pyVersion <= "3":
        exit('需要python版本3.0以上！')
    app = QApplication(sys.argv)
    ss = Ss()
    ss.ui.show()
    sys.exit(app.exec_())
