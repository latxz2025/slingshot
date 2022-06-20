import socket
from PyQt5.QtCore import Qt, QThread, pyqtSignal

# 使用socket模块将域名转换为对应的ip地址，域名不带协议前缀，否则解析失败。
class parseDomainToIp(QThread):
    def __init__(self, domain):
        super(parseDomainToIp, self).__init__()
        self.domain = domain

    signal = pyqtSignal(str)

    def run(self):
        try:
            ip = socket.gethostbyname(domain)
            self.signal.emit(ip)
        except:
            self.signal.emit(' ')
            print(domain + "解析失败")
