import time
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QDateTime


# 创建一个子线程
class UpdateThread(QThread):
    # 创建一个信号，触发时传递当前时间给槽函数
    update_data = pyqtSignal(str)

    def run(self):
        # 无限循环，每秒钟传递一次时间给UI
        while True:
            data = QDateTime.currentDateTime()
            currentTime = data.toString("yyyy-MM-dd hh:mm:ss")
            self.update_data.emit(str(currentTime))
            time.sleep(1)
