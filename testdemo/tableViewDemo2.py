from PyQt5.QtWidgets import *
from PyQt5.QtGui import *


class TableDemo(QWidget):

    def __init__(self, rows, cols, title):
        super(TableDemo, self).__init__()
        self.rows = rows
        self.cols = cols
        self.title = title
        self.model = QStandardItemModel(self.rows, self.cols)
        self.model.setHorizontalHeaderLabels(self.title)
        self.item = QStandardItem("row %s, column %s" % (self.rows, self.cols))

        # for row in range(4):
        #     for column in range(4):
        #         item = QStandardItem("row %s, column %s" % (row, column))
        #         self.model.setItem(row, column, item)

        # self.tableView = QTableView()
        # self.tableView.setModel(self.model)

    def setRowContent(self):
        item = QStandardItem("row %s, column %s" % (self.rows, self.cols))

        # 表格QTableView控件，使用setModel来绑定数据源
        # self.domainResultTable = self.ui.domainScanResult
        # self.domainResultTable.setModel(TableDemo(1, 3, ['序号', '子域名', 'IP']).model)
        # 水平方向标签拓展剩下的窗口部分，填满表格
        # self.domainResultTable.horizontalHeader().setStretchLastSection(True)
        # 水平方向，表格大小拓展到适当的尺寸
        # self.domainResultTable.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        # rowNum = self.domainResultTable.rowCount()
        # colNum = self.domainResultTable.columnCount()
        # print(rowNum, colNum)
