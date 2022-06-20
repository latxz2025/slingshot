from PyQt5.QtWidgets import *
from PyQt5.QtGui import *


class SetTable(QWidget):

    def __init__(self, rows, cols, title):
        super(SetTable, self).__init__()
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

    # def setNewContent(self):
    #     item = QStandardItem("row %s, column %s" % (self.rows, self.cols))

