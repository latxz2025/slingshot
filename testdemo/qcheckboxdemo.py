import sys
from PyQt5.QtWidgets import QApplication, QWidget, QCheckBox, QLabel, QHBoxLayout


class Example(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.resize(250, 155)
        self.setWindowTitle('title')

        self.check_1 = QCheckBox('A', self)
        self.check_1.stateChanged.connect(self.choose)
        self.check_2 = QCheckBox('B', self)
        self.check_2.move(0, 20)
        self.check_2.stateChanged.connect(self.choose)
        self.check_3 = QCheckBox('C', self)
        self.check_3.move(0, 40)
        self.check_3.stateChanged.connect(self.choose)

        self.title = QLabel('Your choice:', self)
        self.content = QLabel(self)

        self.hbox = QHBoxLayout()
        self.hbox.addWidget(self.title)
        self.hbox.addWidget(self.content)
        self.setLayout(self.hbox)

        self.show()

    def choose(self):
        choice_1 = self.check_1.text() if self.check_1.isChecked() else ''
        choice_2 = self.check_2.text() if self.check_2.isChecked() else ''
        choice_3 = self.check_3.text() if self.check_3.isChecked() else ''
        self.content.setText(choice_1 + choice_2 + choice_3)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    ex = Example()
    sys.exit(app.exec_())