import sys

from PySide2 import QtWidgets
from PySide2.QtUiTools import QUiLoader
from PySide2.QtWidgets import QApplication, QAction, QTextBrowser, QTextEdit, QCheckBox, QComboBox, QTableWidget, \
    QPushButton
from PySide2.QtCore import QFile, QObject, QDir
from scapy.all import *
from Analyser import Analyser


class TextWindow(QObject):
    def __init__(self, ui_file, analyser,parent=None):
        super(TextWindow, self).__init__(parent)
        ui_file = QFile(ui_file)
        ui_file.open(QFile.ReadOnly)
        loader = QUiLoader()
        self.window = loader.load(ui_file)
        ui_file.close()
        self.window.show()
        self.textEdit = self.window.findChild(QTextEdit, 'textEdit')
        self.textEdit.setText(analyser.get_hex(True, True, True, True, True, True, True))

class App(QObject):
    analyser = None

    def __init__(self, ui_file, parent=None):
        super(App, self).__init__(parent)
        ui_file = QFile(ui_file)
        ui_file.open(QFile.ReadOnly)

        loader = QUiLoader()
        self.window = loader.load(ui_file)
        ui_file.close()

        self.btn = self.window.findChild(QAction, 'actionOpen')
        self.btn.triggered.connect(self.openFileMenu)


        self.chckMac = self.window.findChild(QCheckBox, 'checkBox')
        self.chckLOne = self.window.findChild(QCheckBox, 'checkBox_2')
        self.chckLTwo = self.window.findChild(QCheckBox, 'checkBox_3')
        self.chckIP = self.window.findChild(QCheckBox, 'checkBox_4')
        self.chckLThree = self.window.findChild(QCheckBox, 'checkBox_5')
        self.chckLFour = self.window.findChild(QCheckBox, 'checkBox_6')
        self.chckPORTS = self.window.findChild(QCheckBox, 'checkBox_7')
        self.table = self.window.findChild(QTableWidget, 'tableWidget')
        self.table.setSelectionBehavior(QTableWidget.SelectRows);
        self.textEdit = self.window.findChild(QTextEdit, 'textEdit')
        self.allIPButton = self.window.findChild(QPushButton, 'pushButton')
        self.arp_filter = self.window.findChild(QPushButton, "pushButton_2")
        self.tcp_filter = self.window.findChild(QPushButton, "pushButton_3")
        self.tftp_filter = self.window.findChild(QPushButton, "pushButton_4")
        self.all_filter = self.window.findChild(QPushButton, "pushButton_5")
        self.icmp_filter = self.window.findChild(QPushButton, "pushButton_6")
        self.text_view = self.window.findChild(QPushButton, "pushButton_7")

        self.text_view.clicked.connect(self.open_text_view)
        self.icmp_filter.clicked.connect(self.filter_icmp)
        self.all_filter.clicked.connect(self.filter_all)
        self.tftp_filter.clicked.connect(self.filter_tftp)
        self.arp_filter.clicked.connect(self.filter_arp)
        self.tcp_filter.clicked.connect(self.filter_tcp)
        self.table.itemSelectionChanged.connect(self.onTableChange)
        self.chckMac.stateChanged.connect(self.onStateChangeMac)
        self.chckLOne.stateChanged.connect(self.onStateChangeLOne)
        self.chckLTwo.stateChanged.connect(self.onStateChangeLTwo)
        self.chckIP.stateChanged.connect(self.onStateChangeIP)
        self.chckLThree.stateChanged.connect(self.onStateChangeLThree)
        self.chckLFour.stateChanged.connect(self.onStateChangeLFour)
        self.chckPORTS.stateChanged.connect(self.onStateChangePorts)
        self.allIPButton.clicked.connect(self.showAllIPs)
        self.table.setColumnWidth(0, 15);
        self.window.show()
        self.showMac = False
        self.showLOne = False
        self.showLTwo = False
        self.showIP = False
        self.showLThree = False
        self.showLFour = False
        self.showPorts = False

    def open_text_view(self):
        self.app_2 = TextWindow('Text_window.ui', analyser=self.analyser)

    def filter_icmp(self):
        self.analyser.filter_icmp(self.table, True)
    def filter_all(self):
        self.analyser.sort_communicastions(self.table)

    def filter_tftp(self):
        self.analyser.filter_tftp(self.table, True)

    def filter_tcp(self):
        self.analyser.filter_tcp(self.table, True)

    def filter_arp(self):
        self.analyser.filter_arp(self.table, True)

    def showAllIPs(self):
        self.textEdit.setText(self.analyser.get_IPs())

    def onTableChange(self):
        self.textEdit.setText(self.analyser.get_info(int(self.table.selectedItems()[0].text()), self.showMac, self.showLOne, self.showLTwo, self.showLThree, self.showLFour, self.showIP, self.showPorts))

    def openFileMenu(self):
        fileName = QtWidgets.QFileDialog().getOpenFileName(None, 'Output directory', QDir.currentPath(), "pcap(*.pcap)");
        self.window.setWindowTitle(fileName[0])
        self.analyser = Analyser(rdpcap(fileName[0]))
        #self.textEdit.append(str(self.file.res))
        self.analyser.populate(self.table)
        #self.textEdit.append(self.analyser.get_hex(self.showMac, self.showLOne, self.showLTwo, self.showLThree, self.showLFour, self.showIP, self.showPorts))

    def onStateChangeMac(self):
        if self.chckMac.isChecked():
            self.showMac = True
        else:
            self.showMac = False

        self.textEdit.setText(self.analyser.get_info(self.table.selectedItems()[0].row(), self.showMac, self.showLOne, self.showLTwo, self.showLThree, self.showLFour, self.showIP, self.showPorts))

    def onStateChangeLOne(self):
        if self.chckLOne.isChecked():
            self.showLOne = True
        else:
            self.showLOne = False
        self.textEdit.setText(self.analyser.get_info(self.table.selectedItems()[0].row(), self.showMac, self.showLOne, self.showLTwo, self.showLThree, self.showLFour, self.showIP, self.showPorts))

    def onStateChangeLTwo(self):
        if self.chckLTwo.isChecked():
            self.showLTwo = True
        else:
            self.showLTwo = False
        self.textEdit.setText(self.analyser.get_info(self.table.selectedItems()[0].row(), self.showMac, self.showLOne, self.showLTwo, self.showLThree, self.showLFour, self.showIP, self.showPorts))

    def onStateChangeIP(self):
        if self.chckIP.isChecked():
            self.showIP = True
        else:
            self.showIP = False
        self.textEdit.setText(self.analyser.get_info(self.table.selectedItems()[0].row(), self.showMac, self.showLOne, self.showLTwo, self.showLThree, self.showLFour, self.showIP, self.showPorts))

    def onStateChangeLThree(self):
        if self.chckLThree.isChecked():
            self.showLThree = True
        else:
            self.showLThree = False
        self.textEdit.setText(self.analyser.get_info(self.table.selectedItems()[0].row(), self.showMac, self.showLOne, self.showLTwo, self.showLThree, self.showLFour, self.showIP, self.showPorts))

    def onStateChangeLFour(self):
        if self.chckLFour.isChecked():
            self.showLFour = True
        else:
            self.showLFour = False
        self.textEdit.setText(self.analyser.get_info(self.table.selectedItems()[0].row(), self.showMac, self.showLOne, self.showLTwo, self.showLThree, self.showLFour, self.showIP, self.showPorts))

    def onStateChangePorts(self):
        if self.chckPORTS.isChecked():
            self.showPorts = True
        else:
            self.showPorts = False
        self.textEdit.setText(self.analyser.get_info(self.table.selectedItems()[0].row(), self.showMac, self.showLOne, self.showLTwo, self.showLThree, self.showLFour, self.showIP, self.showPorts))
if __name__ == '__main__':
    app = QApplication(sys.argv)
    mainApp = App('App.ui')
    sys.exit(app.exec_())