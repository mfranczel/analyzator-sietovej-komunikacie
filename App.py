import sys

from PySide2 import QtWidgets
from PySide2.QtUiTools import QUiLoader
from PySide2.QtWidgets import QApplication, QAction, QTextBrowser, QTextEdit
from PySide2.QtCore import QFile, QObject, QDir
from scapy.all import *
from Analyser import Analyser


class App(QObject):

    def __init__(self, ui_file, parent=None):
        super(App, self).__init__(parent)
        ui_file = QFile(ui_file)
        ui_file.open(QFile.ReadOnly)

        loader = QUiLoader()
        self.window = loader.load(ui_file)
        ui_file.close()

        self.btn = self.window.findChild(QAction, 'actionOpen')
        self.btn.triggered.connect(self.openFileMenu)

        self.textEdit = self.window.findChild(QTextEdit, 'textEdit')

        self.window.show()

    def openFileMenu(self):
        fileName = QtWidgets.QFileDialog().getOpenFileName(None, 'Output directory', QDir.currentPath(), "pcap(*.pcap)");
        self.analyser = Analyser(rdpcap(fileName[0]))
        #self.textEdit.append(str(self.file.res))
        self.textEdit.append(self.analyser.get_hex())



if __name__ == '__main__':
    app = QApplication(sys.argv)
    mainApp = App('App.ui')
    sys.exit(app.exec_())