import sys

from PySide2 import QtWidgets
from PySide2.QtUiTools import QUiLoader
from PySide2.QtWidgets import QApplication, QAction, QTextBrowser, QTextEdit, QCheckBox, QComboBox
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

        self.combo = self.window.findChild(QComboBox, 'comboBox')

        self.chckMac = self.window.findChild(QCheckBox, 'checkBox')
        self.chckLOne = self.window.findChild(QCheckBox, 'checkBox_2')
        self.chckLTwo = self.window.findChild(QCheckBox, 'checkBox_3')
        self.chckIP = self.window.findChild(QCheckBox, 'checkBox_4')
        self.chckLThree = self.window.findChild(QCheckBox, 'checkBox_5')
        self.chckLFour = self.window.findChild(QCheckBox, 'checkBox_6')
        self.chckPORTS = self.window.findChild(QCheckBox, 'checkBox_7')

        self.textEdit = self.window.findChild(QTextEdit, 'textEdit')

        self.chckMac.stateChanged.connect(self.onStateChangeMac)
        self.chckLOne.stateChanged.connect(self.onStateChangeLOne)
        self.chckLTwo.stateChanged.connect(self.onStateChangeLTwo)
        self.chckIP.stateChanged.connect(self.onStateChangeIP)
        self.chckLThree.stateChanged.connect(self.onStateChangeLThree)
        self.chckLFour.stateChanged.connect(self.onStateChangeLFour)
        self.chckPORTS.stateChanged.connect(self.onStateChangePorts)

        self.combo.activated.connect(self.comboSelect)
        self.window.show()
        self.showMac = False
        self.showLOne = False
        self.showLTwo = False
        self.showIP = False
        self.showLThree = False
        self.showLFour = False
        self.showPorts = False

    def openFileMenu(self):
        fileName = QtWidgets.QFileDialog().getOpenFileName(None, 'Output directory', QDir.currentPath(), "pcap(*.pcap)");
        self.analyser = Analyser(rdpcap(fileName[0]))
        #self.textEdit.append(str(self.file.res))
        self.textEdit.append(self.analyser.get_hex(self.showMac, self.showLOne, self.showLTwo, self.showLThree, self.showLFour, self.showIP, self.showPorts))

    def comboSelect(self, sel):
        self.chckLOne.setChecked(True)
        self.chckLTwo.setChecked(True)
        self.chckMac.setChecked(True)

    def onStateChangeMac(self):
        if self.chckMac.isChecked():
            self.showMac = True
        else:
            self.showMac = False

        self.textEdit.setText(self.analyser.get_hex(self.showMac, self.showLOne, self.showLTwo, self.showLThree, self.showLFour, self.showIP, self.showPorts))

    def onStateChangeLOne(self):
        if self.chckLOne.isChecked():
            self.showLOne = True
        else:
            self.showLOne = False
        self.textEdit.setText(self.analyser.get_hex(self.showMac, self.showLOne, self.showLTwo, self.showLThree, self.showLFour, self.showIP, self.showPorts))

    def onStateChangeLTwo(self):
        if self.chckLTwo.isChecked():
            self.showLTwo = True
        else:
            self.showLTwo = False
        self.textEdit.setText(self.analyser.get_hex(self.showMac, self.showLOne, self.showLTwo, self.showLThree, self.showLFour, self.showIP, self.showPorts))

    def onStateChangeIP(self):
        if self.chckIP.isChecked():
            self.showIP = True
        else:
            self.showIP = False
        self.textEdit.setText(self.analyser.get_hex(self.showMac, self.showLOne, self.showLTwo, self.showLThree, self.showLFour, self.showIP, self.showPorts))

    def onStateChangeLThree(self):
        if self.chckLThree.isChecked():
            self.showLThree = True
        else:
            self.showLThree = False
        self.textEdit.setText(self.analyser.get_hex(self.showMac, self.showLOne, self.showLTwo, self.showLThree, self.showLFour, self.showIP, self.showPorts))

    def onStateChangeLFour(self):
        if self.chckLFour.isChecked():
            self.showLFour = True
        else:
            self.showLFour = False
        self.textEdit.setText(self.analyser.get_hex(self.showMac, self.showLOne, self.showLTwo, self.showLThree, self.showLFour, self.showIP, self.showPorts))

    def onStateChangePorts(self):
        if self.chckPORTS.isChecked():
            self.showPorts = True
        else:
            self.showPorts = False
        self.textEdit.setText(self.analyser.get_hex(self.showMac, self.showLOne, self.showLTwo, self.showLThree, self.showLFour, self.showIP, self.showPorts))
if __name__ == '__main__':
    app = QApplication(sys.argv)
    mainApp = App('App.ui')
    sys.exit(app.exec_())