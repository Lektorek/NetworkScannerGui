#-*- coding: utf-8 -*-
import sys
from PyQt4 import QtGui
from PyQt4 import *
from PyQt4.QtGui import *
import nmap

class Example(QtGui.QWidget):

	def __init__(self):
		super(Example, self).__init__()

		self.initUi()

	def initUi(self):

		self.setGeometry(400, 250, 430, 460)
		self.setWindowTitle('Network scanner')
		self.setWindowIcon(QtGui.QIcon('web.png'))
		
                self.output = QTextEdit(self)
		self.output.setReadOnly(True)
		self.output.move(15, 15)
		self.output.resize(400, 400)
		self.output.setLineWrapMode(QTextEdit.NoWrap)
		self.output.setText("Działa!".decode("utf-8"))
		#print("Działa!")

		scan = QPushButton(self)
		scan.setText("Scan")
		scan.move(50, 420)
		scan.clicked.connect(self.scan)
		
                quit = QPushButton(self)
                quit.setText("Quit")
                quit.move(300, 420)
		quit.clicked.connect(self.quit)

		self.show()
	def quit(self):
		QtCore.QCoreApplication.instance().quit()

	def scan(self):
		nm = nmap.PortScanner()
		nm.scan('192.168.0.248/24');
		result = '';
		for host in nm.all_hosts():
			result += 'Host: %s (%s)\n' % (host,nm[host].hostname())
			result += 'State: %s\n' % (nm[host].state())
			for proto in nm[host].all_protocols():
				#result += '----------\n'
				result += 'Protocol : %s\n' % (proto)
				lport = nm[host][proto].keys()
				lport.sort()
				for port in lport:
					result += 'port : %s\tstate : %s\n' % (port, nm[host][proto][port]['state'])
			result += '----------\n'
		self.output.setText(result.decode('utf-8'))

def main():

	app = QtGui.QApplication(sys.argv)
	ex = Example()
	sys.exit(app.exec_())


if __name__ == '__main__':
	main()
