"""
Tasarım II
----------
Buse SAVCI
1611012017
Suleyman Demirel University

"""
import subprocess as sub
from pyptables import default_tables, restore
from pyptables.rules import Rule, Accept, Reject, Drop
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5 import QtCore, QtGui

button_sayac = 0
sayac = 0
# get a default set of tables and chains
tables = default_tables()


forward = tables['filter']['FORWARD']
input = tables['filter']['INPUT']
output: object = tables['filter']['OUTPUT']

# any packet matching an established connection should be allowed
forward.append(Accept(match='conntrack', ctstate='ESTABLISHED'))
input.append(Accept(match='conntrack', ctstate='ESTABLISHED'))
output.append(Accept(match='conntrack', ctstate='ESTABLISHED'))

# kurallara uymayan paketleri drop et
forward.policy = Rule.DROP

# default koruma
forward.append(Accept(proto='tcp', dport='53'))
forward.append(Accept(proto='tcp', dport='80'))
forward.append(Accept(proto='tcp', dport='443'))


drop_ddos = Rule(proto='tcp', dport='80', m='limit', limit='25/minute', limit_burst='100', j='ACCEPT',
                 comment='Save you from DDos :)')
input.append(drop_ddos)
restore(tables)


# iptables durumunu görüntüleme
p = sub.Popen(('iptables', '-L', '-v', '-n'), stdout=sub.PIPE)
terminal_output, errors = p.communicate()
terminal_output = str(terminal_output, 'UTF-8')
terminal_output.split("/n")

# |------------------------  Özel CheckBox Sınıfımız  -------------------------|
class MyCheckBox(QCheckBox):

    def __init__(self, *args, **kwargs):
        QCheckBox.__init__(self, *args, **kwargs)
        self.setStyleSheet("background-color: rgb(0, 0, 0); color: rgb(255, 255, 255);")
        # set default check as True
        self.setChecked(True)
        # set default enable as True
        #    if it set to false will always remain on/off
        #    here it is on as setChecked is True
        self.setEnabled(True)
        self._enable = True

    #   mousePressEvent
    def mousePressEvent(self, *args, **kwargs):
        # tick on and off set here
        if self.isChecked():
            self.setChecked(False)
        else:
            self.setChecked(True)
        return QCheckBox.mousePressEvent(self, *args, **kwargs)

    # paintEvent
    def paintEvent(self, event):

        # just setting some size aspects
        self.setMaximumHeight(30)
        self.setMaximumWidth(100)
        self.setMinimumWidth(100)
        self.setMaximumHeight(30)

        self.resize(self.parent().width(), self.parent().height())
        painter = QtGui.QPainter()
        painter.begin(self)

        # for the black background
        brush = QtGui.QBrush(QtGui.QColor(20, 20, 20), style=QtCore.Qt.SolidPattern)
        painter.fillRect(self.rect(), brush)

        # smooth curves
        painter.setRenderHint(QtGui.QPainter.Antialiasing)

        # for the on off font
        font = QtGui.QFont()
        font.setFamily("Courier New")
        font.setPixelSize(12)
        painter.setFont(font)

        # change the look for on/off
        if self.isChecked():
            # blue fill
            brush = QtGui.QBrush(QtGui.QColor(50, 50, 255), style=QtCore.Qt.SolidPattern)
            painter.setBrush(brush)

            # rounded rectangle as a whole
            painter.drawRoundedRect(0, 0, self.width() - 2, self.height() - 2, self.height() / 2, self.height() / 2)

            # white circle/button instead of the tick mark
            brush = QtGui.QBrush(QtGui.QColor(255, 255, 255), style=QtCore.Qt.SolidPattern)
            painter.setBrush(brush)
            painter.drawEllipse(self.width() - self.height(), 0, self.height(), self.height())

            # on text
            painter.drawText(self.width() / 4, self.height() / 1.5, "Açık")

            forward.clear()
            input.clear()
            output.clear()
            # genel kurallar

            forward.append(Accept(proto='tcp', dport='53'))
            forward.append(Accept(proto='tcp', dport='80'))
            forward.append(Accept(proto='tcp', dport='443'))

            drop_ddos = Rule(proto='tcp', dport='80', m='limit', limit='25/minute', limit_burst='100', j='ACCEPT',
                             comment='Save you from DDos :)')
            input.append(drop_ddos)
            restore(tables)


        else:
            # gray fill
            brush = QtGui.QBrush(QtGui.QColor(50, 50, 50), style=QtCore.Qt.SolidPattern)
            painter.setBrush(brush)

            # rounded rectangle as a whole
            painter.drawRoundedRect(0, 0, self.width() - 2, self.height() - 2, self.height() / 2, self.height() / 2)

            # white circle/button instead of the tick but in different location
            brush = QtGui.QBrush(QtGui.QColor(255, 255, 255), style=QtCore.Qt.SolidPattern)
            painter.setBrush(brush)
            painter.drawEllipse(0, 0, self.height(), self.height())

            # off text
            painter.drawText(self.width() / 2, self.height() / 1.5, "Kapalı")
            sub.call('iptables -F > /dev/null', shell=True)


# |----------------------------   FireWall Widget    ---------------------------------|
class FireWallWidget(QWidget):

    def __init__(self):
        # super(first_GUI, self).__init__()
        # super().__init__()
        QWidget.__init__(self)
        self.setStyleSheet("background-color: rgb(20, 20, 20);")

        # |----------------------------  Nesne tanımları  ----------------------------|

        # genel koruma tanımları
        self.genel_koruma_label = QLabel("Genel Koruma")
        self.genel_koruma_label.setAlignment(Qt.AlignLeft)
        self.genel_koruma_label.setStyleSheet("color: rgb(255,255,255);font-weight: bold; font-size: 16pt")
        genel_koruma = MyCheckBox()
        genel_koruma.setStyleSheet("margin-bottom: 10px;")
        genel_koruma.setCheckState(True)
        genel_koruma.stateChanged.connect(self.kuralEkle)
        kuralSil = QPushButton("Kuralları Sil", self)
        kuralSil.setMinimumHeight(30)
        kuralSil.clicked.connect(self.kuralSil)

        # ek seçenek tanımları
        self.özel_koruma_label = QLabel("Ek Seçenekler")
        self.özel_koruma_label.setAlignment(Qt.AlignLeft)
        self.özel_koruma_label.setStyleSheet("color: rgb(255,255,255);font-weight: bold; font-size: 16pt")

        # port
        self.port = QLineEdit()
        self.port.setText("0")
        self.port_button = QPushButton()
        self.port_button.setObjectName("connect")
        self.port_button.setText("Portu Kapat")
        self.port_button.clicked.connect(self.port_kapa)
        self.port_button_ac = QPushButton("Portu Aç")
        self.port_button_ac.clicked.connect(self.port_ac)
        # data tanımları
        yenile_button = QPushButton("Yenile")
        yenile_button.clicked.connect(self.yenile)
        self.textBox_1 = QPlainTextEdit(terminal_output)
        self.textBox_1.setMinimumHeight(30)
        copyright = QLabel("Copyright © 2020 Buse SAVCI")
        copyright.setStyleSheet("color: rgb(255,255,255); font-size: 8pt")

        # |-----------------------------------  layout'umuz  --------------------------------------|
        vertical_layout = QGridLayout()
        vertical_layout.setSpacing(10)

        # genel koruma kısmı
        vertical_layout.addWidget(self.genel_koruma_label, 0, 0)
        vertical_layout.addWidget(genel_koruma, 1, 0)
        vertical_layout.addWidget(kuralSil, 1, 1)

        # özel koruma kısmı
        vertical_layout.addWidget(self.özel_koruma_label, 2, 0)

        vertical_layout.addWidget(self.port, 4, 0)
        vertical_layout.addWidget(self.port_button, 4, 1)
        vertical_layout.addWidget(self.port_button_ac, 4, 2)

        # data kısmı
        vertical_layout.addWidget(yenile_button, 6, 0, 1, 6)
        vertical_layout.addWidget(self.textBox_1, 7, 0, 1, 7)
        vertical_layout.addWidget(copyright)

        self.setLayout(vertical_layout)
        self.setWindowTitle("iPyTables Firewall")
        self.resize(800, 600)

    def port_kapa(self):
        deger = self.port.text()
        input.append(Reject(proto='tcp', dport=deger))
        output.append(Reject(proto='tcp', dport=deger))
        restore(tables)
        self.yenile()

    def port_ac(self):
        deger = self.port.text()
        try:
            forward.remove(Reject(proto='tcp', dport=deger))
            input.remove(Reject(proto='tcp', dport=deger))
            output.remove(Reject(proto='tcp', dport=deger))
            restore(tables)
            self.yenile()
        except:
            msg = QMessageBox()
            msg.setText("Port Açıldı")
            msg.exec()
            self.yenile()


    def kuralSil(self):
        sub.call('iptables -F', shell=True)
        forward.clear()
        input.clear()
        output.clear()
        restore(tables)
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Information)
        msg.setText("Tüm Koruma Kuralları Silindi.")
        msg.setInformativeText("Güvende kalmak için korumayı açmayı unutmayın.")
        msg.setWindowTitle("Kurallar Silindi!")
        msg.exec()
        self.yenile()


    def yenile(self):
        p = sub.Popen(('iptables', '-L', '-v', '-n'), stdout=sub.PIPE)
        terminal_output, errors = p.communicate()
        terminal_output = str(terminal_output, 'UTF-8')
        terminal_output.split("/n")
        restore(tables)
        self.textBox_1.setPlainText(terminal_output)


    def kuralEkle(self):
        # genel kurallar
        forward.clear()
        input.clear()
        output.clear()

        forward.append(Accept(proto='tcp', dport='53'))
        forward.append(Accept(proto='tcp', dport='80'))
        forward.append(Accept(proto='tcp', dport='443'))


        drop_ddos = Rule(proto='tcp', dport='80', m='limit', limit='25/minute', limit_burst='100', j='ACCEPT',
                         comment='Save you from DDos :)')
        input.append(drop_ddos)
        restore(tables)
        self.yenile()
        forward.clear()
        input.clear()
        output.clear()


if __name__ == "__main__":
    app = QApplication([])
    widget = FireWallWidget()
    widget.show()
    app.exec_()

# try:
#     p = sub.Popen(('sudo', 'tcpdump', '-l'), stdout=sub.PIPE)
#     for row in iter(p.stdout.readline, 'b'):
#         sayac = sayac + 1
#         print(row.rstrip())  # process here
#         bir = row.rstrip()
#         if sayac % 30 == 0:
#             sub.call('iptables -L -v -n', shell=True)
#             iki = sub.call('iptables -L -v -n', shell=True)
#             print(100 * "_")
#
#
# finally:
#     print("\nFirewall kapatılıyor. Teşekkür ederiz.")
#     print("*" * 50)
#     sub.call('iptables -F', shell=True)


