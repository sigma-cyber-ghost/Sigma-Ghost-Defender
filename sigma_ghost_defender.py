import os
import sys
import webbrowser
from PyQt5.QtWidgets import (
    QApplication, QWidget, QPushButton, QVBoxLayout, QLabel,
    QFileDialog, QTextEdit, QHBoxLayout, QMessageBox, QDialog, QListWidget,
    QDialogButtonBox, QAbstractItemView
)
from PyQt5.QtGui import QFont, QTextCursor
from PyQt5.QtCore import Qt, QTimer

SIGNATURES = {
    "RAT": [b"socket.connect", b"com.rat", b"reverse_shell"],
    "BACKDOOR": [b"/dev/tcp/", b"bash -i", b"nohup"],
    "VIRUS": [b"mov eax", b"jmp", b"xor"],
    "MALWARE": [b"keylogger", b"chmod 777", b"rm -rf", b"wget http"]
}

BANNER_ASCII = r"""
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢀⡶⣿⣿⣿⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣾⣿⣿⣿⣿⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢺⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠈⠻⣿⣻⣿⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠿⠶⠾⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠷⢰⣆⢠⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣤⡄
⢀⠀⠙⢿⣿⣷⠀⣤⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣤⣼⠏⠁
⠈⠀⣧⠀⠛⢿⡿⢿⣿⣿⣶⣄⢠⠀⠀⠀⢀⡀⠀⠀⠀⠀⠀⠀⢀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣴⡶⠾⠞⠛⠋⢁⠀⠀
⠀⠀⠘⠁⠆⠀⠁⡀⠹⠟⣿⣿⡾⣷⠀⢀⣿⣷⠀⣠⣿⣷⣆⠀⢰⣿⣿⣷⠀⢠⣾⣇⠀⣼⠃⠰⡿⢹⠋⠀⠀⢠⢺⠀⡎⠀⠀
⠀⠀⠀⠀⠀⠈⠆⠀⢀⡀⠉⠈⠃⠈⠠⣾⣿⣿⢠⣿⣿⣿⣿⠂⢸⣿⣿⣿⣗⣻⣿⣿⡦⢿⡼⠇⠁⠀⠃⠀⡇⠘⠈⠀⠁⠀⠀
⠀⠀⠀⠀⠀⠀⠘⠀⠈⢷⠈⢷⠄⠀⠃⠙⠿⠏⣼⣿⣿⣿⣿⣦⣾⣿⢿⣿⣵⠟⠿⠛⠁⠈⢳⠐⠀⡠⢠⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢅⣸⡆⠀⠀⠀⢀⠀⠛⠿⠿⠛⠛⠋⠻⣿⣼⠻⠿⡀⢀⣤⣀⠀⣦⠀⠈⠃⠘⠁⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠀⠁⣆⠀⢀⣾⡆⢼⣷⣶⠀⣾⣵⢀⣿⣷⠀⣿⡇⢸⣿⣿⡀⢻⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠀⣾⠟⠁⣸⣿⡟⠘⣿⡟⢸⣿⡿⠀⢿⡇⠸⣿⡟⠇⠈⠛⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠀⠀⠙⠟⠁⠀⠉⠁⠈⠛⠇⠀⠀⠁⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
"""

HEADER_ASCII = r"""

   _____  _    _   ____    _____  _______             _   _  _______  _____     __      __ _____  _____   _    _   _____ 
  / ____|| |  | | / __ \  / ____||__   __|     /\    | \ | ||__   __||_   _|    \ \    / /|_   _||  __ \ | |  | | / ____|
 | |  __ | |__| || |  | || (___     | |       /  \   |  \| |   | |     | | ______\ \  / /   | |  | |__) || |  | || (___  
 | | |_ ||  __  || |  | | \___ \    | |      / /\ \  | . ` |   | |     | ||______|\ \/ /    | |  |  _  / | |  | | \___ \ 
 | |__| || |  | || |__| | ____) |   | |     / ____ \ | |\  |   | |    _| |_        \  /    _| |_ | | \ \ | |__| | ____) |
  \_____||_|  |_| \____/ |_____/    |_|    /_/    \_\|_| \_|   |_|   |_____|        \/    |_____||_|  \_\ \____/ |_____/ 
                                                                                                                         
                                                                                                                         

"""

LINKS = {
    "Twitter": "https://twitter.com/safderkhan0800_",
    "YouTube": "https://www.youtube.com/@sigma_ghost_hacking",
    "Telegram": "https://t.me/Sigma_Cyber_Ghost",
    "GitHub": "https://github.com/sigma-cyber-ghost"
}


def scan_file(path):
    try:
        with open(path, "rb") as f:
            data = f.read()
            for family, sigs in SIGNATURES.items():
                for sig in sigs:
                    if sig in data:
                        return (f"[INFECTED: {family}] {path}", family)
        return (f"[CLEAN] {path}", None)
    except Exception as e:
        return (f"[ERROR] {path}: {str(e)}", None)


def scan_directory(path):
    results = []
    for root, _, files in os.walk(path):
        for name in files:
            fpath = os.path.join(root, name)
            results.append(scan_file(fpath))
    return results


class ThreatDialog(QDialog):
    def __init__(self, threats, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Threats Detected")
        self.setFixedSize(600, 400)
        self.setStyleSheet("background-color: #111; color: #00ff66;")
        self.selected_option = None

        layout = QVBoxLayout()
        self.list_widget = QListWidget()
        self.list_widget.addItems(threats)
        self.list_widget.setSelectionMode(QAbstractItemView.NoSelection)
        self.list_widget.setStyleSheet("background-color: black; color: #00ff66;")
        layout.addWidget(self.list_widget)

        buttons = QDialogButtonBox()
        self.all_btn = QPushButton("Delete All")
        self.skip_btn = QPushButton("Skip All")
        self.manual_btn = QPushButton("Delete One-by-One")
        for btn in [self.all_btn, self.skip_btn, self.manual_btn]:
            btn.setStyleSheet("background-color: #222; color: #00ff66; padding: 6px;")
            buttons.addButton(btn, QDialogButtonBox.ActionRole)

        self.all_btn.clicked.connect(lambda: self.finish("all"))
        self.skip_btn.clicked.connect(lambda: self.finish("skip"))
        self.manual_btn.clicked.connect(lambda: self.finish("manual"))
        layout.addWidget(buttons)
        self.setLayout(layout)

    def finish(self, choice):
        self.selected_option = choice
        self.accept()


class SigmaGhost(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SIGMA GHOST DEFENDER")
        self.setFixedSize(1000, 720)
        self.setStyleSheet("background-color: black; color: #00ff66;")
        self.setFont(QFont("Courier New", 10))
        self.detected_files = []

        layout = QVBoxLayout()

        self.banner = QLabel(BANNER_ASCII)
        self.banner.setTextFormat(Qt.PlainText)
        self.banner.setAlignment(Qt.AlignCenter)
        self.banner.setFont(QFont("Courier New", 9))
        self.banner.setStyleSheet("color: #00ff66;")
        layout.addWidget(self.banner)

        self.header = QLabel(HEADER_ASCII)
        self.header.setTextFormat(Qt.PlainText)
        self.header.setAlignment(Qt.AlignCenter)
        self.header.setFont(QFont("Courier New", 10))
        self.header.setStyleSheet("color: #00ff66;")
        layout.addWidget(self.header)

        self.output = QTextEdit()
        self.output.setReadOnly(True)
        self.output.setStyleSheet("background-color: black; border: 1px solid #00ff66; color: #00ff66;")
        layout.addWidget(self.output)

        btns = QHBoxLayout()
        self.file_btn = QPushButton("Scan File")
        self.folder_btn = QPushButton("Scan Folder")
        self.file_btn.clicked.connect(self.scan_file_action)
        self.folder_btn.clicked.connect(self.scan_folder_action)
        for btn in (self.file_btn, self.folder_btn):
            btn.setStyleSheet("background-color: #111; color: #00ff66; padding: 5px 10px;")
            btns.addWidget(btn)
        layout.addLayout(btns)

        links = QHBoxLayout()
        for name, url in LINKS.items():
            link_btn = QPushButton(name)
            link_btn.setStyleSheet("background-color: #111; color: #00ff66;")
            link_btn.clicked.connect(lambda _, u=url: webbrowser.open(u))
            links.addWidget(link_btn)
        layout.addLayout(links)

        self.setLayout(layout)

        self.typing_text = ">> Sigma Ghost Defender Activated...\n"
        self.typing_index = 0
        self.timer = QTimer()
        self.timer.timeout.connect(self.animate_typing)
        self.timer.start(45)

    def animate_typing(self):
        if self.typing_index < len(self.typing_text):
            self.output.moveCursor(QTextCursor.End)
            self.output.insertPlainText(self.typing_text[self.typing_index])
            self.typing_index += 1
        else:
            self.timer.stop()

    def scan_file_action(self):
        self.detected_files = []
        path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if path:
            result, family = scan_file(path)
            self.output.append(result)
            if family:
                self.detected_files.append((path, family))
                self.handle_threats()

    def scan_folder_action(self):
        self.detected_files = []
        path = QFileDialog.getExistingDirectory(self, "Select Folder")
        if path:
            results = scan_directory(path)
            for res, family in results:
                self.output.append(res)
                if family:
                    self.detected_files.append((res.split("] ")[1], family))
            if self.detected_files:
                self.handle_threats()

    def handle_threats(self):
        threat_lines = [f"[{family}] {path}" for path, family in self.detected_files]
        dialog = ThreatDialog(threat_lines, self)
        if dialog.exec_():
            choice = dialog.selected_option
            if choice == "all":
                for path, family in self.detected_files:
                    try:
                        os.remove(path)
                        self.output.append(f"[DELETED] {path}")
                    except Exception as e:
                        self.output.append(f"[ERROR] {path}: {e}")
            elif choice == "manual":
                for path, family in self.detected_files:
                    confirm = QMessageBox.question(
                        self,
                        "Delete?",
                        f"[{family}] {path}\nDelete this file?",
                        QMessageBox.Yes | QMessageBox.No
                    )
                    if confirm == QMessageBox.Yes:
                        try:
                            os.remove(path)
                            self.output.append(f"[DELETED] {path}")
                        except Exception as e:
                            self.output.append(f"[ERROR] {path}: {e}")
            else:
                self.output.append("Skipped all infected files.")


def run_app():
    os.environ["XDG_RUNTIME_DIR"] = "/tmp/runtime-root"
    app = QApplication(sys.argv)
    window = SigmaGhost()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    run_app()
