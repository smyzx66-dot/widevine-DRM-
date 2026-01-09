import sys
from ui import WidevineUI
from PyQt6.QtWidgets import QApplication

def main():
    app = QApplication(sys.argv)
    window = WidevineUI()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()