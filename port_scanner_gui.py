import sys
import threading
from typing import List

from PyQt6.QtCore import Qt, QAbstractTableModel, QModelIndex, pyqtSignal, QObject
from PyQt6.QtWidgets import (
    QApplication,
    QCheckBox,
    QGridLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QTableView,
    QVBoxLayout,
    QWidget,
    QFileDialog,
    QHBoxLayout,
    QProgressBar,
)

from port_scanner_core import parse_ports, resolve_target, scan_ports, ScanResult


class ScanTableModel(QAbstractTableModel):
    HEADERS = ["Port", "Status", "Service", "Banner"]

    def __init__(self, results: List[ScanResult] = None):
        super().__init__()
        self.results = results or []

    def rowCount(self, parent=QModelIndex()):
        return len(self.results)

    def columnCount(self, parent=QModelIndex()):
        return len(self.HEADERS)

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid() or role != Qt.ItemDataRole.DisplayRole:
            return None
        result = self.results[index.row()]
        col = index.column()
        if col == 0:
            return str(result.port)
        elif col == 1:
            return result.status
        elif col == 2:
            return result.service or ""
        elif col == 3:
            return result.banner or ""
        return None

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return self.HEADERS[section]
        return super().headerData(section, orientation, role)

    def update_results(self, results: List[ScanResult]):
        self.beginResetModel()
        self.results = results
        self.endResetModel()


class WorkerSignals(QObject):
    finished = pyqtSignal(list)
    error = pyqtSignal(str)


class ScanWorker(threading.Thread):
    def __init__(self, ip, ports, timeout, workers, grab_banner):
        super().__init__()
        self.ip = ip
        self.ports = ports
        self.timeout = timeout
        self.workers = workers
        self.grab_banner = grab_banner
        self.signals = WorkerSignals()

    def run(self):
        try:
            results = scan_ports(
                ip=self.ip,
                ports=self.ports,
                timeout=self.timeout,
                workers=self.workers,
                grab_banner=self.grab_banner,
            )
            self.signals.finished.emit(results)
        except Exception as e:
            self.signals.error.emit(str(e))


class PortScannerApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Techie Modern Port Scanner")
        self.resize(900, 600)
        self._setup_ui()
        self.scan_worker = None

    def _setup_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout()
        central.setLayout(layout)

        grid = QGridLayout()
        layout.addLayout(grid)

        grid.addWidget(QLabel("Target (hostname or IP):"), 0, 0)
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("e.g. scanme.nmap.org")
        grid.addWidget(self.target_input, 0, 1)

        grid.addWidget(QLabel("Ports (e.g. 22,80,443 or 1-1024):"), 1, 0)
        self.ports_input = QLineEdit()
        self.ports_input.setPlaceholderText("Leave empty to use top ports or default")
        grid.addWidget(self.ports_input, 1, 1)

        grid.addWidget(QLabel("Top N common ports:"), 2, 0)
        self.top_spin = QSpinBox()
        self.top_spin.setRange(0, 1000)
        self.top_spin.setValue(0)
        grid.addWidget(self.top_spin, 2, 1)

        grid.addWidget(QLabel("Timeout (seconds):"), 3, 0)
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(1, 10)
        self.timeout_spin.setValue(1)
        grid.addWidget(self.timeout_spin, 3, 1)

        grid.addWidget(QLabel("Concurrent workers:"), 4, 0)
        self.workers_spin = QSpinBox()
        self.workers_spin.setRange(1, 1000)
        self.workers_spin.setValue(100)
        grid.addWidget(self.workers_spin, 4, 1)

        self.banner_checkbox = QCheckBox("Grab service banners")
        grid.addWidget(self.banner_checkbox, 5, 0, 1, 2)

        btn_layout = QHBoxLayout()
        layout.addLayout(btn_layout)

        self.scan_button = QPushButton("Start Scan")
        self.scan_button.clicked.connect(self.start_scan)
        btn_layout.addWidget(self.scan_button)

        self.save_button = QPushButton("Save Results as JSON")
        self.save_button.setEnabled(False)
        self.save_button.clicked.connect(self.save_results)
        btn_layout.addWidget(self.save_button)

        self.table_model = ScanTableModel()
        self.table_view = QTableView()
        self.table_view.setModel(self.table_model)
        self.table_view.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.table_view)

        self.status = self.statusBar()
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        self.status.addPermanentWidget(self.progress)

        self.setStyleSheet("""
            QWidget {
                background-color: #121212;
                color: #e0e0e0;
                font-family: 'Consolas', monospace;
                font-size: 12pt;
            }
            QLineEdit, QSpinBox {
                background-color: #1e1e1e;
                border: 1px solid #333;
                padding: 4px;
                color: #e0e0e0;
            }
            QPushButton {
                background-color: #007acc;
                border: none;
                padding: 8px 16px;
                color: white;
                font-weight: bold;
                border-radius: 4px;
            }
            QPushButton:disabled {
                background-color: #555;
            }
            QTableView {
                background-color: #1e1e1e;
                gridline-color: #333;
                color: #e0e0e0;
            }
            QHeaderView::section {
                background-color: #333;
                padding: 4px;
                border: none;
            }
        """)

    def start_scan(self):
        target = self.target_input.text().strip()
        ports_spec = self.ports_input.text().strip()
        top_n = self.top_spin.value()
        timeout = float(self.timeout_spin.value())
        workers = self.workers_spin.value()
        grab_banner = self.banner_checkbox.isChecked()

        if not target:
            QMessageBox.warning(self, "Input Error", "Please enter a target hostname or IP.")
            return

        if ports_spec and top_n > 0:
            QMessageBox.warning(self, "Input Error", "Specify either ports or top N ports, not both.")
            return

        try:
            ports = parse_ports(ports_spec if ports_spec else None, top_n if top_n > 0 else None)
        except Exception as e:
            QMessageBox.critical(self, "Port Parsing Error", str(e))
            return

        try:
            ip = resolve_target(target)
        except Exception as e:
            QMessageBox.critical(self, "Target Resolution Error", str(e))
            return

        self.status.showMessage(f"Scanning {target} ({ip}) ports: {ports[0]}-{ports[-1]} ...")
        self.scan_button.setEnabled(False)
        self.save_button.setEnabled(False)
        self.progress.setVisible(True)
        self.progress.setRange(0, 0)  # Indeterminate progress

        self.scan_worker = ScanWorker(ip, ports, timeout, workers, grab_banner)
        self.scan_worker.signals.finished.connect(self.scan_finished)
        self.scan_worker.signals.error.connect(self.scan_error)
        self.scan_worker.start()

    def scan_finished(self, results: List[ScanResult]):
        self.progress.setVisible(False)
        self.status.showMessage(f"Scan completed: {len(results)} ports scanned.")
        self.table_model.update_results(results)
        self.scan_button.setEnabled(True)
        self.save_button.setEnabled(True)

    def scan_error(self, message: str):
        self.progress.setVisible(False)
        self.status.showMessage("Scan failed.")
        QMessageBox.critical(self, "Scan Error", message)
        self.scan_button.setEnabled(True)

    def save_results(self):
        filename, _ = QFileDialog.getSaveFileName(self, "Save Scan Results", "", "JSON Files (*.json)")
        if not filename:
            return
        import json
        try:
            data = [r.__dict__ for r in self.table_model.results]
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            self.status.showMessage(f"Results saved to {filename}")
        except Exception as e:
            QMessageBox.critical(self, "Save Error", str(e))


def main():
    app = QApplication(sys.argv)
    window = PortScannerApp()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()