# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Samuel J. Tirwa & Gabriel Leiria-Roussin

import base64
import json
import os
import sys

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
    QListWidget, QListWidgetItem, QTableWidget, QTableWidgetItem, QPushButton,
    QLineEdit, QLabel, QInputDialog, QMessageBox, QFileDialog, QHeaderView,
    QTextEdit, QDialog, QFormLayout, QDialogButtonBox,
)

from app.core import APP_STYLE
from crypto import derive_master_key
from encrypt import encrypt_meta
from decrypt import decrypt_meta


class EntryDialog(QDialog):
    def __init__(self, parent=None, entry=None, folders=None):
        super().__init__(parent)
        self.setWindowTitle("Eintrag" if not entry else "Eintrag bearbeiten")
        self.resize(420, 320)
        folders = folders or ["Allgemein"]
        layout = QFormLayout(self)

        self.name_edit = QLineEdit(entry.get("name", "") if entry else "")
        self.user_edit = QLineEdit(entry.get("username", "") if entry else "")
        self.pass_edit = QLineEdit(entry.get("password", "") if entry else "")
        self.pass_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.folder_combo = QListWidget()  # simple text input instead
        self.folder_edit = QLineEdit(entry.get("folder", folders[0]) if entry else folders[0])
        self.notes_edit = QTextEdit(entry.get("notes", "") if entry else "")

        layout.addRow("Name:", self.name_edit)
        layout.addRow("Benutzername:", self.user_edit)
        layout.addRow("Passwort:", self.pass_edit)
        layout.addRow("Ordner:", self.folder_edit)
        layout.addRow("Notizen:", self.notes_edit)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addRow(buttons)

    def values(self):
        return {
            "name": self.name_edit.text().strip(),
            "username": self.user_edit.text().strip(),
            "password": self.pass_edit.text(),
            "folder": self.folder_edit.text().strip() or "Allgemein",
            "notes": self.notes_edit.toPlainText(),
        }


class KeyManagerWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("ANCORATE EncryptKey")
        self.resize(900, 600)

        self.vault_path = None
        self.salt = None
        self.master = None
        self.meta = {"version": 1, "folders": ["Allgemein"], "entries": []}

        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)

        # Toolbar
        bar = QHBoxLayout()
        self.open_btn = QPushButton("Vault öffnen")
        self.new_btn = QPushButton("Neuer Vault")
        self.lock_btn = QPushButton("Sperren")
        self.add_btn = QPushButton("Eintrag hinzufügen")
        self.add_folder_btn = QPushButton("Ordner hinzufügen")
        self.settings_btn = QPushButton("Einstellungen")
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Suchen…")
        bar.addWidget(self.open_btn)
        bar.addWidget(self.new_btn)
        bar.addWidget(self.lock_btn)
        bar.addWidget(self.add_btn)
        bar.addWidget(self.add_folder_btn)
        bar.addWidget(self.settings_btn)
        bar.addWidget(self.search_edit)
        root.addLayout(bar)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        self.folder_list = QListWidget()
        self.entry_table = QTableWidget(0, 4)
        self.entry_table.setHorizontalHeaderLabels(["Name", "Benutzername", "Ordner", "Notizen"])
        self.entry_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.entry_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        splitter.addWidget(self.folder_list)
        splitter.addWidget(self.entry_table)
        splitter.setSizes([200, 700])
        root.addWidget(splitter)

        self.status = QLabel("Kein Vault geöffnet.")
        root.addWidget(self.status)

        # Signals
        self.open_btn.clicked.connect(self.open_vault)
        self.new_btn.clicked.connect(self.create_vault)
        self.lock_btn.clicked.connect(self.lock_vault)
        self.add_btn.clicked.connect(self.add_entry)
        self.add_folder_btn.clicked.connect(self.add_folder)
        self.settings_btn.clicked.connect(self.open_settings)
        self.folder_list.currentTextChanged.connect(self.refresh_entries)
        self.search_edit.textChanged.connect(self.refresh_entries)
        self.entry_table.cellDoubleClicked.connect(self.copy_password)

        self._lock_ui(True)

    def _lock_ui(self, locked: bool):
        self.add_btn.setEnabled(not locked)
        self.add_folder_btn.setEnabled(not locked)
        self.lock_btn.setEnabled(not locked)
        self.entry_table.setEnabled(not locked)
        self.folder_list.setEnabled(not locked)
        self.search_edit.setEnabled(not locked)

    def _load_vault_file(self, path: str, password: str):
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        import base64
        salt = base64.b64decode(data["salt"])
        blob = base64.b64decode(data["blob"])
        master = derive_master_key(password, salt)
        meta = decrypt_meta(blob, master)
        self.vault_path = path
        self.salt = salt
        self.master = master
        self.meta = meta
        if "folders" not in self.meta:
            self.meta["folders"] = ["Allgemein"]
        if "entries" not in self.meta:
            self.meta["entries"] = []
        self._refresh_folders()
        self._lock_ui(False)
        self.status.setText(f"Vault geöffnet: {os.path.basename(path)}")

    def _save_vault(self):
        if not self.vault_path or not self.master:
            return
        import base64
        blob = encrypt_meta(self.meta, self.master)
        data = {
            "salt": base64.b64encode(self.salt).decode("ascii"),
            "blob": base64.b64encode(blob).decode("ascii"),
        }
        with open(self.vault_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def open_vault(self):
        path, _ = QFileDialog.getOpenFileName(self, "Vault öffnen", "", "EncryptKey Vault (*.ekv *.json);;Alle Dateien (*)")
        if not path:
            return
        pw, ok = QInputDialog.getText(self, "Vault öffnen", "Master-Passwort:", QLineEdit.EchoMode.Password)
        if not ok or not pw:
            return
        try:
            self._load_vault_file(path, pw)
        except Exception as e:
            QMessageBox.critical(self, "Fehler", f"Vault konnte nicht geöffnet werden:\n{e}")

    def create_vault(self):
        path, _ = QFileDialog.getSaveFileName(self, "Neuen Vault erstellen", "vault.ekv", "EncryptKey Vault (*.ekv)")
        if not path:
            return
        pw, ok = QInputDialog.getText(self, "Neuer Vault", "Master-Passwort:", QLineEdit.EchoMode.Password)
        if not ok or not pw:
            return
        pw2, ok2 = QInputDialog.getText(self, "Neuer Vault", "Passwort wiederholen:", QLineEdit.EchoMode.Password)
        if not ok2 or pw != pw2:
            QMessageBox.warning(self, "Fehler", "Passwörter stimmen nicht überein.")
            return
        import os, base64
        salt = os.urandom(16)
        master = derive_master_key(pw, salt)
        self.meta = {"version": 1, "folders": ["Allgemein"], "entries": []}
        self.vault_path = path
        self.salt = salt
        self.master = master
        self._save_vault()
        self._refresh_folders()
        self._lock_ui(False)
        self.status.setText(f"Vault erstellt: {os.path.basename(path)}")

    def lock_vault(self):
        self.vault_path = None
        self.salt = None
        self.master = None
        self.meta = {"version": 1, "folders": ["Allgemein"], "entries": []}
        self.folder_list.clear()
        self.entry_table.setRowCount(0)
        self._lock_ui(True)
        self.status.setText("Vault gesperrt.")

    def open_settings(self):
        from utilities.settings import SettingsDialog
        dlg = SettingsDialog(self)
        dlg.setWindowTitle("Einstellungen")
        dlg.resize(900, 600)
        dlg.show()

    def _refresh_folders(self):
        self.folder_list.clear()
        self.folder_list.addItem("Alle")
        for folder in self.meta.get("folders", []):
            self.folder_list.addItem(folder)
        self.folder_list.setCurrentRow(0)

    def refresh_entries(self):
        if not self.master:
            return
        query = self.search_edit.text().strip().lower()
        selected = self.folder_list.currentItem().text() if self.folder_list.currentItem() else "Alle"
        entries = self.meta.get("entries", [])
        filtered = []
        for e in entries:
            if selected != "Alle" and e.get("folder") != selected:
                continue
            if query and query not in (e.get("name", "") + e.get("username", "")).lower():
                continue
            filtered.append(e)

        self.entry_table.setRowCount(len(filtered))
        for i, e in enumerate(filtered):
            self.entry_table.setItem(i, 0, QTableWidgetItem(e.get("name", "")))
            self.entry_table.setItem(i, 1, QTableWidgetItem(e.get("username", "")))
            self.entry_table.setItem(i, 2, QTableWidgetItem(e.get("folder", "")))
            self.entry_table.setItem(i, 3, QTableWidgetItem(e.get("notes", "")[:60]))

    def add_folder(self):
        name, ok = QInputDialog.getText(self, "Neuer Ordner", "Ordnername:")
        if not ok or not name.strip():
            return
        name = name.strip()
        if name not in self.meta.setdefault("folders", []):
            self.meta["folders"].append(name)
            self._save_vault()
            self._refresh_folders()
        else:
            QMessageBox.information(self, "Info", "Ordner existiert bereits.")

    def add_entry(self):
        if not self.master:
            return
        folders = self.meta.get("folders", ["Allgemein"])
        dlg = EntryDialog(self, folders=folders)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        vals = dlg.values()
        if not vals["name"]:
            QMessageBox.warning(self, "Fehler", "Name ist erforderlich.")
            return
        if any(e.get("name") == vals["name"] for e in self.meta.get("entries", [])):
            QMessageBox.warning(self, "Fehler", "Eintrag existiert bereits.")
            return
        self.meta.setdefault("entries", []).append(vals)
        self._save_vault()
        self.refresh_entries()

    def copy_password(self, row, col):
        item = self.entry_table.item(row, 0)
        if not item:
            return
        name = item.text()
        entry = next((e for e in self.meta.get("entries", []) if e.get("name") == name), None)
        if entry:
            from PyQt6.QtWidgets import QApplication
            QApplication.clipboard().setText(entry.get("password", ""))
            self.status.setText(f"Passwort für '{name}' kopiert.")
            QTimer.singleShot(15000, lambda: QApplication.clipboard().clear())


def run_gui():
    app = QApplication(sys.argv)
    app.setStyleSheet(APP_STYLE)
    window = KeyManagerWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    run_gui()
