import sys
import json
import os
import random
import string
import pyperclip
from cryptography.fernet import Fernet
from PyQt5.QtWidgets import (QApplication, QWidget, QVBoxLayout, QHBoxLayout, 
                           QPushButton, QLineEdit, QLabel, QMessageBox,
                           QTableWidget, QTableWidgetItem, QHeaderView, QSpinBox)
from PyQt5.QtCore import Qt

class ModernPasswordManager(QWidget):
    def __init__(self):
        super().__init__()
        self.init_storage()
        self.init_encryption()
        self.initUI()
        
    def init_storage(self):
        self.DATA_FOLDER = r"C:\PasManager"
        if not os.path.exists(self.DATA_FOLDER):
            os.makedirs(self.DATA_FOLDER)
            
        self.DATA_FILE = os.path.join(self.DATA_FOLDER, "passwords.json")
        self.KEY_FILE = os.path.join(self.DATA_FOLDER, "key.key")
        
    def init_encryption(self):
        if not os.path.exists(self.KEY_FILE):
            key = Fernet.generate_key()
            with open(self.KEY_FILE, "wb") as key_file:
                key_file.write(key)
        else:
            with open(self.KEY_FILE, "rb") as key_file:
                key = key_file.read()
                
        self.fernet = Fernet(key)
        
    def initUI(self):
        self.setWindowTitle("JavaD 🛠")
        self.setGeometry(100, 100, 800, 500)
        
        layout = QVBoxLayout()
        layout.setSpacing(15)
        
        title_layout = QHBoxLayout()
        title_label = QLabel("Title:")
        self.title_input = QLineEdit()
        self.title_input.setPlaceholderText("Enter Title For Password...")
        title_layout.addWidget(title_label)
        title_layout.addWidget(self.title_input)
        
        self.length_spinbox = QSpinBox()
        self.length_spinbox.setRange(8, 32)
        self.length_spinbox.setValue(16)
        self.length_spinbox.setPrefix("Length: ")
        title_layout.addWidget(self.length_spinbox)
        
        layout.addLayout(title_layout)
        
        password_layout = QHBoxLayout()
        
        self.password_display = QLineEdit()
        self.password_display.setReadOnly(True)
        self.password_display.setPlaceholderText("Generated Password")
        
        self.generate_btn = QPushButton("Generate")
        self.generate_btn.clicked.connect(self.generate_password)
        
        self.copy_btn = QPushButton("Copy")
        self.copy_btn.clicked.connect(self.copy_password)
        
        self.save_btn = QPushButton("Save")
        self.save_btn.clicked.connect(self.save_password)
        
        password_layout.addWidget(self.password_display)
        password_layout.addWidget(self.generate_btn)
        password_layout.addWidget(self.copy_btn)
        password_layout.addWidget(self.save_btn)
        
        layout.addLayout(password_layout)
        
        table_label = QLabel("Saved Passwords")
        table_label.setStyleSheet("font-weight: bold; font-size: 14px; margin-top: 10px;")
        layout.addWidget(table_label)
        
        self.passwords_table = QTableWidget()
        self.passwords_table.setColumnCount(3)
        self.passwords_table.setHorizontalHeaderLabels(["Title", "Password", "Actions"])
        
        header = self.passwords_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Stretch)
        header.setSectionResizeMode(1, QHeaderView.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        
        layout.addWidget(self.passwords_table)
        
        self.setStyleSheet("""
            QWidget {
                font-size: 12px;
            }
            QLabel {
                color: #2c3e50;
            }
            QLineEdit {
                padding: 8px;
                border: 2px solid #e0e0e0;
                border-radius: 5px;
                background: white;
            }
            QLineEdit:focus {
                border: 2px solid #2196F3;
            }
            QPushButton {
                padding: 8px 15px;
                background-color: #2196F3;
                color: white;
                border: none;
                border-radius: 5px;
                min-width: 80px;
            }
            QPushButton:hover {
                background-color: #1976D2;
            }
            QPushButton[warning="true"] {
                background-color: #dc3545;
            }
            QPushButton[warning="true"]:hover {
                background-color: #c82333;
            }
            QTableWidget {
                border: 1px solid #e0e0e0;
                border-radius: 5px;
                background: white;
            }
            QHeaderView::section {
                background-color: #f5f5f5;
                padding: 8px;
                border: none;
                border-right: 1px solid #e0e0e0;
                font-weight: bold;
            }
            QSpinBox {
                padding: 5px;
                border: 2px solid #e0e0e0;
                border-radius: 5px;
                min-width: 100px;
            }
        """)
        
        self.setLayout(layout)
        self.load_passwords()

    def generate_password(self):
        length = self.length_spinbox.value()
        characters = string.ascii_letters + string.digits + "!@#$%^&*"
        password = ''.join(random.choice(characters) for _ in range(length))
        self.password_display.setText(password)
        
    def copy_password(self):
        password = self.password_display.text()
        if password:
            pyperclip.copy(password)
            QMessageBox.information(self, "Success", "Password copied to clipboard!")
        else:
            QMessageBox.warning(self, "Error", "No password to copy!")
            
    def save_password(self):
        title = self.title_input.text()
        password = self.password_display.text()
        
        if not title or not password:
            QMessageBox.warning(self, "Error", "Please enter both title and password!")
            return
            
        try:
            passwords = self.load_encrypted_data()
            passwords[title] = password
            
            encrypted_data = self.fernet.encrypt(json.dumps(passwords).encode())
            with open(self.DATA_FILE, "wb") as file:
                file.write(encrypted_data)
                
            self.load_passwords()
            self.title_input.clear()
            self.password_display.clear()
            QMessageBox.information(self, "Success", "Password saved successfully!")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error saving password: {str(e)}")
    
    def load_encrypted_data(self):
        if not os.path.exists(self.DATA_FILE):
            return {}
        try:
            with open(self.DATA_FILE, "rb") as file:
                encrypted_data = file.read()
            decrypted_data = self.fernet.decrypt(encrypted_data)
            return json.loads(decrypted_data)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error decrypting data: {str(e)}")
            return {}
    
    def load_passwords(self):
        self.passwords_table.setRowCount(0)
        
        try:
            passwords = self.load_encrypted_data()
            
            for row, (title, password) in enumerate(passwords.items()):
                self.passwords_table.insertRow(row)
                
                title_item = QTableWidgetItem(title)
                self.passwords_table.setItem(row, 0, title_item)
                
                password_item = QTableWidgetItem("●" * 12)
                self.passwords_table.setItem(row, 1, password_item)
                
                action_widget = QWidget()
                action_layout = QHBoxLayout(action_widget)
                action_layout.setContentsMargins(5, 2, 5, 2)
                
                view_btn = QPushButton("View")
                view_btn.setFixedWidth(60)
                view_btn.clicked.connect(lambda _, p=password: self.view_password(p))
                
                delete_btn = QPushButton("Delete")
                delete_btn.setFixedWidth(60)
                delete_btn.setProperty("warning", True)
                delete_btn.clicked.connect(lambda _, t=title: self.delete_password(t))
                
                action_layout.addWidget(view_btn)
                action_layout.addWidget(delete_btn)
                
                self.passwords_table.setCellWidget(row, 2, action_widget)
                    
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error loading passwords: {str(e)}")
    
    def view_password(self, password):
        dialog = QMessageBox(self)
        dialog.setWindowTitle("Password")
        dialog.setText(f"Password: {password}")
        
        copy_btn = dialog.addButton("Copy", QMessageBox.ActionRole)
        dialog.addButton("Close", QMessageBox.RejectRole)
        
        dialog.exec_()
        
        if dialog.clickedButton() == copy_btn:
            pyperclip.copy(password)
            QMessageBox.information(self, "Success", "Password copied to clipboard!")
    
    def delete_password(self, title):
        reply = QMessageBox.question(self, "Confirm Delete",
                                   f"Are you sure you want to delete '{title}'?",
                                   QMessageBox.Yes | QMessageBox.No)
        
        if reply == QMessageBox.Yes:
            try:
                passwords = self.load_encrypted_data()
                
                if title in passwords:
                    del passwords[title]
                    
                    encrypted_data = self.fernet.encrypt(json.dumps(passwords).encode())
                    with open(self.DATA_FILE, "wb") as file:
                        file.write(encrypted_data)
                    
                    self.load_passwords()
                    QMessageBox.information(self, "Success", "Password deleted successfully!")
            
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Error deleting password: {str(e)}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ModernPasswordManager()
    window.show()
    sys.exit(app.exec_())