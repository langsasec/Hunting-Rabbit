import json
import os.path
import re
import sys


from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import QApplication, QMainWindow, QSplitter, QWidget, QVBoxLayout, QLabel, QLineEdit, \
    QComboBox, QPushButton, QTextEdit, QMessageBox


class PoCGenerator(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Hunting-Rabbit-POC-Generator V1.0")
        self.setAccessibleName("Hunting-Rabbit-POC-Generator")
        self.setGeometry(300, 300, 1700, 900)
        self.setWindowIcon(QIcon('favicon.ico'))

        # 检测配置文件是否存在：
        if not os.path.exists("config.ini"):
            # 弹出提示框让填写信息
            QMessageBox.information(self, "提示", f"请填写配置文件 config.ini ，方便其他用户使用POC时可以互相交流。")
            # 如果不存在，则创建配置文件
            with open("config.ini", "w",encoding="utf-8") as f:
                f.write('# 请勿删除此行，这是为了用户填写联系信息，你将是POC的贡献者，方便其他用户使用POC时可以互相联系，也可以不填写\n')
                f.write('Author=\n')
                f.write('Email=\n')
                f.write('GitHub=\n')
        else:
            pass

        # 创建分割器
        self.splitter = QSplitter(self)
        self.setCentralWidget(self.splitter)

        # 左侧：基本信息
        self.left_widget = QWidget()
        self.splitter.addWidget(self.left_widget)
        self.left_layout = QVBoxLayout()
        self.left_widget.setLayout(self.left_layout)
        # 漏洞POC基本信息
        self.create_vulnerability_info()

        # 右侧：PoC代码
        self.right_widget = QWidget()
        self.splitter.addWidget(self.right_widget)
        self.right_layout = QVBoxLayout()
        self.right_widget.setLayout(self.right_layout)
        # 验证规则
        self.create_verification_rules()

        # 清空按钮
        self.clear_button = QPushButton("清空")
        self.clear_button.clicked.connect(self.clear_all_edit)
        self.left_layout.addWidget(self.clear_button)


        # 生成PoC按钮
        self.generate_button = QPushButton("生成PoC")
        self.generate_button.clicked.connect(self.generate_poc)
        self.left_layout.addWidget(self.generate_button)
        # 应用样式表
        self.apply_stylesheet()

    def clear_all_edit(self):
        # 清空所有编辑框的内容
        for widget in self.left_widget.findChildren(QLineEdit):
            widget.clear()
        for widget in self.right_widget.findChildren(QLineEdit):
            widget.clear()
        for widget in self.left_widget.findChildren(QTextEdit):
            widget.clear()
        for widget in self.right_widget.findChildren(QTextEdit):
            widget.clear()


    def apply_stylesheet(self):
        stylesheet = """
               QWidget {
                   background-color: #F5F5F5;
                   color: #333;
                   font-family: 'Microsoft YaHei', 'Segoe UI', Tahoma, sans-serif;
                   font-size: 20px;
               }
               QLabel {
                   font-weight: bold;
               }
               QLineEdit, QTextEdit, QComboBox {
                   border: 2px solid #BBB;
                   border-radius: 4px;
                   padding: 2px;
               }
               QComboBox {
                   padding-right: 15px; /* Make room for the dropdown arrow */
               }
               QPushButton {
                   background-color: #0078D7;
                   color: #FFF;
                   border: none;
                   border-radius: 4px;
                   padding: 5px 15px;
                   font-weight: bold;
               }
               QPushButton:hover {
                   background-color: #005A9C;
               }
               QTextEdit {
                   border: 1px solid #BBB;
                   border-radius: 4px;
                   padding: 2px;
               }
               """
        self.setStyleSheet(stylesheet)

    def create_vulnerability_info(self):
        # 漏洞名称
        self.vul_name_label = QLabel("漏洞名称：")
        self.vul_name_edit = QLineEdit()
        # 设置提示性文字
        self.vul_name_edit.setPlaceholderText("请输入漏洞名称，例如：某OA存在任意文件上传漏洞")
        self.left_layout.addWidget(self.vul_name_label)
        self.left_layout.addWidget(self.vul_name_edit)

        # 危害级别
        self.severity_label = QLabel("危害级别：")
        self.severity_combo = QComboBox()
        self.severity_combo.addItems(["高危", "中危", "低危"])
        self.left_layout.addWidget(self.severity_label)
        self.left_layout.addWidget(self.severity_combo)

        # 漏洞描述
        self.desc_label = QLabel("漏洞描述：")
        self.desc_edit = QTextEdit()
        self.desc_edit.setPlaceholderText("简要描述漏洞及危害")
        self.left_layout.addWidget(self.desc_label)
        self.left_layout.addWidget(self.desc_edit)

        # 影响产品
        self.product_label = QLabel("影响产品：")
        self.product_edit = QLineEdit()
        self.product_edit.setPlaceholderText("漏洞所影响的产品名称")
        self.left_layout.addWidget(self.product_label)
        self.left_layout.addWidget(self.product_edit)

        # 影响版本
        self.version_label = QLabel("影响版本：")
        self.version_edit = QLineEdit()
        self.version_edit.setPlaceholderText("漏洞所影响产品的对应版本")
        self.left_layout.addWidget(self.version_label)
        self.left_layout.addWidget(self.version_edit)

        # CVE/CNVD/CNNVD编号
        self.cve_label = QLabel("CVE/CNVD/CNNVD编号：")
        self.cve_edit = QLineEdit()
        self.cve_edit.setPlaceholderText("请输入CVE/CNVD/CNNVD编号,例如：CVE-2022-1000")
        self.left_layout.addWidget(self.cve_label)
        self.left_layout.addWidget(self.cve_edit)

        # Reference
        self.reference_label = QLabel("Reference：")
        self.reference_edit = QLineEdit()
        self.reference_edit.setPlaceholderText("请输入参考链接，信息来源等")
        self.left_layout.addWidget(self.reference_label)
        self.left_layout.addWidget(self.reference_edit)

        # 修复建议
        self.advice_label = QLabel("修复建议：")
        self.advice_edit = QTextEdit()
        self.advice_edit.setPlaceholderText("这里填写漏洞修复的方法，建议，参考链接等，方便系统管理者修复漏洞")
        self.left_layout.addWidget(self.advice_label)
        self.left_layout.addWidget(self.advice_edit)

    def create_verification_rules(self):
        # 路径
        self.path_label = QLabel("路径 - Path：")
        self.path_edit = QLineEdit()
        # 设置提示性文字
        self.path_edit.setPlaceholderText("请输入漏洞所存在的路径，例如：/upload.php")
        self.right_layout.addWidget(self.path_label)
        self.right_layout.addWidget(self.path_edit)

        # 请求方法
        self.method_label = QLabel("请求方法 - Method：")
        self.method_combo = QComboBox()
        self.method_combo.addItems(["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
        self.right_layout.addWidget(self.method_label)
        self.right_layout.addWidget(self.method_combo)

        # 请求头
        self.header_label = QLabel("请求头 - Headers：")
        self.header_edit = QTextEdit()
        # 设置提示性文字
        self.header_edit.setPlaceholderText("""User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:99.0) Gecko/20100101 Firefox/99.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded""")
        self.right_layout.addWidget(self.header_label)
        self.right_layout.addWidget(self.header_edit)

        # 请求体
        self.body_label = QLabel("请求体 - Body：")
        self.body_edit = QTextEdit()
        self.body_edit.setPlaceholderText("""username=admin&password=123456""")
        self.right_layout.addWidget(self.body_label)
        self.right_layout.addWidget(self.body_edit)

        # 响应码
        self.status_label = QLabel("响应状态码：")
        self.status_edit = QLineEdit()
        self.status_edit.setPlaceholderText("请求后的响应状态码，例如：200")
        self.right_layout.addWidget(self.status_label)
        self.right_layout.addWidget(self.status_edit)

        # 关键字
        self.keyword_label = QLabel("响应关键字（特征字，响应头和响应体中的均可）：")
        self.keyword_edit = QLineEdit()
        self.keyword_edit.setPlaceholderText("能够确定漏洞存在的关键字，特征字，多个用英文分号;隔开")
        self.right_layout.addWidget(self.keyword_label)
        self.right_layout.addWidget(self.keyword_edit)

        # 响应时间
        self.response_time_label = QLabel("响应时间（单位/秒/s，常用于延时注入）：")
        self.response_time_edit = QLineEdit()
        self.response_time_edit.setPlaceholderText("输入最短响应时间,可为空")
        self.right_layout.addWidget(self.response_time_label)
        self.right_layout.addWidget(self.response_time_edit)

    def generate_poc(self):
        # 获取输入的数据
        vul_name = self.vul_name_edit.text()
        level = self.severity_combo.currentText()
        description = self.desc_edit.toPlainText()
        product = self.product_edit.text()
        version = self.version_edit.text()
        cve = self.cve_edit.text()
        reference = self.reference_edit.text()
        fixing = self.advice_edit.toPlainText()
        path = self.path_edit.text()
        method = self.method_combo.currentText()
        headers = self.header_edit.toPlainText()
        body = self.body_edit.toPlainText()
        status_code = self.status_edit.text()
        keywords = self.keyword_edit.text()
        res_time = self.response_time_edit.text()

        with open("config.ini", "r", encoding="utf-8") as f:
            lines = f.readlines()
            author = lines[1].replace("\n", "").replace("Author=", "")
            email = lines[2].replace("\n", "").replace("Email=", "")
            github = lines[3].replace("\n", "").replace("GitHub=", "")

        poc = {
            "vul_name": vul_name,
            "level": level,
            "description": description,
            "product": product,
            "version": version,
            "cve": cve,
            "reference": reference,
            "fixing": fixing,
            "rule": {
                "path": path,
                "method": method,
                "headers": headers,
                "body": body,
                "status_code": status_code,
                "keywords": keywords,
                "res_time": res_time
            },
            "operator": {
                "author": author,
                "email": email,
                "github": github
            },
        }
        # 禁止非法字符
        if vul_name:

            vul_name = sanitize_filename(vul_name)
            # 判断规则是否已写全
            if not path or not method or not status_code:
                QMessageBox.warning(self, "警告", "请填写有效完整规则！包括路径、响应状态码等。")
            else:
                if not keywords:
                    if QMessageBox.Yes == QMessageBox.warning(self, "警告", "不填写响应关键字可能会导致POC误报率提高！你确定要继续吗？",QMessageBox.Yes | QMessageBox.No, QMessageBox.No):
                        # 判断是否已存在同名POC文件
                        if os.path.exists(f"{vul_name}.json"):
                            QMessageBox.warning(self, "警告", f"POC文件已存在！{vul_name}.json")

                            # 询问是否覆盖
                            overwrite = QMessageBox.question(self, "提示", f"是否覆盖已存在的POC文件？{vul_name}.json", QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
                            if overwrite == QMessageBox.Yes:
                                with open(f"{vul_name}.json", "w", encoding="utf-8") as f:
                                    json.dump(poc, f, ensure_ascii=False, indent=4)
                                QMessageBox.information(self, "提示", f"POC已生成！{vul_name}.json")
                        else:
                            with open(f"{vul_name}.json", "w", encoding="utf-8") as f:
                                json.dump(poc, f, ensure_ascii=False, indent=4)
                            QMessageBox.information(self, "提示", f"POC已生成！{vul_name}.json")
                else:
                    with open(f"{vul_name}.json", "w", encoding="utf-8") as f:
                        json.dump(poc, f, ensure_ascii=False, indent=4)
                    QMessageBox.information(self, "提示", f"POC已生成！{vul_name}.json")

        else:
            QMessageBox.warning(self, "警告", "请输入POC名称！")


# 禁止非法字符
def sanitize_filename(filename, replacement='-'):
    # 创建一个正则表达式模式，匹配需要被替换的字符
    pattern = re.compile(r'[ "\/\\<>*|:?]')
    # 使用指定的字符替换匹配到的字符
    sanitized_filename = pattern.sub(replacement, filename)
    return sanitized_filename


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PoCGenerator()
    window.show()
    sys.exit(app.exec_())
