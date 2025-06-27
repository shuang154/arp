import requests
import json
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
import time
from datetime import datetime, timedelta
import os


class NJFULibraryInteractive:
    """南京林业大学图书馆交互式预约系统"""

    def __init__(self):
        self.session = None
        self.token = None
        self.user_info = None
        self.base_url = "https://libseat.njfu.edu.cn"
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
            "Content-Type": "application/json;charset=UTF-8",
            "Referer": "https://libseat.njfu.edu.cn/",
            "Origin": "https://libseat.njfu.edu.cn"
        }

    def login(self, username, password):
        """登录系统"""
        self.session = requests.Session()
        try:
            self.session.get(f"{self.base_url}/", headers=self.headers)
            time.sleep(0.5)

            response = self.session.get(f"{self.base_url}/ic-web/login/publicKey", headers=self.headers)
            data = response.json()
            public_key = data["data"]["publicKey"]
            nonce_str = data["data"]["nonceStr"]

            password_to_encrypt = password + ";" + nonce_str
            formatted_key = f"-----BEGIN PUBLIC KEY-----\n{public_key}\n-----END PUBLIC KEY-----"
            rsa_key = RSA.importKey(formatted_key)
            cipher = PKCS1_v1_5.new(rsa_key)
            encrypted_bytes = cipher.encrypt(password_to_encrypt.encode())
            encrypted_password = base64.b64encode(encrypted_bytes).decode()

            login_data = {
                "logonName": username,
                "password": encrypted_password,
                "captcha": "",
                "consoleType": 16,
                "privacy": True
            }

            response = self.session.post(f"{self.base_url}/ic-web/login/user",
                                         json=login_data, headers=self.headers)
            result = response.json()

            if result.get("code") == 0:
                self.user_info = result.get("data", {})
                self.token = self.user_info.get("token")
                return True
            else:
                return False

        except Exception:
            return False

    def get_my_reservations(self):
        """获取我的预约列表"""
        begin_date = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
        end_date = (datetime.now() + timedelta(days=7)).strftime("%Y-%m-%d")

        params = {
            "beginDate": begin_date,
            "endDate": end_date,
            "needStatus": 6,
            "page": 1,
            "pageNum": 20,
            "orderKey": "gmt_create",
            "orderModel": "desc"
        }

        try:
            response = self.session.get(f"{self.base_url}/ic-web/reserve/resvInfo",
                                        params=params, headers=self.headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                if data.get("code") == 0:
                    return data.get("data", [])
        except Exception:
            pass
        return []


def main():
    """主程序"""
    library = NJFULibraryInteractive()
    script_dir = os.path.dirname(os.path.abspath(__file__))  # 获取脚本所在目录
    input_file = os.path.join(script_dir, "lib.txt")  # 确保 lib.txt 在同级目录
    output_file = os.path.join(script_dir, "lib_analyse.txt")  # 确保 lib_analyse.txt 在同级目录

    try:
        with open(input_file, "r", encoding="utf-8") as infile, open(output_file, "w", encoding="utf-8") as outfile:
            for line in infile:
                line = line.strip()
                if not line:
                    continue
                username, password = line.split("  ")
                if library.login(username, password):
                    true_name = library.user_info.get("trueName", "未知")
                    reservations = library.get_my_reservations()

                    # 写入并打印进行中的预约信息
                    if reservations:
                        for resv in reservations:
                            dev_info = resv.get("resvDevInfoList", [{}])[0]
                            seat_name = dev_info.get("devName", "未知座位")
                            room_name = dev_info.get("roomName", "未知房间")
                            begin_time = datetime.fromtimestamp(resv.get("resvBeginTime") / 1000).strftime("%Y-%m-%d %H:%M")
                            end_time = datetime.fromtimestamp(resv.get("resvEndTime") / 1000).strftime("%Y-%m-%d %H:%M")
                            info = f"{true_name} {seat_name} ({room_name}) {begin_time} - {end_time}"
                            outfile.write(info + "\n")
                            print(info)  # 打印到命令行
                    outfile.write("\n")
                    print()  # 打印空行
                else:
                    error_message = f"{username} 登录失败"
                    outfile.write(error_message + "\n\n")
                    print(error_message)  # 打印到命令行
    except Exception as e:
        print(f"❌ 程序异常: {e}")


if __name__ == "__main__":
    main()