import requests
import json
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
import time
from datetime import datetime, timedelta
import os
import logging
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Semaphore
import signal
import socket


class NJFULibraryInteractive:
    """南京林业大学图书馆交互式预约系统"""

    def __init__(self):
        self.session = None
        self.token = None
        self.user_info = None
        self.base_url = "https://libseat.njfu.edu.cn"
        self.timeout = (2, 4)  # 为ARP环境进一步减少超时：连接2秒，读取4秒
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
            "Content-Type": "application/json;charset=UTF-8",
            "Referer": "https://libseat.njfu.edu.cn/",
            "Origin": "https://libseat.njfu.edu.cn"
        }

    def safe_request(self, method, url, **kwargs):
        """安全的HTTP请求，包含超时和重试机制（为嵌入式设备优化）"""
        global stop_flag
        
        max_retries = 2  # 为嵌入式设备减少重试次数
        for attempt in range(max_retries):
            if stop_flag:
                raise KeyboardInterrupt("收到停止信号")
                
            try:
                kwargs['timeout'] = self.timeout
                response = method(url, **kwargs)
                return response
            except requests.Timeout:
                logging.warning(f"请求超时 (尝试 {attempt + 1}/{max_retries}): {url}")
                if attempt == max_retries - 1:
                    raise
                interruptible_sleep(0.5 * (2 ** attempt))  # 减少等待时间
            except requests.RequestException as e:
                if "NameResolutionError" in str(e) or "Temporary failure in name resolution" in str(e):
                    logging.error(f"DNS解析失败: {url}")
                    interruptible_sleep(3)  # DNS解析失败时减少等待时间
                    # DNS解析失败时，快速检查网络连接
                    if self._check_network_connectivity():
                        logging.info("网络连接正常，可能是目标服务器问题")
                    else:
                        logging.warning("网络检测失败，但继续尝试")
                    if attempt == max_retries - 1:
                        raise
                else:
                    logging.error(f"请求异常 (尝试 {attempt + 1}/{max_retries}): {e}")
                    if attempt == max_retries - 1:
                        raise
                interruptible_sleep(0.5 * (2 ** attempt))  # 减少等待时间
        return None

    def _check_network_connectivity(self):
        """检查网络连接性（极速检测，专为嵌入式设备和ARP环境优化）"""
        global stop_flag
        
        if stop_flag:
            return False
            
        # 使用极短超时时间，适应ARP欺骗环境
        test_hosts = [
            ("8.8.8.8", 53),      # Google DNS
            ("114.114.114.114", 53),  # 114 DNS
        ]
        
        for host, port in test_hosts:
            if stop_flag:
                return False
            try:
                # 极短超时：200ms，适合ARP欺骗环境
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.2)  # 200ms超时
                result = sock.connect_ex((host, port))
                sock.close()
                if result == 0:
                    return True
            except Exception:
                try:
                    sock.close()
                except:
                    pass
                continue
        
        # 所有检测都失败，直接返回False
        return False

    def login(self, username, password):
        """登录系统"""
        self.session = requests.Session()
        try:
            # 第一个请求：获取主页
            self.safe_request(self.session.get, f"{self.base_url}/", headers=self.headers)
            interruptible_sleep(0.8)  # 增加速率限制时间

            # 第二个请求：获取公钥
            response = self.safe_request(self.session.get, f"{self.base_url}/ic-web/login/publicKey", headers=self.headers)
            if not response or response.status_code != 200:
                return False
            data = response.json()
            public_key = data["data"]["publicKey"]
            nonce_str = data["data"]["nonceStr"]

            # 加密密码
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

            interruptible_sleep(0.8)  # 增加速率限制时间
            # 第三个请求：登录
            response = self.safe_request(self.session.post, f"{self.base_url}/ic-web/login/user",
                                       json=login_data, headers=self.headers)
            if not response or response.status_code != 200:
                return False
            result = response.json()

            if result.get("code") == 0:
                self.user_info = result.get("data", {})
                self.token = self.user_info.get("token")
                return True
            else:
                logging.warning(f"登录失败: {username}, 错误信息: {result.get('msg', '未知错误')}")
                return False

        except requests.Timeout:
            logging.error(f"登录超时: {username}")
            return False
        except Exception as e:
            logging.error(f"登录异常: {username}, 错误: {e}")
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
            response = self.safe_request(self.session.get, f"{self.base_url}/ic-web/reserve/resvInfo",
                                       params=params, headers=self.headers)
            if response.status_code == 200:
                data = response.json()
                if data.get("code") == 0:
                    return data.get("data", [])
        except Exception as e:
            logging.error(f"获取预约信息失败: {e}")
        return []


# 全局信号量用于限制并发数
rate_limiter = Semaphore(2)  # 降低到最多2个并发连接
stop_flag = False  # 全局停止标志
# 全局线程池
executor = None


def interruptible_sleep(seconds):
    """可中断的睡眠函数，为ARP环境优化"""
    global stop_flag
    start_time = time.time()
    while time.time() - start_time < seconds:
        if stop_flag:
            return
        time.sleep(0.05)  # 每50ms检查一次中断信号（更频繁）


def signal_handler(signum, frame):
    """处理 Ctrl-C 信号（优化版）"""
    global stop_flag, executor
    
    if stop_flag:  # 避免重复处理信号
        return
        
    stop_flag = True
    print("\n🛑 接收到中断信号，正在快速退出...")
    
    if executor:
        try:
            executor.shutdown(wait=False)  # 立即关闭线程池
            print("✅ 线程池已关闭")
        except Exception as e:
            print(f"关闭线程池时出错: {e}")
    
    # 快速退出，避免线程清理问题
    os._exit(0)


def process_account(credentials, output_file):
    """处理单个账户的函数"""
    global stop_flag
    
    if stop_flag:
        return None
        
    username, password = credentials.strip().split("  ")
    
    with rate_limiter:  # 限制并发数
        if stop_flag:
            return None
            
        logging.info(f"开始处理账户: {username}")
        library = NJFULibraryInteractive()
        
        try:
            if library.login(username, password):
                true_name = library.user_info.get("trueName", "未知")
                interruptible_sleep(0.3)  # 为嵌入式设备减少延时
                reservations = library.get_my_reservations()
                
                results = []
                if reservations:
                    for resv in reservations:
                        dev_info = resv.get("resvDevInfoList", [{}])[0]
                        seat_name = dev_info.get("devName", "未知座位")
                        room_name = dev_info.get("roomName", "未知房间")
                        begin_time = datetime.fromtimestamp(resv.get("resvBeginTime") / 1000).strftime("%Y-%m-%d %H:%M")
                        end_time = datetime.fromtimestamp(resv.get("resvEndTime") / 1000).strftime("%Y-%m-%d %H:%M")
                        info = f"{true_name} {seat_name} ({room_name}) {begin_time} - {end_time}"
                        results.append(info)
                        print(info)  # 实时打印
                
                logging.info(f"✅ {username} 处理完成，找到 {len(results)} 个预约")
                return {"username": username, "success": True, "results": results}
            else:
                error_message = f"{username} 登录失败"
                print(error_message)
                logging.warning(error_message)
                return {"username": username, "success": False, "error": "登录失败"}
                
        except Exception as e:
            error_message = f"{username} 处理异常: {e}"
            print(error_message)
            logging.error(error_message)
            return {"username": username, "success": False, "error": str(e)}
        finally:
            interruptible_sleep(0.7)  # 为嵌入式设备减少速率限制等待时间


def main():
    """主程序"""
    global executor, stop_flag
    
    # 重置全局变量
    stop_flag = False
    executor = None
    
    # 设置日志
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler('library_process.log', encoding='utf-8')
        ]
    )

    # 注册信号处理器
    signal.signal(signal.SIGINT, signal_handler)

    script_dir = os.path.dirname(os.path.abspath(__file__))
    input_file = os.path.join(script_dir, "lib.txt")
    output_file = os.path.join(script_dir, "lib_analyse.txt")

    try:
        print("🚀 开始处理账户信息...")
        logging.info("开始批量处理账户")

        # 可选：添加快速跳过网络检测的选项
        if "--skip-network-check" in sys.argv:
            print("⏭️  跳过网络检测，直接开始处理")
            logging.info("用户选择跳过网络检测")
        else:
            # 检查网络连接（快速检测）
            print("🔍 正在快速检查网络连接（3秒内完成）...")
            library_test = NJFULibraryInteractive()
            try:
                if not library_test._check_network_connectivity():
                    print("⚠️  网络连接检测失败，但程序将继续运行")
                    print("   如果遇到DNS解析问题，请检查网络设置")
                    logging.warning("网络连接检测失败，但继续执行")
                else:
                    print("✅ 网络连接正常")
                    logging.info("网络连接检测通过")
            except Exception as e:
                print(f"⚠️  网络检测异常: {e}，但程序将继续运行")
                logging.warning(f"网络检测异常: {e}，但继续执行")

        # 读取所有账户信息
        with open(input_file, "r", encoding="utf-8") as infile:
            credentials_list = [line.strip() for line in infile if line.strip()]

        print(f"📋 共找到 {len(credentials_list)} 个账户")

        # 使用线程池进行并发处理
        all_results = []
        # 为嵌入式设备进一步降低并发数
        if "--single-thread" in sys.argv:
            max_workers = 1
            print("🔧 使用单线程模式（适合低性能设备）")
        else:
            max_workers = min(2, len(credentials_list))  # 最多2个并发线程

        executor = ThreadPoolExecutor(max_workers=max_workers)
        try:
            future_to_cred = {
                executor.submit(process_account, cred, output_file): cred 
                for cred in credentials_list
            }

            completed = 0
            for future in as_completed(future_to_cred):
                if stop_flag:
                    break

                try:
                    result = future.result(timeout=30)  # 为嵌入式设备减少超时时间
                    if result:
                        all_results.append(result)
                    completed += 1
                    print(f"⏳ 进度: {completed}/{len(credentials_list)}")
                except Exception as e:
                    cred = future_to_cred[future]
                    username = cred.split()[0] if cred else 'unknown'
                    logging.error(f"处理账户失败: {username}, 错误: {e}")
                    # 添加失败的结果
                    all_results.append({"username": username, "success": False, "error": str(e)})

        finally:
            # 确保线程池正确关闭
            if executor:
                try:
                    executor.shutdown(wait=False)  # 立即关闭，不等待
                    logging.info("线程池已关闭")
                except Exception as e:
                    logging.error(f"关闭线程池异常: {e}")
                executor = None

        # 写入结果文件
        print("📝 正在写入结果文件...")
        with open(output_file, "w", encoding="utf-8") as outfile:
            success_count = 0
            fail_count = 0

            for result in all_results:
                if result["success"]:
                    success_count += 1
                    if result["results"]:
                        for info in result["results"]:
                            outfile.write(info + "\n")
                    else:
                        outfile.write(f"{result['username']} 无预约信息\n")
                    outfile.write("\n")
                else:
                    fail_count += 1
                    outfile.write(f"{result['username']} {result['error']}\n\n")

            summary = f"=== 处理统计 ===\n总账户数: {len(credentials_list)}\n成功: {success_count}\n失败: {fail_count}\n处理时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            outfile.write(summary)
            print(summary)

        print(f"✅ 处理完成！结果已保存到: {output_file}")
        logging.info(f"批量处理完成，成功: {success_count}, 失败: {fail_count}")

    except KeyboardInterrupt:
        print("\n🛑 用户中断操作")
        if executor:
            executor.shutdown(wait=False)
        os._exit(0)  # 快速退出
    except FileNotFoundError:
        print(f"❌ 文件不存在: {input_file}")
        logging.error(f"输入文件不存在: {input_file}")
        sys.exit(1)
    except Exception as e:
        print(f"❌ 程序异常: {e}")
        logging.error(f"程序异常: {e}")
        if executor:
            executor.shutdown(wait=False)
        sys.exit(1)
    finally:
        # 最终清理
        if executor:
            try:
                executor.shutdown(wait=False)
            except:
                pass


if __name__ == "__main__":
    main()