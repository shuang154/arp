"""
配置管理模块
============
负载加载和管理系统配置参数
"""

import yaml
import os
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

@dataclass
class NetworkConfig:
    """网络配置"""
    interface: str = "wlan0"
    gateway_ip: str = "10.17.0.1"  # ★【修复】★ 根据temporary.txt中的IP段修改
    target_server: str = "121.248.150.37"  # ★【修复】★ 校园网认证服务器
    target_ports: List[int] = field(default_factory=lambda: [80, 443, 8080, 801])  # 包含801端口

@dataclass
class IPCConfig:
    """IPC通信配置"""
    packet_address: str = "ipc:///tmp/arp_spoofer_packets.ipc"
    command_address: str = "ipc:///tmp/arp_spoofer_commands.ipc"

@dataclass
class PerformanceConfig:
    """性能配置"""
    max_worker_threads: int = 8
    packet_buffer_size: int = 8388608  # 8MB
    command_timeout: int = 1000  # ms

@dataclass
class AttackConfig:
    """攻击策略配置"""
    stealth_mode: bool = False
    attack_timeout: int = 45  # seconds
    max_concurrent_attacks: int = 20
    cooldown_time: int = 3600  # seconds

@dataclass
class CacheConfig:
    """缓存配置"""
    arp_cache_ttl: int = 1800  # seconds
    attack_cache_ttl: int = 3600  # seconds
    target_info_ttl: int = 7200  # seconds

@dataclass
class LoggingConfig:
    """日志配置"""
    level: str = "INFO"
    file: str = "/var/log/arp_spoofer.log"
    max_size: int = 104857600  # 100MB
    backup_count: int = 5

@dataclass
class WebAPIConfig:
    """Web API配置"""
    enabled: bool = True
    port: int = 8080
    host: str = "0.0.0.0"

@dataclass
class SecurityConfig:
    """安全配置"""
    require_root: bool = True
    bind_to_cpu: bool = True
    memory_limit: int = 536870912  # 512MB

class Config:
    """主配置类"""
    
    def __init__(self):
        self.network = NetworkConfig()
        self.ipc = IPCConfig()
        self.performance = PerformanceConfig()
        self.attack = AttackConfig()
        self.cache = CacheConfig()
        self.logging = LoggingConfig()
        self.web_api = WebAPIConfig()
        self.security = SecurityConfig()
    
    # 便捷属性
    @property
    def packet_ipc_address(self) -> str:
        return self.ipc.packet_address
    
    @packet_ipc_address.setter
    def packet_ipc_address(self, value: str):
        """设置数据包IPC地址"""
        self.ipc.packet_address = value
    
    @property
    def command_ipc_address(self) -> str:
        return self.ipc.command_address
    
    @command_ipc_address.setter
    def command_ipc_address(self, value: str):
        """设置命令IPC地址"""
        self.ipc.command_address = value
    
    @property
    def max_worker_threads(self) -> int:
        return self.performance.max_worker_threads
    
    @max_worker_threads.setter
    def max_worker_threads(self, value: int):
        """设置最大工作线程数"""
        if value < 1:
            raise ValueError("工作线程数必须大于0")
        self.performance.max_worker_threads = value
    
    @property
    def log_level(self) -> str:
        return self.logging.level
    
    @log_level.setter
    def log_level(self, value: str):
        """设置日志级别"""
        if value not in ['DEBUG', 'INFO', 'WARNING', 'ERROR']:
            raise ValueError("日志级别必须是 'DEBUG', 'INFO', 'WARNING', 或 'ERROR' 之一")
        self.logging.level = value
    
    @property
    def log_file(self) -> str:
        return self.logging.file
    
    @log_file.setter
    def log_file(self, value: str):
        """设置日志文件路径"""
        self.logging.file = value
    
    @property
    def enable_web_api(self) -> bool:
        return self.web_api.enabled
    
    @enable_web_api.setter
    def enable_web_api(self, value: bool):
        """设置是否启用Web API"""
        self.web_api.enabled = value
    
    @property
    def web_api_port(self) -> int:
        return self.web_api.port
    
    @web_api_port.setter
    def web_api_port(self, value: int):
        """设置Web API端口"""
        if value < 1 or value > 65535:
            raise ValueError("端口必须在1-65535范围内")
        self.web_api.port = value
    
    @classmethod
    def load_from_file(cls, config_file: str) -> 'Config':
        """从YAML文件加载配置"""
        config = cls()
        
        if not os.path.exists(config_file):
            print(f"警告: 配置文件 {config_file} 不存在，使用默认配置")
            return config
        
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                yaml_data = yaml.safe_load(f)
            
            if not yaml_data:
                print("警告: 配置文件为空，使用默认配置")
                return config
            
            # 解析各个配置部分
            if 'network' in yaml_data:
                net_config = yaml_data['network']
                config.network.interface = net_config.get('interface', config.network.interface)
                config.network.gateway_ip = net_config.get('gateway_ip', config.network.gateway_ip)
                config.network.target_server = net_config.get('target_server', config.network.target_server)
                config.network.target_ports = net_config.get('target_ports', config.network.target_ports)
            
            if 'ipc' in yaml_data:
                ipc_config = yaml_data['ipc']
                config.ipc.packet_address = ipc_config.get('packet_address', config.ipc.packet_address)
                config.ipc.command_address = ipc_config.get('command_address', config.ipc.command_address)
            
            if 'performance' in yaml_data:
                perf_config = yaml_data['performance']
                config.performance.max_worker_threads = perf_config.get('max_worker_threads', config.performance.max_worker_threads)
                config.performance.packet_buffer_size = perf_config.get('packet_buffer_size', config.performance.packet_buffer_size)
                config.performance.command_timeout = perf_config.get('command_timeout', config.performance.command_timeout)
            
            if 'attack' in yaml_data:
                attack_config = yaml_data['attack']
                config.attack.stealth_mode = attack_config.get('stealth_mode', config.attack.stealth_mode)
                config.attack.attack_timeout = attack_config.get('attack_timeout', config.attack.attack_timeout)
                config.attack.max_concurrent_attacks = attack_config.get('max_concurrent_attacks', config.attack.max_concurrent_attacks)
                config.attack.cooldown_time = attack_config.get('cooldown_time', config.attack.cooldown_time)
            
            if 'cache' in yaml_data:
                cache_config = yaml_data['cache']
                config.cache.arp_cache_ttl = cache_config.get('arp_cache_ttl', config.cache.arp_cache_ttl)
                config.cache.attack_cache_ttl = cache_config.get('attack_cache_ttl', config.cache.attack_cache_ttl)
                config.cache.target_info_ttl = cache_config.get('target_info_ttl', config.cache.target_info_ttl)
            
            if 'logging' in yaml_data:
                log_config = yaml_data['logging']
                config.logging.level = log_config.get('level', config.logging.level)
                config.logging.file = log_config.get('file', config.logging.file)
                config.logging.max_size = log_config.get('max_size', config.logging.max_size)
                config.logging.backup_count = log_config.get('backup_count', config.logging.backup_count)
            
            if 'web_api' in yaml_data:
                api_config = yaml_data['web_api']
                config.web_api.enabled = api_config.get('enabled', config.web_api.enabled)
                config.web_api.port = api_config.get('port', config.web_api.port)
                config.web_api.host = api_config.get('host', config.web_api.host)
            
            if 'security' in yaml_data:
                sec_config = yaml_data['security']
                config.security.require_root = sec_config.get('require_root', config.security.require_root)
                config.security.bind_to_cpu = sec_config.get('bind_to_cpu', config.security.bind_to_cpu)
                config.security.memory_limit = sec_config.get('memory_limit', config.security.memory_limit)
            
            return config
            
        except Exception as e:
            print(f"错误: 无法加载配置文件 {config_file}: {e}")
            print("使用默认配置")
            return config
    
    def save_to_file(self, config_file: str):
        """保存配置到YAML文件"""
        config_dict = {
            'network': {
                'interface': self.network.interface,
                'gateway_ip': self.network.gateway_ip,
                'target_server': self.network.target_server,
                'target_ports': self.network.target_ports
            },
            'ipc': {
                'packet_address': self.ipc.packet_address,
                'command_address': self.ipc.command_address
            },
            'performance': {
                'max_worker_threads': self.performance.max_worker_threads,
                'packet_buffer_size': self.performance.packet_buffer_size,
                'command_timeout': self.performance.command_timeout
            },
            'attack': {
                'stealth_mode': self.attack.stealth_mode,
                'attack_timeout': self.attack.attack_timeout,
                'max_concurrent_attacks': self.attack.max_concurrent_attacks,
                'cooldown_time': self.attack.cooldown_time
            },
            'cache': {
                'arp_cache_ttl': self.cache.arp_cache_ttl,
                'attack_cache_ttl': self.cache.attack_cache_ttl,
                'target_info_ttl': self.cache.target_info_ttl
            },
            'logging': {
                'level': self.logging.level,
                'file': self.logging.file,
                'max_size': self.logging.max_size,
                'backup_count': self.logging.backup_count
            },
            'web_api': {
                'enabled': self.web_api.enabled,
                'port': self.web_api.port,
                'host': self.web_api.host
            },
            'security': {
                'require_root': self.security.require_root,
                'bind_to_cpu': self.security.bind_to_cpu,
                'memory_limit': self.security.memory_limit
            }
        }
        
        try:
            os.makedirs(os.path.dirname(config_file), exist_ok=True)
            with open(config_file, 'w', encoding='utf-8') as f:
                yaml.dump(config_dict, f, default_flow_style=False, indent=2)
            print(f"配置已保存到: {config_file}")
        except Exception as e:
            print(f"错误: 无法保存配置文件 {config_file}: {e}")
    
    def validate(self) -> List[str]:
        """验证配置的有效性，返回错误列表"""
        errors = []
        
        # 验证网络配置
        if not self.network.interface:
            errors.append("网络接口不能为空")
        
        if not self.network.gateway_ip:
            errors.append("网关IP不能为空")
        
        if not self.network.target_ports:
            errors.append("目标端口列表不能为空")
        
        # 验证性能配置
        if self.performance.max_worker_threads < 1:
            errors.append("工作线程数必须大于0")
        
        if self.performance.packet_buffer_size < 1024:
            errors.append("数据包缓冲区大小必须至少1KB")
        
        # 验证攻击配置
        if self.attack.attack_timeout < 1:
            errors.append("攻击超时时间必须大于0")
        
        if self.attack.max_concurrent_attacks < 1:
            errors.append("最大并发攻击数必须大于0")
        
        # 验证缓存配置
        if self.cache.arp_cache_ttl < 60:
            errors.append("ARP缓存TTL必须至少60秒")
        
        # 验证日志配置
        if self.logging.level not in ['DEBUG', 'INFO', 'WARNING', 'ERROR']:
            errors.append("日志级别必须是DEBUG、INFO、WARNING或ERROR之一")
        
        # 验证Web API配置
        if self.web_api.enabled and (self.web_api.port < 1 or self.web_api.port > 65535):
            errors.append("Web API端口必须在1-65535范围内")
        
        return errors
    
    def __str__(self) -> str:
        """配置信息的字符串表示"""
        return f"""ARP Spoofer Pro配置:
网络: {self.network.interface} -> {self.network.gateway_ip}
IPC: {self.ipc.packet_address}
性能: {self.performance.max_worker_threads} 线程
攻击: {self.attack.max_concurrent_attacks} 并发
缓存: ARP={self.cache.arp_cache_ttl}s
日志: {self.logging.level} -> {self.logging.file}
Web API: {'启用' if self.web_api.enabled else '禁用'}({self.web_api.port})"""
