"""
极简攻击协调器 - 专为香橙派3B优化
=====================================
完全移除复杂控制机制，直接高效运行
"""

import logging
import time
import threading
from dataclasses import dataclass
from typing import Optional, Callable, Dict, Any

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

class UltraSimpleAttackCoordinator:
    """
    极简攻击协调器 - 零复杂度版本
    ===========================
    
    只有三个核心机制：
    1. 信号量限制最大并发攻击数
    2. 简单计数器限流 (每秒最多X个新攻击)
    3. 活跃攻击字典跟踪
    
    移除的复杂机制：
    - Scout/Attack分离
    - 令牌桶算法
    - 复杂去重逻辑
    - 缓冲池和队列
    - 自适应流控
    - 状态缓存
    - 分阶段并发控制
    """
    
    def __init__(self, config, attack_callback: Callable):
        self.config = config
        self.attack_callback = attack_callback
        self.logger = logging.getLogger(__name__)
        
        # 三个核心控制机制
        max_concurrent = getattr(config, 'max_concurrent_attacks', 15)
        self.attack_semaphore = threading.Semaphore(max_concurrent)
        
        max_per_second = getattr(config, 'max_attacks_per_second', 8)
        self.attack_count = 0
        self.last_reset_time = time.time()
        self.rate_lock = threading.Lock()
        
        self.active_attacks = {}  # {target_ip: start_time}
        self.active_lock = threading.Lock()
        
        # 运行状态
        self.running = True
        self.stats = {
            'total_decisions': 0,
            'attacks_launched': 0,
            'rate_limited': 0,
            'concurrent_limited': 0
        }
        
        self.logger.info(f"🚀 极简协调器启动 - 最大并发:{max_concurrent}, 限流:{max_per_second}/s")
    
    def initialize(self, command_sender: Callable) -> bool:
        """初始化协调器 - 兼容性方法"""
        self.command_sender = command_sender
        self.logger.info("✅ 极简协调器初始化完成")
        return True
    
    def make_decision(self, analysis_result) -> Optional[AttackDecision]:
        """
        攻击决策 - 极简版本
        只做最基本的检查，不进行复杂分析
        """
        self.stats['total_decisions'] += 1
        
        # 获取目标IP
        target_ip = getattr(analysis_result, 'src_ip', None) or getattr(analysis_result, 'source_ip', None)
        
        # 1. 基本有效性检查
        if not target_ip or target_ip == "0.0.0.0":
            return None
            
        # 2. 检查是否已在攻击
        with self.active_lock:
            if target_ip in self.active_attacks:
                return None
        
        # 3. 限流检查
        if not self._check_rate_limit():
            self.stats['rate_limited'] += 1
            return None
        
        # 4. 并发检查 (非阻塞)
        if not self.attack_semaphore.acquire(blocking=False):
            self.stats['concurrent_limited'] += 1
            return None
        
        # 记录活跃攻击
        with self.active_lock:
            self.active_attacks[target_ip] = time.time()
        
        # 设置攻击清理定时器
        threading.Timer(50.0, self._cleanup_attack, args=[target_ip]).start()
        
        # 直接调用攻击回调
        decision = AttackDecision(
            action='attack',
            target_ip=target_ip,
            gateway_ip=getattr(analysis_result, 'gateway_ip', '192.168.1.1'),
            duration=45,
            reason='direct_attack'
        )
        
        # 异步执行攻击
        threading.Thread(
            target=self._execute_attack,
            args=(decision,),
            daemon=True
        ).start()
        
        self.stats['attacks_launched'] += 1
        self.logger.info(f"🎯 直接攻击 {target_ip} (活跃:{len(self.active_attacks)})")
        return decision
    
    def _execute_attack(self, decision: AttackDecision):
        """执行攻击"""
        try:
            self.attack_callback(decision)
        except Exception as e:
            self.logger.error(f"❌ 攻击执行失败 {decision.target_ip}: {e}")
    
    def _cleanup_attack(self, target_ip: str):
        """清理攻击状态"""
        try:
            with self.active_lock:
                self.active_attacks.pop(target_ip, None)
            
            # 释放信号量
            self.attack_semaphore.release()
            
            self.logger.debug(f"🧹 清理攻击状态: {target_ip}")
        except Exception as e:
            self.logger.error(f"清理攻击状态错误: {e}")
    
    def _check_rate_limit(self) -> bool:
        """
        检查限流 - 简单计数器实现
        """
        max_per_second = getattr(self.config, 'max_attacks_per_second', 8)
        
        with self.rate_lock:
            current_time = time.time()
            
            # 每秒重置计数器
            if current_time - self.last_reset_time >= 1.0:
                self.attack_count = 0
                self.last_reset_time = current_time
            
            # 检查是否超过限制
            if self.attack_count >= max_per_second:
                return False
            
            self.attack_count += 1
            return True
    
    def get_status(self) -> Dict[str, Any]:
        """获取状态信息"""
        with self.active_lock:
            active_count = len(self.active_attacks)
        
        return {
            'type': 'ultra_simple',
            'active_attacks': active_count,
            'available_slots': self.attack_semaphore._value,
            'stats': self.stats.copy()
        }
    
    def cleanup(self):
        """清理资源"""
        self.running = False
        
        # 等待所有攻击完成
        active_count = len(self.active_attacks)
        if active_count > 0:
            self.logger.info(f"🕐 等待 {active_count} 个攻击完成...")
            
            # 最多等待60秒
            for _ in range(60):
                with self.active_lock:
                    if not self.active_attacks:
                        break
                time.sleep(1)
        
        self.logger.info("🛑 极简协调器已关闭")

# 为了兼容性，保留原有的类名
class SimpleAttackCoordinator(UltraSimpleAttackCoordinator):
    """兼容性别名"""
    def __init__(self, config, state_cache=None):
        # 忽略state_cache参数，极简版本不需要
        super().__init__(config, self._dummy_callback)
    
    def _dummy_callback(self, decision):
        """占位回调，由外部设置真正的回调"""
        pass

class AttackCoordinator(UltraSimpleAttackCoordinator):
    """兼容性别名"""
    pass
