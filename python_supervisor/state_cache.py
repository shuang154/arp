"""
状态缓存管理器 - 使用TTL缓存实现智能状态管理
=============================================
功能：
1. 管理已攻击目标的状态（避免重复攻击）
2. 管理正在进行的攻击任务
3. 缓存ARP信息以提高性能
4. 自动过期清理，避免内存泄漏
"""

import threading
import time
from typing import Dict, Set, Optional, Any
from dataclasses import dataclass
from cachetools import TTLCache
from collections import defaultdict

@dataclass
class TargetInfo:
    """目标信息"""
    ip: str
    mac: str
    first_seen: float
    last_seen: float
    attack_count: int = 0
    successful_attacks: int = 0
    last_attack_time: float = 0

@dataclass
class AttackSession:
    """攻击会话信息"""
    target_ip: str
    start_time: float
    duration: int
    attack_type: str
    status: str = 'active'  # active, completed, failed

class StateCache:
    """状态缓存管理器"""
    
    def __init__(self):
        # TTL缓存 - 自动过期的状态存储
        self.successful_attacks = TTLCache(maxsize=10000, ttl=3600)  # 1小时后忘记成功的攻击
        self.active_attacks = TTLCache(maxsize=1000, ttl=300)        # 5分钟后清理活跃攻击
        self.arp_cache = TTLCache(maxsize=50000, ttl=1800)           # 30分钟ARP缓存
        self.target_info = TTLCache(maxsize=10000, ttl=7200)         # 2小时目标信息缓存
        
        # 🚀 新增：凭据去重缓存 (防止重复保存同一用户的凭据)
        self.saved_credentials = TTLCache(maxsize=5000, ttl=1800)    # 30分钟凭据缓存
        
        # 线程锁
        self.successful_attacks_lock = threading.RLock()
        self.active_attacks_lock = threading.RLock()
        self.arp_cache_lock = threading.RLock()
        self.target_info_lock = threading.RLock()
        
        # 🚀 新增：凭据缓存锁
        self.saved_credentials_lock = threading.RLock()
        
        # 统计信息
        self.stats = {
            'cache_hits': 0,
            'cache_misses': 0,
            'attacks_blocked': 0,
            'arp_queries': 0,
            'total_attacks': 0
        }
        self.stats_lock = threading.Lock()
        
        # 攻击会话历史
        self.attack_sessions: Dict[str, AttackSession] = {}
        self.sessions_lock = threading.Lock()
        
    def is_target_recently_successful(self, ip: str) -> bool:
        """检查目标是否最近已被成功攻击"""
        with self.successful_attacks_lock:
            result = ip in self.successful_attacks
            
        with self.stats_lock:
            if result:
                self.stats['cache_hits'] += 1
                self.stats['attacks_blocked'] += 1
            else:
                self.stats['cache_misses'] += 1
                
        return result
    
    def has_credentials_saved(self, credential_key: str) -> bool:
        """检查凭据是否已保存（防重复）"""
        with self.saved_credentials_lock:
            return credential_key in self.saved_credentials
    
    def mark_credentials_saved(self, credential_key: str):
        """标记凭据已保存"""
        with self.saved_credentials_lock:
            self.saved_credentials[credential_key] = time.time()
        
    def mark_attack_successful(self, ip: str, credentials_captured: bool = False):
        """标记攻击成功"""
        current_time = time.time()
        
        with self.successful_attacks_lock:
            self.successful_attacks[ip] = {
                'timestamp': current_time,
                'credentials_captured': credentials_captured
            }
            
        # 更新目标信息
        self._update_target_info(ip, successful_attack=True)
        
        with self.stats_lock:
            self.stats['total_attacks'] += 1
            
    def is_target_under_attack(self, ip: str) -> bool:
        """检查目标是否正在被攻击"""
        with self.active_attacks_lock:
            return ip in self.active_attacks
            
    def start_attack_session(self, ip: str, duration: int, attack_type: str = 'standard'):
        """开始攻击会话"""
        current_time = time.time()
        
        with self.active_attacks_lock:
            self.active_attacks[ip] = current_time
            
        # 记录攻击会话
        session = AttackSession(
            target_ip=ip,
            start_time=current_time,
            duration=duration,
            attack_type=attack_type
        )
        
        with self.sessions_lock:
            self.attack_sessions[ip] = session
            
    def end_attack_session(self, ip: str, success: bool = False):
        """结束攻击会话"""
        with self.active_attacks_lock:
            if ip in self.active_attacks:
                del self.active_attacks[ip]
                
        # 更新会话状态
        with self.sessions_lock:
            if ip in self.attack_sessions:
                session = self.attack_sessions[ip]
                session.status = 'completed' if success else 'failed'
                
        if success:
            self.mark_attack_successful(ip)
            
    def cache_arp_info(self, ip: str, mac: str):
        """缓存ARP信息"""
        with self.arp_cache_lock:
            self.arp_cache[ip] = {
                'mac': mac,
                'timestamp': time.time()
            }
            
        with self.stats_lock:
            self.stats['arp_queries'] += 1
            
    def get_cached_mac(self, ip: str) -> Optional[str]:
        """获取缓存的MAC地址"""
        with self.arp_cache_lock:
            arp_info = self.arp_cache.get(ip)
            if arp_info:
                with self.stats_lock:
                    self.stats['cache_hits'] += 1
                return arp_info['mac']
                
        with self.stats_lock:
            self.stats['cache_misses'] += 1
        return None
        
    def _update_target_info(self, ip: str, successful_attack: bool = False):
        """更新目标信息"""
        current_time = time.time()
        
        with self.target_info_lock:
            if ip in self.target_info:
                target = self.target_info[ip]
                target.last_seen = current_time
                target.attack_count += 1
                if successful_attack:
                    target.successful_attacks += 1
                    target.last_attack_time = current_time
            else:
                # 新目标，创建信息记录
                self.target_info[ip] = TargetInfo(
                    ip=ip,
                    mac='',  # MAC稍后更新
                    first_seen=current_time,
                    last_seen=current_time,
                    attack_count=1,
                    successful_attacks=1 if successful_attack else 0,
                    last_attack_time=current_time if successful_attack else 0
                )
                
    def get_target_info(self, ip: str) -> Optional[TargetInfo]:
        """获取目标信息"""
        with self.target_info_lock:
            return self.target_info.get(ip)
            
    def should_attack_target(self, ip: str) -> bool:
        """判断是否应该攻击目标"""
        # 检查是否最近已成功攻击
        if self.is_target_recently_successful(ip):
            return False
            
        # 检查是否正在被攻击
        if self.is_target_under_attack(ip):
            return False
            
        # 检查攻击频率限制
        target_info = self.get_target_info(ip)
        if target_info:
            # 如果攻击次数过多，延长冷却时间
            if target_info.attack_count > 5:
                cooldown_time = 3600  # 1小时冷却
                if time.time() - target_info.last_attack_time < cooldown_time:
                    return False
                    
        return True
        
    def get_active_attacks(self) -> Dict[str, float]:
        """获取当前活跃的攻击"""
        with self.active_attacks_lock:
            return dict(self.active_attacks)
            
    def get_successful_attacks(self) -> Dict[str, Dict]:
        """获取成功的攻击记录"""
        with self.successful_attacks_lock:
            return dict(self.successful_attacks)
            
    def get_attack_sessions(self) -> Dict[str, AttackSession]:
        """获取攻击会话历史"""
        with self.sessions_lock:
            return dict(self.attack_sessions)
            
    def get_statistics(self) -> Dict[str, Any]:
        """获取缓存统计信息"""
        with self.stats_lock:
            stats = dict(self.stats)
            
        # 添加缓存大小信息
        with self.successful_attacks_lock:
            stats['successful_attacks_count'] = len(self.successful_attacks)
        with self.active_attacks_lock:
            stats['active_attacks_count'] = len(self.active_attacks)
        with self.arp_cache_lock:
            stats['arp_cache_count'] = len(self.arp_cache)
        with self.target_info_lock:
            stats['target_info_count'] = len(self.target_info)
        with self.saved_credentials_lock:
            stats['saved_credentials_count'] = len(self.saved_credentials)
        with self.sessions_lock:
            stats['attack_sessions_count'] = len(self.attack_sessions)
        with self.arp_cache_lock:
            stats['arp_cache_count'] = len(self.arp_cache)
        with self.target_info_lock:
            stats['target_info_count'] = len(self.target_info)
            
        # 计算命中率
        total_queries = stats['cache_hits'] + stats['cache_misses']
        if total_queries > 0:
            stats['hit_rate'] = (stats['cache_hits'] / total_queries) * 100
        else:
            stats['hit_rate'] = 0
            
        stats['total_entries'] = (stats['successful_attacks_count'] + 
                                 stats['active_attacks_count'] + 
                                 stats['arp_cache_count'] + 
                                 stats['target_info_count'])
                                 
        return stats
        
    def cleanup_expired_entries(self):
        """手动清理过期条目（TTLCache会自动处理，这里用于强制清理）"""
        current_time = time.time()
        
        # 清理过期的攻击会话
        with self.sessions_lock:
            expired_sessions = []
            for ip, session in self.attack_sessions.items():
                if current_time - session.start_time > session.duration + 300:  # 额外5分钟缓冲
                    expired_sessions.append(ip)
                    
            for ip in expired_sessions:
                del self.attack_sessions[ip]
                
        return len(expired_sessions)
        
    def clear_all_caches(self):
        """清空所有缓存（用于测试或重置）"""
        with self.successful_attacks_lock:
            self.successful_attacks.clear()
        with self.active_attacks_lock:
            self.active_attacks.clear()
        with self.arp_cache_lock:
            self.arp_cache.clear()
        with self.target_info_lock:
            self.target_info.clear()
        with self.saved_credentials_lock:
            self.saved_credentials.clear()
        with self.sessions_lock:
            self.attack_sessions.clear()
            
        # 清零统计
        with self.stats_lock:
            for key in self.stats:
                self.stats[key] = 0
