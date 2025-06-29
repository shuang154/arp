"""
极简状态缓存 - 专为香橙派3B优化
=================================
移除所有复杂缓存机制，只保留最基本功能
"""

import threading
import time
from typing import Dict, Set, Optional, Any

class StateCache:
    """极简状态缓存管理器"""
    
    def __init__(self):
        # 最简单的内存存储
        self.active_attacks = {}  # {target_ip: start_time}
        self.successful_attacks = set()  # {target_ip, ...}
        self.stats = {
            'total_attacks': 0,
            'successful_attacks': 0,
            'active_attacks': 0
        }
        self.lock = threading.Lock()
        
    def should_attack_target(self, target_ip: str) -> bool:
        """判断是否应该攻击目标 - 极简版本"""
        with self.lock:
            # 简单检查：如果正在攻击则不重复攻击
            return target_ip not in self.active_attacks
    
    def start_attack_session(self, target_ip: str, duration: int = 45, attack_type: str = "standard"):
        """开始攻击会话"""
        with self.lock:
            self.active_attacks[target_ip] = time.time()
            self.stats['active_attacks'] = len(self.active_attacks)
            self.stats['total_attacks'] += 1
    
    def end_attack_session(self, target_ip: str, success: bool = True):
        """结束攻击会话"""
        with self.lock:
            if target_ip in self.active_attacks:
                del self.active_attacks[target_ip]
                if success:
                    self.successful_attacks.add(target_ip)
                    self.stats['successful_attacks'] = len(self.successful_attacks)
            self.stats['active_attacks'] = len(self.active_attacks)
    
    def get_active_attacks(self) -> Dict[str, float]:
        """获取活跃攻击"""
        with self.lock:
            return self.active_attacks.copy()
    
    def get_successful_attacks(self) -> Set[str]:
        """获取成功攻击"""
        with self.lock:
            return self.successful_attacks.copy()
    
    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息"""
        with self.lock:
            return self.stats.copy()
    
    def get_attack_sessions(self) -> Dict[str, Dict]:
        """获取攻击会话 - 简化版本"""
        with self.lock:
            sessions = {}
            for target_ip, start_time in self.active_attacks.items():
                sessions[target_ip] = {
                    'target_ip': target_ip,
                    'start_time': start_time,
                    'duration': time.time() - start_time,
                    'status': 'active'
                }
            return sessions
    
    def cleanup_expired(self):
        """清理过期会话"""
        current_time = time.time()
        with self.lock:
            # 清理超过5分钟的活跃攻击
            expired = [ip for ip, start_time in self.active_attacks.items() 
                      if current_time - start_time > 300]
            for ip in expired:
                del self.active_attacks[ip]
            
            self.stats['active_attacks'] = len(self.active_attacks)
    
    def get_cached_mac(self, ip: str) -> Optional[str]:
        """获取缓存的MAC地址 - 占位方法"""
        return None
    
    def cache_mac(self, ip: str, mac: str):
        """缓存MAC地址 - 占位方法"""
        pass
    
    def has_credentials_saved(self, credential_key: str) -> bool:
        """检查凭据是否已保存 - 占位方法"""
        return False
    
    def mark_credentials_saved(self, credential_key: str):
        """标记凭据已保存 - 占位方法"""
        pass
