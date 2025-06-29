"""
动态自适应流量控制组件
====================

实现基于下游压力的动态令牌桶，以及任务缓冲池管理
"""

import time
import threading
from queue import Queue, Full, Empty
from typing import Optional, Any
from collections import deque
import logging


class DynamicTokenBucket:
    """动态令牌桶 - 根据下游压力自适应调节流量"""
    
    def __init__(self, initial_rate: float = 50.0, capacity: int = 100, min_rate: float = 1.0, max_rate: float = 100.0):
        """
        初始化动态令牌桶
        
        Args:
            initial_rate: 初始令牌生成速率（每秒）
            capacity: 令牌桶容量
            min_rate: 最小速率
            max_rate: 最大速率
        """
        self.rate = initial_rate  # 当前令牌生成速率 - 可动态调整
        self.capacity = capacity
        self.min_rate = min_rate
        self.max_rate = max_rate
        
        self._tokens = float(capacity)  # 当前令牌数
        self._last_time = time.time()
        self._lock = threading.Lock()
        
        self.logger = logging.getLogger(f"{__name__}.DynamicTokenBucket")
        
        # 统计信息
        self.stats = {
            'tokens_granted': 0,
            'tokens_denied': 0,
            'rate_adjustments': 0,
            'last_rate_change': time.time()
        }
        
    def get_token(self) -> bool:
        """
        尝试获取一个令牌
        
        Returns:
            bool: 是否成功获取令牌
        """
        with self._lock:
            current_time = time.time()
            
            # 生成新令牌
            time_passed = current_time - self._last_time
            new_tokens = time_passed * self.rate
            self._tokens = min(self.capacity, self._tokens + new_tokens)
            self._last_time = current_time
            
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                self.stats['tokens_granted'] += 1
                return True
            else:
                self.stats['tokens_denied'] += 1
                return False
    
    def adjust_rate(self, new_rate: float, reason: str = ""):
        """
        动态调整令牌生成速率
        
        Args:
            new_rate: 新的速率
            reason: 调整原因（用于日志）
        """
        new_rate = max(self.min_rate, min(self.max_rate, new_rate))
        
        with self._lock:
            if abs(new_rate - self.rate) > 0.1:  # 只有显著变化才记录
                old_rate = self.rate
                self.rate = new_rate
                self.stats['rate_adjustments'] += 1
                self.stats['last_rate_change'] = time.time()
                
                self.logger.debug(f"Rate adjusted: {old_rate:.1f} -> {new_rate:.1f} ({reason})")
    
    def get_status(self) -> dict:
        """获取令牌桶状态"""
        with self._lock:
            return {
                'current_rate': self.rate,
                'tokens': self._tokens,
                'capacity': self.capacity,
                'stats': dict(self.stats)
            }


class TaskBufferPool:
    """任务缓冲池 - 实现"弃老保新"策略的有界队列"""
    
    def __init__(self, maxsize: int = 100, name: str = "TaskBuffer"):
        """
        初始化任务缓冲池
        
        Args:
            maxsize: 最大缓冲任务数
            name: 缓冲池名称（用于日志）
        """
        self.queue = Queue(maxsize=maxsize)
        self.maxsize = maxsize
        self.name = name
        self.logger = logging.getLogger(f"{__name__}.{name}")
        
        # 统计信息
        self.stats = {
            'tasks_added': 0,
            'tasks_processed': 0,
            'tasks_discarded': 0,  # 因为队列满而丢弃的任务
            'old_tasks_evicted': 0,  # 被新任务挤掉的老任务
        }
        self._stats_lock = threading.Lock()
    
    def put_task(self, task: Any, timeout: Optional[float] = None) -> bool:
        """
        放入任务，实现"弃老保新"策略
        
        Args:
            task: 要放入的任务
            timeout: 超时时间
            
        Returns:
            bool: 是否成功放入任务
        """
        try:
            # 首先尝试直接放入
            self.queue.put_nowait(task)
            with self._stats_lock:
                self.stats['tasks_added'] += 1
            return True
            
        except Full:
            # 队列满了，执行"弃老保新"策略
            try:
                # 1. 尝试取出最老的任务
                old_task = self.queue.get_nowait()
                with self._stats_lock:
                    self.stats['old_tasks_evicted'] += 1
                
                # 2. 再次尝试放入新任务
                self.queue.put_nowait(task)
                with self._stats_lock:
                    self.stats['tasks_added'] += 1
                
                self.logger.debug(f"Evicted old task to make room for new task in {self.name}")
                return True
                
            except (Full, Empty):
                # 极低概率下的竞态条件，直接丢弃
                with self._stats_lock:
                    self.stats['tasks_discarded'] += 1
                self.logger.warning(f"Failed to add task to {self.name} - buffer pool conflict")
                return False
    
    def get_task(self, timeout: Optional[float] = 1.0) -> Optional[Any]:
        """
        获取任务
        
        Args:
            timeout: 超时时间
            
        Returns:
            任务对象或None
        """
        try:
            task = self.queue.get(timeout=timeout)
            with self._stats_lock:
                self.stats['tasks_processed'] += 1
            return task
        except Empty:
            return None
    
    def qsize(self) -> int:
        """获取当前队列长度"""
        return self.queue.qsize()
    
    def get_stats(self) -> dict:
        """获取统计信息"""
        with self._stats_lock:
            return {
                'current_size': self.qsize(),
                'max_size': self.maxsize,
                'utilization': (self.qsize() / self.maxsize) * 100,
                'stats': dict(self.stats)
            }


class AdaptiveFlowController:
    """自适应流量控制器 - 将令牌桶和缓冲池结合的智能调节器"""
    
    def __init__(self, 
                 initial_rate: float = 50.0, 
                 buffer_size: int = 100,
                 name: str = "FlowController"):
        """
        初始化自适应流量控制器
        
        Args:
            initial_rate: 初始令牌速率
            buffer_size: 缓冲池大小
            name: 控制器名称
        """
        self.name = name
        self.logger = logging.getLogger(f"{__name__}.{name}")
        
        # 创建令牌桶和缓冲池
        self.token_bucket = DynamicTokenBucket(initial_rate=initial_rate)
        self.buffer_pool = TaskBufferPool(maxsize=buffer_size, name=f"{name}Buffer")
        
        # 自适应控制参数
        self.high_pressure_threshold = buffer_size * 0.75  # 75%为高压线
        self.low_pressure_threshold = buffer_size * 0.30   # 30%为低压线
        self.normal_rate = initial_rate
        self.restricted_rate = initial_rate * 0.2  # 限制状态下降到20%
        
        # 控制状态
        self.current_state = "normal"  # normal, restricted, recovering
        self.last_adjustment_time = time.time()
        self.min_adjustment_interval = 2.0  # 最小调整间隔（秒）
        
    def should_process_packet(self) -> bool:
        """
        判断是否应该处理新数据包（前端流量控制）
        
        Returns:
            bool: 是否允许处理
        """
        # 检查缓冲池压力并动态调整令牌桶
        self._adjust_flow_based_on_pressure()
        
        # 使用令牌桶进行流量控制
        return self.token_bucket.get_token()
    
    def submit_task(self, task: Any) -> bool:
        """
        提交任务到缓冲池
        
        Args:
            task: 要提交的任务
            
        Returns:
            bool: 是否成功提交
        """
        return self.buffer_pool.put_task(task)
    
    def get_task(self, timeout: Optional[float] = 1.0) -> Optional[Any]:
        """
        从缓冲池获取任务
        
        Args:
            timeout: 超时时间
            
        Returns:
            任务对象或None
        """
        return self.buffer_pool.get_task(timeout)
    
    def _adjust_flow_based_on_pressure(self):
        """根据缓冲池压力动态调整流量"""
        current_time = time.time()
        
        # 避免频繁调整
        if current_time - self.last_adjustment_time < self.min_adjustment_interval:
            return
        
        buffer_size = self.buffer_pool.qsize()
        
        # 状态转换逻辑
        if buffer_size >= self.high_pressure_threshold:
            if self.current_state != "restricted":
                self.current_state = "restricted"
                self.token_bucket.adjust_rate(self.restricted_rate, f"buffer pressure: {buffer_size}")
                self.last_adjustment_time = current_time
                self.logger.warning(f"Flow restricted due to high buffer pressure: {buffer_size}/{self.buffer_pool.maxsize}")
                
        elif buffer_size <= self.low_pressure_threshold:
            if self.current_state != "normal":
                self.current_state = "normal"
                self.token_bucket.adjust_rate(self.normal_rate, f"buffer pressure relieved: {buffer_size}")
                self.last_adjustment_time = current_time
                self.logger.info(f"Flow normalized, buffer pressure relieved: {buffer_size}/{self.buffer_pool.maxsize}")
    
    def get_comprehensive_stats(self) -> dict:
        """获取完整的统计信息"""
        return {
            'flow_state': self.current_state,
            'token_bucket': self.token_bucket.get_status(),
            'buffer_pool': self.buffer_pool.get_stats(),
            'thresholds': {
                'high_pressure': self.high_pressure_threshold,
                'low_pressure': self.low_pressure_threshold,
                'normal_rate': self.normal_rate,
                'restricted_rate': self.restricted_rate
            }
        }
