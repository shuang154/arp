#!/usr/bin/env python3
"""
ARP Spoofer 性能诊断工具
=========================
实时监控系统性能指标，诊断捕获率和进程状态问题
"""

import time
import json
import subprocess
import threading
import argparse
from datetime import datetime
from collections import deque
import signal
import sys

class ARPSpooferDiagnostics:
    """ARP欺骗器诊断工具"""
    
    def __init__(self):
        self.running = False
        self.stats_history = deque(maxlen=60)  # 保存60秒历史
        self.last_stats = {}
        
    def get_process_stats(self):
        """获取进程统计信息"""
        stats = {
            'timestamp': time.time(),
            'processes': {},
            'memory': {},
            'network': {}
        }
        
        try:
            # 检查进程状态
            processes = ['arp_core', 'python.*main.py']
            for proc_pattern in processes:
                result = subprocess.run(['pgrep', '-f', proc_pattern], 
                                      capture_output=True, text=True)
                if result.returncode == 0:
                    pids = result.stdout.strip().split('\n')
                    stats['processes'][proc_pattern] = {
                        'pids': pids,
                        'count': len(pids),
                        'status': 'running'
                    }
                else:
                    stats['processes'][proc_pattern] = {
                        'pids': [],
                        'count': 0,
                        'status': 'stopped'
                    }
            
            # 获取内存使用
            result = subprocess.run(['free', '-m'], capture_output=True, text=True)
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                mem_line = lines[1].split()
                stats['memory'] = {
                    'total': int(mem_line[1]),
                    'used': int(mem_line[2]),
                    'free': int(mem_line[3]),
                    'usage_percent': round(int(mem_line[2]) / int(mem_line[1]) * 100, 2)
                }
            
            # 获取网络统计
            result = subprocess.run(['cat', '/proc/net/dev'], capture_output=True, text=True)
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')[2:]  # 跳过头部
                for line in lines:
                    parts = line.split()
                    if parts[0].startswith('wlan0') or parts[0].startswith('eth0'):
                        iface = parts[0].rstrip(':')
                        stats['network'][iface] = {
                            'rx_packets': int(parts[1]),
                            'rx_bytes': int(parts[2]),
                            'tx_packets': int(parts[9]),
                            'tx_bytes': int(parts[10])
                        }
                        break
                        
        except Exception as e:
            print(f"❌ 获取统计信息失败: {e}")
            
        return stats
    
    def calculate_rates(self, current_stats, previous_stats):
        """计算速率"""
        if not previous_stats:
            return {}
            
        time_diff = current_stats['timestamp'] - previous_stats['timestamp']
        if time_diff <= 0:
            return {}
            
        rates = {}
        
        # 计算网络速率
        for iface in current_stats.get('network', {}):
            if iface in previous_stats.get('network', {}):
                curr_net = current_stats['network'][iface]
                prev_net = previous_stats['network'][iface]
                
                rx_rate = (curr_net['rx_packets'] - prev_net['rx_packets']) / time_diff
                tx_rate = (curr_net['tx_packets'] - prev_net['tx_packets']) / time_diff
                
                rates[f'{iface}_rx_pps'] = round(rx_rate, 2)
                rates[f'{iface}_tx_pps'] = round(tx_rate, 2)
                
        return rates
    
    def print_dashboard(self, stats, rates):
        """打印实时仪表板"""
        # 清屏
        subprocess.run(['clear'])
        
        print("🎯 ARP Spoofer 实时性能监控")
        print("=" * 60)
        print(f"时间: {datetime.fromtimestamp(stats['timestamp']).strftime('%Y-%m-%d %H:%M:%S')}")
        print()
        
        # 进程状态
        print("📊 进程状态:")
        for proc_pattern, proc_info in stats['processes'].items():
            status_icon = "✅" if proc_info['status'] == 'running' else "❌"
            print(f"  {status_icon} {proc_pattern}: {proc_info['count']} 个进程")
            if proc_info['pids']:
                print(f"     PIDs: {', '.join(proc_info['pids'])}")
        print()
        
        # 内存状态
        if stats['memory']:
            mem = stats['memory']
            mem_icon = "⚠️" if mem['usage_percent'] > 80 else "✅"
            print(f"💾 内存使用: {mem_icon}")
            print(f"  已用: {mem['used']}MB / {mem['total']}MB ({mem['usage_percent']}%)")
            print(f"  可用: {mem['free']}MB")
        print()
        
        # 网络状态和性能
        print("🌐 网络性能:")
        for iface, net_info in stats['network'].items():
            print(f"  接口 {iface}:")
            print(f"    接收: {net_info['rx_packets']} 包, {net_info['rx_bytes']} 字节")
            print(f"    发送: {net_info['tx_packets']} 包, {net_info['tx_bytes']} 字节")
            
            # 显示速率
            rx_rate_key = f'{iface}_rx_pps'
            tx_rate_key = f'{iface}_tx_pps'
            if rx_rate_key in rates:
                rx_rate = rates[rx_rate_key]
                tx_rate = rates[tx_rate_key]
                
                # 性能警告
                rate_icon = "⚠️" if rx_rate < 1 and tx_rate < 1 else "✅"
                print(f"    实时速率 {rate_icon}: RX {rx_rate} pps, TX {tx_rate} pps")
        print()
        
        # 性能建议
        print("💡 性能建议:")
        if not any(proc['status'] == 'running' for proc in stats['processes'].values()):
            print("  ❌ 所有进程已停止 - 请检查服务状态")
        elif stats['memory'].get('usage_percent', 0) > 90:
            print("  ⚠️  内存使用率过高 - 考虑重启服务")
        elif all(rates.get(f'{iface}_rx_pps', 0) < 0.1 for iface in stats['network']):
            print("  ⚠️  网络活动很低 - 检查网络连接或攻击目标")
        else:
            print("  ✅ 系统运行正常")
            
        print("\n按 Ctrl+C 退出监控")
    
    def run_monitoring(self, interval=2):
        """运行实时监控"""
        self.running = True
        print("🚀 启动ARP Spoofer性能监控...")
        
        previous_stats = None
        
        try:
            while self.running:
                current_stats = self.get_process_stats()
                rates = self.calculate_rates(current_stats, previous_stats)
                
                self.print_dashboard(current_stats, rates)
                self.stats_history.append(current_stats)
                
                previous_stats = current_stats
                time.sleep(interval)
                
        except KeyboardInterrupt:
            print("\n🛑 监控已停止")
        finally:
            self.running = False
    
    def check_orphan_processes(self):
        """检查孤儿进程"""
        print("🔍 检查孤儿进程...")
        
        patterns = ['arp_core', 'python.*main.py', 'pcap']
        orphans_found = False
        
        for pattern in patterns:
            result = subprocess.run(['pgrep', '-f', pattern], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                pids = result.stdout.strip().split('\n')
                print(f"  发现 {pattern} 进程: {', '.join(pids)}")
                orphans_found = True
        
        if orphans_found:
            print("\n💡 清理命令:")
            print("  sudo pkill -f 'arp_core'")
            print("  sudo pkill -f 'python.*main.py'")
        else:
            print("  ✅ 没有发现孤儿进程")

def signal_handler(signum, frame):
    """信号处理器"""
    print(f"\n收到信号 {signum}，正在退出...")
    sys.exit(0)

def main():
    parser = argparse.ArgumentParser(description="ARP Spoofer诊断工具")
    parser.add_argument('-m', '--monitor', action='store_true', 
                       help='实时监控模式')
    parser.add_argument('-c', '--check-orphans', action='store_true',
                       help='检查孤儿进程')
    parser.add_argument('-i', '--interval', type=int, default=2,
                       help='监控间隔(秒)')
    
    args = parser.parse_args()
    
    # 设置信号处理
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    diagnostics = ARPSpooferDiagnostics()
    
    if args.check_orphans:
        diagnostics.check_orphan_processes()
    elif args.monitor:
        diagnostics.run_monitoring(args.interval)
    else:
        print("请指定操作模式:")
        print("  -m, --monitor     实时监控")
        print("  -c, --check-orphans  检查孤儿进程")
        parser.print_help()

if __name__ == "__main__":
    main()
