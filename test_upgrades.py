#!/usr/bin/env python3
"""
测试升级后的系统功能
"""

import sys
import os
sys.path.append('python_supervisor')

from config import Config

def test_config_loading():
    """测试配置加载"""
    print("=" * 60)
    print("🧪 测试配置加载功能")
    print("=" * 60)
    
    try:
        config = Config.load_from_file('config/config.yaml')
        
        print("✅ 基本配置加载成功")
        print(f"   网络接口: {config.network.interface}")
        print(f"   网关IP: {config.network.gateway_ip}")
        print(f"   目标服务器: {config.network.target_server}")
        
        print("\n✅ 分级攻击策略配置:")
        print(f"   侦察持续时间: {config.attack.strategy.scouting_duration}s")
        print(f"   全面攻击持续时间: {config.attack.strategy.full_attack_duration}s")
        print(f"   高价值端口: {config.attack.strategy.high_value_ports}")
        print(f"   立即恢复: {config.attack.strategy.immediate_restore_on_success}")
        
        return True
        
    except Exception as e:
        print(f"❌ 配置加载失败: {e}")
        return False

def test_state_cache():
    """测试状态缓存功能"""
    print("\n" + "=" * 60)
    print("🧪 测试状态缓存功能")
    print("=" * 60)
    
    try:
        sys.path.append('python_supervisor')
        from state_cache import StateCache
        
        cache = StateCache()
        
        # 测试攻击会话管理
        test_ip = "192.168.1.100"
        
        print("✅ 测试侦察会话...")
        cache.start_attack_session(test_ip, 60, 'scouting')
        
        attack_info = cache.get_attack_info(test_ip)
        if attack_info:
            print(f"   攻击类型: {attack_info['attack_type']}")
            print(f"   持续时间: {attack_info['duration']}s")
            print(f"   状态: {attack_info['status']}")
        
        print("✅ 测试攻击升级...")
        cache.upgrade_attack_session(test_ip, 1800, 'full_attack')
        
        attack_info = cache.get_attack_info(test_ip)
        if attack_info:
            print(f"   升级后攻击类型: {attack_info['attack_type']}")
            print(f"   升级后持续时间: {attack_info['duration']}s")
        
        print("✅ 状态缓存功能正常")
        return True
        
    except Exception as e:
        print(f"❌ 状态缓存测试失败: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_attack_coordinator():
    """测试攻击协调器"""
    print("\n" + "=" * 60)
    print("🧪 测试攻击协调器功能")
    print("=" * 60)
    
    try:
        from config import Config
        from state_cache import StateCache
        from attack_coordinator import AttackCoordinator
        
        config = Config.load_from_file('config/config.yaml')
        cache = StateCache()
        coordinator = AttackCoordinator(config, cache)
        
        print("✅ 攻击协调器初始化成功")
        
        # 测试高价值事件检测
        print("✅ 测试高价值事件检测...")
        
        # 测试目标服务器访问
        is_high_value_1 = coordinator._is_high_value_event("121.248.150.37", 80)
        print(f"   访问目标服务器: {is_high_value_1}")
        
        # 测试高价值端口访问
        is_high_value_2 = coordinator._is_high_value_event("192.168.1.1", 801)
        print(f"   访问高价值端口801: {is_high_value_2}")
        
        # 测试普通流量
        is_high_value_3 = coordinator._is_high_value_event("8.8.8.8", 53)
        print(f"   普通DNS流量: {is_high_value_3}")
        
        print("✅ 攻击协调器功能正常")
        return True
        
    except Exception as e:
        print(f"❌ 攻击协调器测试失败: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """主测试函数"""
    print("🚀 ARP Spoofer Pro V2.0 - 分级递进式攻击系统测试")
    print("测试日期:", "2025年6月27日")
    print()
    
    all_passed = True
    
    # 运行所有测试
    all_passed &= test_config_loading()
    all_passed &= test_state_cache()
    all_passed &= test_attack_coordinator()
    
    print("\n" + "=" * 60)
    if all_passed:
        print("🎉 所有测试通过！系统升级成功！")
        print("您的分级递进式攻击系统已准备就绪。")
        print("\n主要功能:")
        print("• 🕵️ 智能侦察模式 (60秒窗口)")
        print("• 🎯 高价值事件检测与攻击升级")
        print("• 🏆 凭据捕获后立即撤退")
        print("• ⏰ 自动定时器管理")
        print("• 🧠 智能缓存与决策")
    else:
        print("❌ 部分测试失败，请检查配置和代码。")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())
