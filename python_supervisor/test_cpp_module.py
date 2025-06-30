#!/usr/bin/env python3
"""
C++ Module Diagnostic Script
测试C++模块是否正确编译和绑定
"""

import sys
import os

def test_cpp_module():
    """测试C++模块的可用性"""
    print("🔍 C++ Module Diagnostic Test")
    print("=" * 50)
    
    try:
        import arp_core_cpp
        print("✅ Module import successful")
        
        # 检查模块属性
        print(f"📦 Version: {getattr(arp_core_cpp, '__version__', 'N/A')}")
        print(f"📋 Description: {getattr(arp_core_cpp, '__description__', 'N/A')}")
        
        # 列出所有属性
        print("\n📚 All module attributes:")
        all_attrs = dir(arp_core_cpp)
        public_attrs = [attr for attr in all_attrs if not attr.startswith('_')]
        private_attrs = [attr for attr in all_attrs if attr.startswith('_')]
        
        print(f"  Public attributes ({len(public_attrs)}):")
        for attr in public_attrs:
            try:
                obj = getattr(arp_core_cpp, attr)
                obj_type = type(obj).__name__
                print(f"    - {attr}: {obj_type}")
            except Exception as e:
                print(f"    - {attr}: Error accessing ({e})")
        
        print(f"  Private attributes ({len(private_attrs)}):")
        for attr in private_attrs[:5]:  # 只显示前5个
            print(f"    - {attr}")
        if len(private_attrs) > 5:
            print(f"    ... and {len(private_attrs) - 5} more")
        
        # 测试关键类
        print("\n🔧 Testing key classes:")
        test_classes = ['ARPSpoofer', 'PacketSniffer', 'ThreadPool']
        
        for cls_name in test_classes:
            if hasattr(arp_core_cpp, cls_name):
                try:
                    cls = getattr(arp_core_cpp, cls_name)
                    print(f"  ✅ {cls_name}: Available ({type(cls).__name__})")
                    
                    # 尝试创建实例（仅用于测试类构造函数）
                    if cls_name == 'ARPSpoofer':
                        try:
                            instance = cls("test_interface")
                            print(f"      ✅ Constructor works")
                            del instance
                        except Exception as e:
                            print(f"      ⚠️ Constructor failed: {e}")
                    elif cls_name == 'PacketSniffer':
                        try:
                            instance = cls("test_interface")
                            print(f"      ✅ Constructor works")
                            del instance
                        except Exception as e:
                            print(f"      ⚠️ Constructor failed: {e}")
                    elif cls_name == 'ThreadPool':
                        try:
                            instance = cls(2)
                            print(f"      ✅ Constructor works")
                            del instance
                        except Exception as e:
                            print(f"      ⚠️ Constructor failed: {e}")
                            
                except Exception as e:
                    print(f"  ❌ {cls_name}: Error accessing ({e})")
            else:
                print(f"  ❌ {cls_name}: Not found")
        
        # 测试工具函数
        print("\n🛠️ Testing utility functions:")
        util_funcs = ['get_timestamp_ms', 'mac_to_string']
        for func_name in util_funcs:
            if hasattr(arp_core_cpp, func_name):
                try:
                    func = getattr(arp_core_cpp, func_name)
                    print(f"  ✅ {func_name}: Available")
                    
                    # 简单测试
                    if func_name == 'get_timestamp_ms':
                        result = func()
                        print(f"      Test result: {result} (type: {type(result).__name__})")
                    elif func_name == 'mac_to_string':
                        # 测试MAC地址转换
                        test_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]
                        result = func(test_mac)
                        print(f"      Test result: {result} (type: {type(result).__name__})")
                        
                except Exception as e:
                    print(f"  ⚠️ {func_name}: Error testing ({e})")
            else:
                print(f"  ❌ {func_name}: Not found")
        
        print("\n" + "=" * 50)
        print("🎯 Module diagnostic complete")
        return True
        
    except ImportError as e:
        print(f"❌ Failed to import module: {e}")
        print("\n💡 Troubleshooting steps:")
        print("1. Check if the module was compiled successfully")
        print("2. Verify the module file exists in the build directory")
        print("3. Check Python path includes the module directory")
        print("4. Rebuild the module: cd cpp_core && mkdir build && cd build && cmake .. && make")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    sys.exit(0 if test_cpp_module() else 1)
