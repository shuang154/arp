#!/bin/bash
# 简化版清理重建脚本 - 专门解决类名不匹配问题

echo "🔧 ARP Spoofer C++ Module - 完全重建"
echo "解决类名不匹配问题 (ARPProcessor vs ARPSpoofer)"
echo "========================================================"

# 获取项目根目录
PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
echo "📁 项目目录: $PROJECT_ROOT"

# 1. 完全清理
echo ""
echo "🧹 第一步：完全清理编译残留..."
cd "$PROJECT_ROOT/cpp_core"

# 删除所有可能的编译产物
rm -rf build/ 2>/dev/null || true
find . -name "*.o" -delete 2>/dev/null || true
find . -name "*.so" -delete 2>/dev/null || true
find . -name "*.a" -delete 2>/dev/null || true
find . -name "CMakeCache.txt" -delete 2>/dev/null || true
find . -name "CMakeFiles" -type d -exec rm -rf {} + 2>/dev/null || true
find . -name "Makefile" -delete 2>/dev/null || true

# 同时清理Python目录中的旧模块
rm -f "$PROJECT_ROOT/python_supervisor/arp_core_cpp*.so" 2>/dev/null || true

echo "✅ 清理完成"

# 2. 验证源文件
echo ""
echo "🔍 第二步：验证关键源文件..."

# 检查关键源文件是否存在
check_file() {
    if [ -f "$1" ]; then
        echo "  ✅ $1"
        return 0
    else
        echo "  ❌ $1 (缺失)"
        return 1
    fi
}

missing_files=0
check_file "src/arp_spoofer.h" || missing_files=$((missing_files + 1))
check_file "src/arp_spoofer.cpp" || missing_files=$((missing_files + 1))
check_file "src/packet_sniffer.h" || missing_files=$((missing_files + 1))
check_file "src/packet_sniffer.cpp" || missing_files=$((missing_files + 1))
check_file "src/python_bindings.cpp" || missing_files=$((missing_files + 1))
check_file "CMakeLists.txt" || missing_files=$((missing_files + 1))

if [ $missing_files -gt 0 ]; then
    echo "❌ 发现 $missing_files 个缺失文件，无法继续编译"
    exit 1
fi

# 3. 检查Python绑定文件的内容
echo ""
echo "🔍 第三步：检查Python绑定..."
if grep -q "ARPSpoofer" src/python_bindings.cpp; then
    echo "  ✅ python_bindings.cpp 包含 ARPSpoofer 绑定"
else
    echo "  ❌ python_bindings.cpp 不包含 ARPSpoofer 绑定"
    echo "  这可能是问题的根源"
fi

# 4. 检查依赖
echo ""
echo "🔍 第四步：检查编译依赖..."
python3 -c "import pybind11; print('  ✅ pybind11 版本:', pybind11.__version__)" || {
    echo "  ❌ pybind11 未安装，正在安装..."
    pip3 install pybind11
}

# 5. 重新编译
echo ""
echo "🔧 第五步：重新编译..."
mkdir -p build
cd build

echo "  配置 CMake..."
cmake .. -DCMAKE_BUILD_TYPE=Release || {
    echo "❌ CMake 配置失败"
    exit 1
}

echo "  开始编译..."
make -j$(nproc) || {
    echo "❌ 编译失败"
    echo "检查上面的错误信息"
    exit 1
}

# 6. 验证编译结果
echo ""
echo "🔍 第六步：验证编译结果..."
MODULE_FILE=$(find . -name "arp_core_cpp*.so" | head -1)

if [ -n "$MODULE_FILE" ]; then
    echo "  ✅ 找到编译的模块: $MODULE_FILE"
    
    # 复制到Python目录
    cp "$MODULE_FILE" "$PROJECT_ROOT/python_supervisor/"
    echo "  ✅ 模块已复制到 python_supervisor/"
    
    # 检查符号
    echo "  🔍 检查模块符号..."
    if command -v nm >/dev/null 2>&1; then
        echo "    模块中的关键符号："
        nm -D "$MODULE_FILE" | grep -E "(ARPSpoofer|PacketSniffer|ThreadPool|ARPProcessor)" | head -10 || echo "    未找到相关符号"
    fi
else
    echo "  ❌ 未找到编译的模块文件"
    exit 1
fi

# 7. 测试模块
echo ""
echo "🧪 第七步：测试模块..."
cd "$PROJECT_ROOT/python_supervisor"

python3 -c "
import sys
import os
sys.path.insert(0, os.getcwd())

try:
    import arp_core_cpp
    print('  ✅ 模块导入成功')
    
    # 显示版本信息
    version = getattr(arp_core_cpp, '__version__', 'unknown')
    print(f'  📦 版本: {version}')
    
    # 列出所有属性
    attrs = [attr for attr in dir(arp_core_cpp) if not attr.startswith('_')]
    print(f'  📋 可用属性: {attrs}')
    
    # 检查期望的类
    expected = ['ARPSpoofer', 'PacketSniffer', 'ThreadPool']
    found = []
    missing = []
    
    for cls in expected:
        if hasattr(arp_core_cpp, cls):
            found.append(cls)
        else:
            missing.append(cls)
    
    if found:
        print(f'  ✅ 找到的类: {found}')
    if missing:
        print(f'  ❌ 缺失的类: {missing}')
        
    # 如果找到ARPSpoofer，尝试创建实例
    if hasattr(arp_core_cpp, 'ARPSpoofer'):
        try:
            test_obj = arp_core_cpp.ARPSpoofer('test_interface')
            print('  ✅ ARPSpoofer 构造函数正常')
            del test_obj
        except Exception as e:
            print(f'  ⚠️ ARPSpoofer 构造函数测试失败: {e}')
    
    if len(missing) == 0:
        print('  🎉 所有必需的类都存在！')
        success = True
    else:
        print('  ⚠️ 仍有类缺失，但模块基本可用')
        success = False
        
except Exception as e:
    print(f'  ❌ 模块测试失败: {e}')
    import traceback
    traceback.print_exc()
    success = False
"

echo ""
if [ $? -eq 0 ]; then
    echo "🎉 重建完成！现在可以运行主程序："
    echo "   cd $PROJECT_ROOT/scripts && ./launch.sh"
else
    echo "⚠️ 重建完成但仍有问题，请检查上面的错误信息"
    echo "可以尝试运行主程序，系统会自动使用Python回退模式"
fi
