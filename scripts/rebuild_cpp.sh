#!/bin/bash
# 完全清理和重新编译C++模块的脚本

set -e  # 遇到错误立即退出

echo "🧹 完全清理旧的编译文件..."

# 进入C++核心目录
cd "$(dirname "$0")/../cpp_core"

# 1. 删除构建目录
if [ -d "build" ]; then
    echo "  - 删除 build/ 目录"
    rm -rf build/
fi

# 2. 查找并删除可能的编译产物
echo "  - 查找并删除编译产物..."
find . -name "*.o" -delete 2>/dev/null || true
find . -name "*.a" -delete 2>/dev/null || true
find . -name "*.so" -delete 2>/dev/null || true
find . -name "*.dylib" -delete 2>/dev/null || true
find . -name "*.dll" -delete 2>/dev/null || true
find . -name "*.exe" -delete 2>/dev/null || true
find . -name "CMakeCache.txt" -delete 2>/dev/null || true
find . -name "CMakeFiles" -type d -exec rm -rf {} + 2>/dev/null || true
find . -name "Makefile" -delete 2>/dev/null || true
find . -name "cmake_install.cmake" -delete 2>/dev/null || true

# 3. 检查Python环境和依赖
echo "🔍 检查Python环境..."
python3 --version
python3 -c "import pybind11; print(f'pybind11 version: {pybind11.__version__}')" || {
    echo "❌ pybind11 not found, installing..."
    pip3 install pybind11
}

# 4. 检查系统依赖
echo "🔍 检查系统依赖..."
pkg-config --exists libpcap || {
    echo "❌ libpcap not found"
    echo "Please install: sudo apt-get install libpcap-dev"
    exit 1
}

# 检查ZeroMQ
ldconfig -p | grep -q libzmq || {
    echo "❌ ZeroMQ not found"
    echo "Please install: sudo apt-get install libzmq3-dev cppzmq-dev"
    exit 1
}

# 检查RapidJSON
find /usr/include -name "rapidjson.h" 2>/dev/null | head -1 || {
    echo "❌ RapidJSON not found"
    echo "Please install: sudo apt-get install rapidjson-dev"
    exit 1
}

echo "✅ 所有依赖检查通过"

# 5. 创建新的构建目录
echo "🔧 创建构建目录..."
mkdir -p build
cd build

# 6. 配置CMake
echo "🔧 配置CMake..."
cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_VERBOSE_MAKEFILE=ON

# 7. 编译
echo "🔧 编译C++模块..."
make clean 2>/dev/null || true  # 清理可能的残留
make -j$(nproc) VERBOSE=1

# 8. 检查编译结果
echo "🔍 检查编译结果..."
if [ -f "arp_core_cpp*.so" ]; then
    echo "✅ Python模块编译成功"
    ls -la arp_core_cpp*.so
    
    # 显示符号信息
    echo "📋 模块符号信息："
    nm -D arp_core_cpp*.so | grep -E "(ARPSpoofer|PacketSniffer|ThreadPool)" || echo "  没有找到预期的符号"
    
    # 将模块复制到Python supervisor目录
    echo "📦 复制模块到Python目录..."
    cp arp_core_cpp*.so ../../python_supervisor/
    
else
    echo "❌ 编译失败，没有找到.so文件"
    exit 1
fi

# 9. 测试模块
echo "🧪 测试模块导入..."
cd ../../python_supervisor
python3 -c "
import sys
sys.path.insert(0, '.')
try:
    import arp_core_cpp
    print('✅ 模块导入成功')
    print(f'版本: {getattr(arp_core_cpp, \"__version__\", \"unknown\")}')
    attrs = [attr for attr in dir(arp_core_cpp) if not attr.startswith('_')]
    print(f'可用属性: {attrs}')
    
    # 检查关键类
    required = ['ARPSpoofer', 'PacketSniffer', 'ThreadPool']
    missing = [cls for cls in required if not hasattr(arp_core_cpp, cls)]
    if missing:
        print(f'❌ 缺少类: {missing}')
        exit(1)
    else:
        print('✅ 所有必需类都存在')
        
except Exception as e:
    print(f'❌ 模块测试失败: {e}')
    import traceback
    traceback.print_exc()
    exit(1)
"

echo ""
echo "🎉 编译和测试完成！"
echo "现在可以运行主程序了"
