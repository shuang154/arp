#!/bin/bash
# 重新编译C++模块的脚本

echo "🔧 Rebuilding C++ module with updated PacketSniffer..."

cd cpp_core

# 清理旧的构建
echo "🧹 Cleaning old build..."
rm -rf build/
find . -name "*.so" -delete

# 重新构建
echo "🏗️ Building..."
mkdir build && cd build

cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)

if [ $? -eq 0 ]; then
    echo "✅ Build successful!"
    
    # 复制模块到Python目录
    if [ -f *.so ]; then
        cp *.so ../../python_supervisor/
        echo "✅ Module copied to python_supervisor/"
    fi
    
    echo "🎉 C++ module rebuild complete!"
    echo "Now you can run the system with: cd ../scripts && sudo ./build.sh"
else
    echo "❌ Build failed!"
    exit 1
fi
