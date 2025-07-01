#!/bin/bash

echo "=== 修复 ARP 欺骗包发送问题 ==="
echo ""
echo "问题分析："
echo "1. ✅ Python 分析器正确识别攻击目标"
echo "2. ✅ 攻击决策制定成功"
echo "3. ❌ Gateway MAC 地址为空导致 C++ 发包失败"
echo ""
echo "修复内容："
echo "1. Python 端尝试从缓存获取网关 MAC"
echo "2. C++ 端处理空 MAC 地址，使用广播地址作为默认值"
echo "3. 添加详细的调试输出确认参数传递"
echo ""

# 进入项目目录
cd "$(dirname "$0")"

# 重新编译 C++ 核心
echo "🔨 重新编译 C++ 核心..."
cd cpp_core
rm -rf build/
mkdir -p build
cd build

cmake .. -DCMAKE_BUILD_TYPE=Release
if [ $? -ne 0 ]; then
    echo "❌ CMake 配置失败"
    exit 1
fi

make -j$(nproc)
if [ $? -ne 0 ]; then
    echo "❌ 编译失败"
    exit 1
fi

cd ../..

echo "✅ 编译完成！"
echo ""
echo "现在可以测试："
echo "  sudo ./scripts/build.sh -i <网卡接口>"
echo ""
echo "关键日志观察点："
echo "1. 查找 'Attack params:' - 确认参数传递正确"
echo "2. 查找 'Successfully sent packets' - 确认前几次发包成功"
echo "3. 查找 'Gateway MAC not provided' - 确认 MAC 地址解析"
echo "4. 数据包统计应该显示 > 0 个包"
echo ""
echo "如果还是 0 pps，可能的原因："
echo "- 权限不足（需要 sudo 运行）"
echo "- 网卡接口错误"
echo "- 防火墙或安全软件阻止"
