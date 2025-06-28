#!/bin/bash

# 简单编译测试脚本
cd cpp_core/src

echo "Testing main.cpp compilation..."

# 检查语法
g++ -fsyntax-only -std=c++17 -I. main.cpp 2>&1 | head -20

echo "Compilation test complete."
