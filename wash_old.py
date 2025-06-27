#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
数据清洗脚本：根据用户ID+密码组合去重，保留最新记录
直接覆盖源文件，保持IP等其他字段不变
添加格式转换功能：将清洗后的数据按照"学号  两个空格  密码"格式写入wifi.txt
"""

def clean_data_by_user_password(file_path='temporary.txt'):
    """
    根据用户ID和密码组合去重，保留时间最新的记录
    直接覆盖源文件
    
    Args:
        file_path: 数据文件路径
        
    Returns:
        sorted_records: 清洗后的记录列表
    """
    
    try:
        # 读取所有行
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        print(f"原始数据行数: {len(lines)}")
        
        # 解析数据并去重
        records = {}
        processed_count = 0
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            parts = line.split(',')
            if len(parts) >= 6:
                ip_address = parts[0]      # IP地址
                field2 = parts[1]          # 第二个字段（空值）
                status = parts[2]          # 状态
                user_id = parts[3]         # 用户ID
                password = parts[4]        # 密码
                timestamp = parts[5]       # 时间戳
                
                processed_count += 1
                
                # 使用用户ID+密码作为唯一键
                key = f"{user_id}_{password}"
                
                # 如果键不存在或当前记录时间更新，则更新记录
                if key not in records or timestamp > records[key]['timestamp']:
                    records[key] = {
                        'line': line,
                        'timestamp': timestamp,
                        'user_id': user_id,
                        'password': password,
                        'ip': ip_address
                    }
        
        # 按时间戳排序
        sorted_records = sorted(records.values(), key=lambda x: x['timestamp'])
        
        print(f"处理了 {processed_count} 条有效记录")
        print(f"清洗后数据行数: {len(sorted_records)}")
        print(f"去除了 {processed_count - len(sorted_records)} 条重复记录")
        
        # 显示清洗后的数据
        print("\n清洗后的数据:")
        print("-" * 80)
        for i, record in enumerate(sorted_records, 1):
            print(f"{i}. {record['line']}")
            print(f"   用户: {record['user_id']}, 密码: {record['password']}, IP: {record['ip']}, 时间: {record['timestamp']}")
        
        # 写回源文件
        with open(file_path, 'w', encoding='utf-8') as f:
            for record in sorted_records:
                f.write(record['line'] + '\n')
        
        print(f"\n数据已清洗完成并保存到源文件: {file_path}")
        print("每个用户+密码组合只保留时间最新的一条记录")
        
        return sorted_records
        
    except FileNotFoundError:
        print(f"错误：找不到文件 {file_path}")
        return []
    except Exception as e:
        print(f"处理数据时出错: {str(e)}")
        return []

def convert_to_wifi_format(sorted_records, output_file='wifi.txt'):
    """
    将清洗后的数据转换为"学号  两个空格  密码"格式并写入wifi.txt
    
    Args:
        sorted_records: 清洗后的记录列表
        output_file: 输出文件名
    """
    
    try:
        if not sorted_records:
            print("没有数据需要转换")
            return
        
        # 创建或覆盖wifi.txt文件
        with open(output_file, 'w', encoding='utf-8') as f:
            for record in sorted_records:
                # 格式：学号  两个空格  密码
                wifi_line = f"{record['user_id']}  {record['password']}"
                f.write(wifi_line + '\n')
        
        print(f"\n格式转换完成！")
        print(f"已将 {len(sorted_records)} 条记录写入 {output_file}")
        print("格式：学号  两个空格  密码")
        
        # 显示转换后的前几条数据作为预览
        print(f"\n{output_file} 文件预览:")
        print("-" * 40)
        with open(output_file, 'r', encoding='utf-8') as f:
            preview_lines = f.readlines()[:10]  # 显示前10行
            for i, line in enumerate(preview_lines, 1):
                print(f"{i}. {line.strip()}")
        
        if len(sorted_records) > 10:
            print(f"... 共 {len(sorted_records)} 条记录")
        print("-" * 40)
        
    except Exception as e:
        print(f"转换格式时出错: {str(e)}")

def preview_data(file_path='temporary.txt'):
    """
    预览数据结构
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()[:5]  # 只读前5行预览
        
        print("数据结构预览:")
        print("-" * 50)
        for i, line in enumerate(lines, 1):
            parts = line.strip().split(',')
            if len(parts) >= 6:
                print(f"第{i}行: IP={parts[0]}, 用户ID={parts[3]}, 密码={parts[4]}, 时间={parts[5]}")
        print("-" * 50)
        
    except Exception as e:
        print(f"预览数据时出错: {str(e)}")

if __name__ == "__main__":
    print("数据清洗工具 - 根据用户+密码组合去重")
    print("=" * 60)
    
    # 预览数据
    preview_data()
    
    # 执行清洗
    cleaned_records = clean_data_by_user_password()
    
    if cleaned_records:
        print(f"\n✅ 清洗成功！最终保留 {len(cleaned_records)} 条不重复的记录")
        
        # 执行格式转换
        convert_to_wifi_format(cleaned_records)
        
        print(f"\n🎉 处理完成！")
        print(f"- 原始数据已清洗并保存到 temporary.txt")
        print(f"- 格式化数据已保存到 wifi.txt")
    else:
        print("\n❌ 清洗失败，请检查文件和数据格式")
    
    print("\n处理完成！")
