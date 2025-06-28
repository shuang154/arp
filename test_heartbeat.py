#!/usr/bin/env python3
"""
心跳机制诊断工具
用于测试C++和Python之间的ZMQ IPC通信
"""

import zmq
import json
import time
import threading

def test_heartbeat_communication():
    """测试心跳通信"""
    print("🔍 Testing ZMQ IPC heartbeat communication...")
    
    context = zmq.Context()
    
    # 模拟Python端 - 绑定心跳接收器
    heartbeat_receiver = context.socket(zmq.PULL)
    try:
        heartbeat_receiver.bind("ipc:///tmp/arp_spoofer_heartbeat.ipc")
        heartbeat_receiver.setsockopt(zmq.RCVTIMEO, 5000)  # 5秒超时
        print("✅ Python heartbeat receiver bound successfully")
    except Exception as e:
        print(f"❌ Failed to bind heartbeat receiver: {e}")
        return False
    
    # 模拟Python端 - 绑定命令发送器
    command_sender = context.socket(zmq.PUSH)
    try:
        command_sender.bind("ipc:///tmp/arp_spoofer_commands.ipc")
        command_sender.setsockopt(zmq.SNDTIMEO, 1000)  # 1秒超时
        print("✅ Python command sender bound successfully")
    except Exception as e:
        print(f"❌ Failed to bind command sender: {e}")
        return False
    
    # 模拟C++端 - 连接心跳发送器
    heartbeat_sender = context.socket(zmq.PUSH)
    try:
        heartbeat_sender.connect("ipc:///tmp/arp_spoofer_heartbeat.ipc")
        heartbeat_sender.setsockopt(zmq.SNDTIMEO, 1000)  # 1秒超时
        print("✅ C++ heartbeat sender connected successfully")
        time.sleep(0.1)  # 等待连接建立
    except Exception as e:
        print(f"❌ Failed to connect heartbeat sender: {e}")
        return False
    
    # 模拟C++端 - 连接命令接收器
    command_receiver = context.socket(zmq.PULL)
    try:
        command_receiver.connect("ipc:///tmp/arp_spoofer_commands.ipc")
        command_receiver.setsockopt(zmq.RCVTIMEO, 5000)  # 5秒超时
        print("✅ C++ command receiver connected successfully")
        time.sleep(0.1)  # 等待连接建立
    except Exception as e:
        print(f"❌ Failed to connect command receiver: {e}")
        return False
    
    # 测试1：发送PING
    print("\n🔄 Testing PING -> PONG communication...")
    
    ping_message = {
        "type": "PING",
        "timestamp": int(time.time() * 1000),
        "seq": 1
    }
    
    try:
        # C++端发送PING
        ping_json = json.dumps(ping_message)
        heartbeat_sender.send_string(ping_json, zmq.NOBLOCK)
        print(f"📤 C++ sent PING: {ping_message}")
        
        # Python端接收PING
        received_data = heartbeat_receiver.recv()
        received_ping = json.loads(received_data.decode('utf-8'))
        print(f"📥 Python received PING: {received_ping}")
        
        # Python端发送PONG
        pong_message = {
            "type": "PONG",
            "timestamp": int(time.time() * 1000),
            "status": "healthy"
        }
        pong_json = json.dumps(pong_message)
        command_sender.send_string(pong_json, zmq.NOBLOCK)
        print(f"📤 Python sent PONG: {pong_message}")
        
        # C++端接收PONG
        received_pong_data = command_receiver.recv()
        received_pong = json.loads(received_pong_data.decode('utf-8'))
        print(f"📥 C++ received PONG: {received_pong}")
        
        print("✅ Heartbeat communication test PASSED!")
        return True
        
    except zmq.Again:
        print("❌ Timeout waiting for message")
        return False
    except Exception as e:
        print(f"❌ Communication test failed: {e}")
        return False
    
    finally:
        heartbeat_receiver.close()
        command_sender.close()
        heartbeat_sender.close()
        command_receiver.close()
        context.term()

def check_ipc_permissions():
    """检查IPC文件权限"""
    import os
    import stat
    
    print("\n🔍 Checking IPC file permissions...")
    
    ipc_files = [
        "/tmp/arp_spoofer_packets.ipc",
        "/tmp/arp_spoofer_commands.ipc", 
        "/tmp/arp_spoofer_heartbeat.ipc"
    ]
    
    for ipc_file in ipc_files:
        if os.path.exists(ipc_file):
            file_stat = os.stat(ipc_file)
            permissions = stat.filemode(file_stat.st_mode)
            print(f"📁 {ipc_file}: {permissions}")
        else:
            print(f"📁 {ipc_file}: Not found")

if __name__ == "__main__":
    print("🧪 ZMQ IPC Heartbeat Diagnostic Tool")
    print("=" * 50)
    
    # 检查文件权限
    check_ipc_permissions()
    
    # 测试通信
    success = test_heartbeat_communication()
    
    print("\n" + "=" * 50)
    if success:
        print("🎉 All tests PASSED! Heartbeat mechanism should work.")
    else:
        print("💥 Tests FAILED! There are communication issues.")
