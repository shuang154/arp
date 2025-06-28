#!/usr/bin/env python3
"""
心跳机制测试脚本
用于验证独立心跳线程是否正常工作
"""

import zmq
import json
import time
import threading
import sys
from python_supervisor.config import Config

def test_heartbeat_only():
    """测试仅心跳功能，不涉及业务逻辑"""
    print("🧪 Testing heartbeat mechanism only...")
    
    # 加载配置
    config = Config()
    config.load_from_file("config/config.yaml")
    
    # 创建独立的心跳上下文
    heartbeat_context = zmq.Context()
    
    # 心跳接收器 (模拟Python Supervisor)
    heartbeat_receiver = heartbeat_context.socket(zmq.PULL)
    heartbeat_receiver.bind(config.ipc.heartbeat_ping_address)
    heartbeat_receiver.setsockopt(zmq.RCVTIMEO, 100)
    heartbeat_receiver.setsockopt(zmq.RCVHWM, 1)
    
    # 心跳发送器 (模拟回复PONG)
    heartbeat_sender = heartbeat_context.socket(zmq.PUSH)
    heartbeat_sender.connect(config.ipc.heartbeat_pong_address)
    heartbeat_sender.setsockopt(zmq.SNDTIMEO, 200)
    heartbeat_sender.setsockopt(zmq.SNDHWM, 1)
    
    print(f"📡 Heartbeat receiver listening on: {config.ipc.heartbeat_ping_address}")
    print(f"📤 Heartbeat sender connected to: {config.ipc.heartbeat_pong_address}")
    
    # 统计
    ping_received = 0
    pong_sent = 0
    json_errors = 0
    running = True
    
    def heartbeat_loop():
        nonlocal ping_received, pong_sent, json_errors, running
        
        while running:
            try:
                # 接收PING
                raw_message = heartbeat_receiver.recv(flags=zmq.NOBLOCK)
                
                if not raw_message or len(raw_message) == 0:
                    time.sleep(0.001)
                    continue
                
                try:
                    # 解析JSON
                    message_str = raw_message.decode('utf-8', errors='replace')
                    ping_data = json.loads(message_str)
                    
                    if ping_data.get("type") == "PING":
                        ping_received += 1
                        print(f"🫀 PING #{ping_received}: seq={ping_data.get('sequence', 'N/A')}")
                        
                        # 立即回复PONG
                        pong_response = {
                            "type": "PONG",
                            "timestamp": time.time(),
                            "sequence": ping_data.get("sequence", 0),
                            "supervisor_status": "test_alive"
                        }
                        
                        heartbeat_sender.send_string(json.dumps(pong_response), zmq.NOBLOCK)
                        pong_sent += 1
                        print(f"💝 PONG #{pong_sent} sent")
                    
                except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as e:
                    json_errors += 1
                    print(f"❌ JSON ERROR #{json_errors}: {e}")
                    print(f"   Raw message: {raw_message[:50]}...")
                    continue
                    
            except zmq.Again:
                time.sleep(0.001)
                continue
            except Exception as e:
                print(f"💥 HEARTBEAT ERROR: {e}")
                time.sleep(0.01)
    
    # 启动心跳线程
    heartbeat_thread = threading.Thread(target=heartbeat_loop, daemon=False, name="TestHeartbeat")
    heartbeat_thread.start()
    
    print("🚀 Heartbeat test started. Waiting for C++ core to send PING...")
    print("📊 Press Ctrl+C to stop and see statistics")
    
    try:
        # 定期输出统计信息
        start_time = time.time()
        while True:
            time.sleep(5)
            elapsed = time.time() - start_time
            print(f"📈 [{elapsed:.1f}s] Stats: PING={ping_received}, PONG={pong_sent}, JSON_ERR={json_errors}")
            
            if ping_received == 0 and elapsed > 30:
                print("⚠️  WARNING: No PING received after 30s. Check if C++ core is running.")
                break
                
    except KeyboardInterrupt:
        print("\n🛑 Test stopped by user")
    finally:
        running = False
        heartbeat_thread.join(timeout=2.0)
        heartbeat_receiver.close()
        heartbeat_sender.close()
        heartbeat_context.term()
        
        print(f"\n📊 FINAL STATISTICS:")
        print(f"   PING received: {ping_received}")
        print(f"   PONG sent: {pong_sent}")
        print(f"   JSON errors: {json_errors}")
        print(f"   Success rate: {(pong_sent/max(ping_received, 1)*100):.1f}%")

if __name__ == "__main__":
    test_heartbeat_only()
