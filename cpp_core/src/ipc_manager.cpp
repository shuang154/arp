#include "ipc_manager.h"
#include "utils.h"
#include <iostream>
#include <sstream>
#include <rapidjson/document.h>
#include <rapidjson/writer.h>
#include <rapidjson/stringbuffer.h>

using namespace rapidjson;

IPCManager::IPCManager() 
    : initialized_(false), packets_sent_(0), commands_received_(0),
      heartbeat_running_(false), pings_sent_(0), pongs_received_(0) {
    last_ping_time_ = std::chrono::steady_clock::now();
    last_pong_time_ = std::chrono::steady_clock::now();
}

IPCManager::~IPCManager() {
    stop_heartbeat();
    shutdown();
}

bool IPCManager::initialize() {
    try {
        // 创建ZMQ上下文
        context_ = std::make_unique<zmq::context_t>(1);
        
        // 创建数据包发送socket (PUSH模式)
        packet_sender_ = std::make_unique<zmq::socket_t>(*context_, zmq::socket_type::push);
        packet_sender_->connect("ipc:///tmp/arp_spoofer_packets.ipc");
        packet_sender_->set(zmq::sockopt::sndtimeo, 1000); // 使用新API
        
        // 创建命令接收socket (PULL模式)  
        command_receiver_ = std::make_unique<zmq::socket_t>(*context_, zmq::socket_type::pull);
        command_receiver_->connect("ipc:///tmp/arp_spoofer_commands.ipc");
        command_receiver_->set(zmq::sockopt::rcvtimeo, 1); // 使用新API
        
        initialized_ = true;
        std::cout << "[IPC Manager] Initialized successfully" << std::endl;
        return true;
        
    } catch (const std::exception& e) {
        std::cerr << "[IPC Manager] Initialization failed: " << e.what() << std::endl;
        return false;
    }
}

void IPCManager::shutdown() {
    if (!initialized_) return;
    
    packet_sender_.reset();
    command_receiver_.reset();
    context_.reset();
    
    initialized_ = false;
    std::cout << "[IPC Manager] Shutdown complete" << std::endl;
}

bool IPCManager::send_packet(const PacketInfo& packet) {
    if (!initialized_) return false;
    
    try {
        std::string json_data = serialize_packet(packet);
        
        zmq::message_t message(json_data.size());
        memcpy(message.data(), json_data.c_str(), json_data.size());
        
        auto result = packet_sender_->send(message, zmq::send_flags::dontwait);
        if (result.has_value()) {  // ★【修复】★ 检查optional是否有值
            packets_sent_++;
            return true;
        }
        
    } catch (const std::exception& e) {
        std::cerr << "[IPC Manager] Send packet failed: " << e.what() << std::endl;
    }
    
    return false;
}

std::optional<IPCCommand> IPCManager::receive_command(int timeout_ms) {
    if (!initialized_) return std::nullopt;
    
    try {
        zmq::message_t message;
        auto result = command_receiver_->recv(message, zmq::recv_flags::dontwait);
        
        if (result) {
            std::string json_data(static_cast<char*>(message.data()), message.size());
            commands_received_++;
            return deserialize_command(json_data);
        }
        
    } catch (const std::exception& e) {
        // 超时不算错误，只记录其他异常
        if (std::string(e.what()).find("timeout") == std::string::npos) {
            std::cerr << "[IPC Manager] Receive command failed: " << e.what() << std::endl;
        }
    }
    
    return std::nullopt;
}

std::string IPCManager::serialize_packet(const PacketInfo& packet) {
    Document doc;
    doc.SetObject();
    Document::AllocatorType& allocator = doc.GetAllocator();
    
    doc.AddMember("type", static_cast<int>(packet.type), allocator);
    doc.AddMember("src_ip", Value(packet.src_ip.c_str(), allocator), allocator);
    doc.AddMember("dst_ip", Value(packet.dst_ip.c_str(), allocator), allocator);
    doc.AddMember("src_port", packet.src_port, allocator);
    doc.AddMember("dst_port", packet.dst_port, allocator);
    doc.AddMember("length", packet.length, allocator);
    
    // 时间戳
    uint64_t timestamp_ms = packet.timestamp.tv_sec * 1000 + packet.timestamp.tv_usec / 1000;
    doc.AddMember("timestamp", timestamp_ms, allocator);
    
    // ARP特定字段
    if (packet.type == PacketType::ARP) {
        doc.AddMember("arp_opcode", packet.arp_opcode, allocator);
        
        // MAC地址
        std::string src_mac = mac_to_string(packet.src_mac);
        std::string dst_mac = mac_to_string(packet.dst_mac);
        doc.AddMember("src_mac", Value(src_mac.c_str(), allocator), allocator);
        doc.AddMember("dst_mac", Value(dst_mac.c_str(), allocator), allocator);
    }
    
    // HTTP载荷 - ★【修复】★ 发送完整的HTTP载荷数据以供凭据提取
    if (packet.type == PacketType::HTTP && packet.payload_length > 0) {
        doc.AddMember("payload_length", packet.payload_length, allocator);
        doc.AddMember("has_payload", true, allocator);
        
        // ★【修复】★ 添加完整的载荷内容，确保Python层能够提取凭据
        std::string payload_str(packet.payload, packet.payload_length);
        doc.AddMember("payload", Value(payload_str.c_str(), allocator), allocator);
    }
    
    // 序列化为JSON字符串
    StringBuffer buffer;
    Writer<StringBuffer> writer(buffer);
    doc.Accept(writer);
    
    return buffer.GetString();
}

std::optional<IPCCommand> IPCManager::deserialize_command(const std::string& data) {
    try {
        Document doc;
        doc.Parse(data.c_str());
        
        if (doc.HasParseError()) {
            std::cerr << "[IPC Manager] JSON parse error" << std::endl;
            return std::nullopt;
        }
        
        IPCCommand cmd;
        
        // 解析命令类型
        if (doc.HasMember("type") && doc["type"].IsString()) {
            std::string type_str = doc["type"].GetString();
            if (type_str == "START_SPOOF") {
                cmd.type = CommandType::START_SPOOF;
            } else if (type_str == "STOP_SPOOF") {
                cmd.type = CommandType::STOP_SPOOF;
            } else if (type_str == "RESTORE_ARP") {
                cmd.type = CommandType::RESTORE_ARP;
            } else if (type_str == "PONG") {
                cmd.type = CommandType::PONG;
                handle_pong();  // 处理心跳响应
                return cmd;     // 直接返回，不需要解析其他参数
            } else if (type_str == "SHUTDOWN") {
                cmd.type = CommandType::SHUTDOWN;
                return cmd;
            } else {
                std::cerr << "[IPC Manager] Unknown command type: " << type_str << std::endl;
                return std::nullopt;
            }
        }
        
        // 解析参数
        if (doc.HasMember("target_ip") && doc["target_ip"].IsString()) {
            cmd.target_ip = doc["target_ip"].GetString();
        }
        if (doc.HasMember("gateway_ip") && doc["gateway_ip"].IsString()) {
            cmd.gateway_ip = doc["gateway_ip"].GetString();
        }
        if (doc.HasMember("target_mac") && doc["target_mac"].IsString()) {
            cmd.target_mac = doc["target_mac"].GetString();
        }
        if (doc.HasMember("gateway_mac") && doc["gateway_mac"].IsString()) {
            cmd.gateway_mac = doc["gateway_mac"].GetString();
        }
        if (doc.HasMember("duration") && doc["duration"].IsUint()) {
            cmd.duration = doc["duration"].GetUint();
        }
        if (doc.HasMember("attack_type") && doc["attack_type"].IsString()) {
            cmd.attack_type = doc["attack_type"].GetString();
        }
        if (doc.HasMember("reason") && doc["reason"].IsString()) {
            cmd.reason = doc["reason"].GetString();
        }
        
        return cmd;
        
    } catch (const std::exception& e) {
        std::cerr << "[IPC Manager] Command deserialization failed: " << e.what() << std::endl;
        return std::nullopt;
    }
}

// ★【新增】★ 心跳机制实现
void IPCManager::start_heartbeat() {
    if (heartbeat_running_) {
        return;
    }
    
    heartbeat_running_ = true;
    heartbeat_thread_ = std::make_unique<std::thread>(&IPCManager::heartbeat_loop, this);
    std::cout << "[IPC Manager] Heartbeat mechanism started" << std::endl;
}

void IPCManager::stop_heartbeat() {
    if (!heartbeat_running_) {
        return;
    }
    
    heartbeat_running_ = false;
    if (heartbeat_thread_ && heartbeat_thread_->joinable()) {
        heartbeat_thread_->join();
    }
    heartbeat_thread_.reset();
    std::cout << "[IPC Manager] Heartbeat mechanism stopped" << std::endl;
}

void IPCManager::heartbeat_loop() {
    std::cout << "[IPC Manager] Heartbeat loop started" << std::endl;
    
    // 初始化最后pong时间为当前时间
    last_pong_time_ = std::chrono::steady_clock::now();
    
    while (heartbeat_running_) {
        // 发送PING
        if (!send_ping()) {
            std::cerr << "[IPC Manager] Failed to send heartbeat ping" << std::endl;
            
            // 如果发送失败，尝试重新连接
            try {
                packet_sender_->disconnect("ipc:///tmp/arp_spoofer_packets.ipc");
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                packet_sender_->connect("ipc:///tmp/arp_spoofer_packets.ipc");
                std::cout << "[IPC Manager] Attempted to reconnect packet sender" << std::endl;
            } catch (const std::exception& e) {
                std::cerr << "[IPC Manager] Reconnection failed: " << e.what() << std::endl;
            }
        }
        
        // 检查连接健康状态
        auto now = std::chrono::steady_clock::now();
        auto time_since_last_pong = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - last_pong_time_).count();
        
        if (time_since_last_pong > HEARTBEAT_TIMEOUT_MS) {
            std::cerr << "[IPC Manager] ⚠️  Connection timeout! Last pong: " 
                      << time_since_last_pong << "ms ago" << std::endl;
            
            // 触发连接丢失回调（但不要过于频繁）
            static auto last_callback_time = std::chrono::steady_clock::now();
            auto time_since_last_callback = std::chrono::duration_cast<std::chrono::milliseconds>(
                now - last_callback_time).count();
            
            if (time_since_last_callback > 10000 && connection_lost_callback_) { // 10秒只调用一次
                connection_lost_callback_();
                last_callback_time = now;
            }
        }
        
        // 等待下一次心跳
        std::this_thread::sleep_for(std::chrono::milliseconds(HEARTBEAT_INTERVAL_MS));
    }
    
    std::cout << "[IPC Manager] Heartbeat loop ended" << std::endl;
}

bool IPCManager::send_ping() {
    if (!initialized_ || !packet_sender_) {
        return false;
    }
    
    try {
        // 构造PING消息
        Document doc;
        doc.SetObject();
        Document::AllocatorType& allocator = doc.GetAllocator();
        
        doc.AddMember("type", "PING", allocator);
        
        // 获取当前时间戳（毫秒）
        auto now = std::chrono::steady_clock::now();
        auto timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()).count();
        doc.AddMember("timestamp", timestamp, allocator);
        doc.AddMember("seq", pings_sent_.load(), allocator);
        
        // 序列化
        StringBuffer buffer;
        Writer<StringBuffer> writer(buffer);
        doc.Accept(writer);
        
        // 发送
        zmq::message_t message(buffer.GetSize());
        memcpy(message.data(), buffer.GetString(), buffer.GetSize());
        
        auto send_result = packet_sender_->send(message, zmq::send_flags::dontwait);
        bool sent = send_result.has_value();
        if (sent) {
            last_ping_time_ = std::chrono::steady_clock::now();
            pings_sent_++;
        }
        
        return sent;
        
    } catch (const std::exception& e) {
        std::cerr << "[IPC Manager] Failed to send ping: " << e.what() << std::endl;
        return false;
    }
}

void IPCManager::handle_pong() {
    last_pong_time_ = std::chrono::steady_clock::now();
    pongs_received_++;
    
    // 计算往返时间
    auto rtt = std::chrono::duration_cast<std::chrono::milliseconds>(
        last_pong_time_ - last_ping_time_).count();
    
    // 可以在这里记录RTT统计信息
    if (rtt > 100) {  // 如果RTT超过100ms，发出警告
        std::cout << "[IPC Manager] ⚠️  High RTT detected: " << rtt << "ms" << std::endl;
    }
}

bool IPCManager::is_connection_healthy() const {
    auto now = std::chrono::steady_clock::now();
    auto time_since_last_pong = std::chrono::duration_cast<std::chrono::milliseconds>(
        now - last_pong_time_).count();
    
    return time_since_last_pong <= HEARTBEAT_TIMEOUT_MS;
}

void IPCManager::set_connection_lost_callback(std::function<void()> callback) {
    connection_lost_callback_ = callback;
}

IPCManager::HeartbeatStatus IPCManager::get_heartbeat_status() const {
    auto now = std::chrono::steady_clock::now();
    
    auto last_ping_ago = std::chrono::duration_cast<std::chrono::milliseconds>(
        now - last_ping_time_);
    auto last_pong_ago = std::chrono::duration_cast<std::chrono::milliseconds>(
        now - last_pong_time_);
    
    return {
        is_connection_healthy(),
        last_ping_ago,
        last_pong_ago,
        pings_sent_.load(),
        pongs_received_.load()
    };
}
