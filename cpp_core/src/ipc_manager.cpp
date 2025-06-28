#include "ipc_manager.h"
#include "utils.h"
#include <iostream>
#include <sstream>
#include <rapidjson/document.h>
#include <rapidjson/writer.h>
#include <rapidjson/stringbuffer.h>
#include <chrono>

using namespace rapidjson;

// ★【重构】★ 构造函数负责所有初始化
IPCManager::IPCManager(const ConfigManager& config)
    : config_(config), 
      shutdown_flag_(false) {

    try {
        // 1. 初始化主Context和业务Sockets
        main_context_ = std::make_unique<zmq::context_t>(1);
        
        packet_sender_ = std::make_unique<zmq::socket_t>(*main_context_, zmq::socket_type::push);
        packet_sender_->connect(config_.get_packet_address());
        packet_sender_->set(zmq::sockopt::sndhwm, config_.get_packet_hwm()); // ★【修复】★ 使用配置的HWM
        packet_sender_->set(zmq::sockopt::sndtimeo, 1000);

        command_receiver_ = std::make_unique<zmq::socket_t>(*main_context_, zmq::socket_type::pull);
        command_receiver_->bind(config_.get_command_address());
        command_receiver_->set(zmq::sockopt::rcvhwm, config_.get_command_hwm()); // ★【修复】★ 使用配置的HWM
        command_receiver_->set(zmq::sockopt::rcvtimeo, 1000); // 非阻塞接收

        // 2. 初始化心跳Context和心跳Sockets
        heartbeat_context_ = std::make_unique<zmq::context_t>(1);

        // PING Sender (C++ PUSH -> Python PULL)
        heartbeat_ping_sender_ = std::make_unique<zmq::socket_t>(*heartbeat_context_, zmq::socket_type::push);
        heartbeat_ping_sender_->connect(config_.get_heartbeat_address());
        heartbeat_ping_sender_->set(zmq::sockopt::sndhwm, config_.get_heartbeat_hwm()); // ★【修复】★ 使用配置的HWM
        heartbeat_ping_sender_->set(zmq::sockopt::linger, 0);
        heartbeat_ping_sender_->set(zmq::sockopt::immediate, 1);   // ★【修复】★ 立即发送，不排队

        // PONG Receiver (Python PUSH -> C++ PULL)
        heartbeat_pong_receiver_ = std::make_unique<zmq::socket_t>(*heartbeat_context_, zmq::socket_type::pull);
        heartbeat_pong_receiver_->bind(config_.get_heartbeat_pong_address());
        heartbeat_pong_receiver_->set(zmq::sockopt::rcvhwm, config_.get_heartbeat_hwm()); // ★【修复】★ 使用配置的HWM
        heartbeat_pong_receiver_->set(zmq::sockopt::rcvtimeo, 100); // 短超时，用于poll

        // 3. 初始化心跳状态并启动线程
        last_pong_time_ = std::chrono::steady_clock::now();
        heartbeat_thread_ = std::thread(&IPCManager::heartbeat_thread_func, this);

        std::cout << "[IPC Manager] Initialized successfully. Heartbeat thread started." << std::endl;

    } catch (const zmq::error_t& e) {
        std::cerr << "[IPC Manager] ZMQ Initialization failed: " << e.what() << " (errno: " << e.num() << ")" << std::endl;
        throw; // 抛出异常，让上层处理
    } catch (const std::exception& e) {
        std::cerr << "[IPC Manager] General Initialization failed: " << e.what() << std::endl;
        throw;
    }
}

// ★【重构】★ 析构函数负责清理
IPCManager::~IPCManager() {
    std::cout << "[IPC Manager] Shutting down..." << std::endl;
    shutdown_flag_ = true;
    if (heartbeat_thread_.joinable()) {
        heartbeat_thread_.join();
    }
    
    // 清理顺序：sockets -> contexts
    packet_sender_.reset();
    command_receiver_.reset();
    heartbeat_ping_sender_.reset();
    heartbeat_pong_receiver_.reset();

    main_context_.reset();
    heartbeat_context_.reset();
    std::cout << "[IPC Manager] Shutdown complete." << std::endl;
}

// ★【重构】★ 心跳线程，独立处理PING发送和PONG接收
void IPCManager::heartbeat_thread_func() {
    auto last_ping_time = std::chrono::steady_clock::now();
    const auto ping_interval = std::chrono::milliseconds(config_.get_heartbeat_interval());

    while (!shutdown_flag_) {
        auto now = std::chrono::steady_clock::now();

        // 1. 发送 PING (JSON格式) - ★【修复】★ 深拷贝+阻塞发送+成功才更新时间戳
        if (now - last_ping_time > ping_interval) {
            // ★【修复】★ 构建标准JSON格式的PING消息
            const std::string ping_json = R"({"type":"PING","timestamp":)" + 
                std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count()) +
                R"(,"sequence":)" + std::to_string(pings_sent_.load()) + "}";
            
            try {
                // ★【关键修复】★ 使用最可靠的深拷贝方式
                zmq::message_t ping_msg(ping_json.begin(), ping_json.end());
                
                // ★【关键修复】★ 使用阻塞发送，只有成功才更新时间戳和计数器
                if (heartbeat_ping_sender_->send(ping_msg, zmq::send_flags::none)) {
                    // ★【关键】★ 只有发送成功后才更新时间戳和计数器
                    last_ping_time = std::chrono::steady_clock::now();
                    pings_sent_++;
                    std::cout << "[Heartbeat] Sent PING: " << ping_json << std::endl; // ★【启用调试】★
                }
            } catch (const zmq::error_t& e) {
                // ★【关键修复】★ 捕获所有网络错误，不更新时间戳
                if (e.num() == EHOSTUNREACH) {
                    std::cerr << "[Heartbeat] Network unreachable (EHOSTUNREACH), retrying..." << std::endl;
                } else if (e.num() != ETERM && e.num() != EAGAIN) {
                    std::cerr << "[Heartbeat] Failed to send PING: " << e.what() << " (errno: " << e.num() << ")" << std::endl;
                }
                // ★【关键】★ 发送失败时不更新last_ping_time，这样下次循环会立即重试
            }
        }

        // 2. 接收 PONG (非阻塞) - JSON格式
        try {
            zmq::message_t pong_msg;
            if (heartbeat_pong_receiver_->recv(pong_msg, zmq::recv_flags::dontwait)) {
                std::string pong_str(static_cast<char*>(pong_msg.data()), pong_msg.size());
                
                // ★【修复】★ 解析JSON格式的PONG消息
                try {
                    Document doc;
                    doc.Parse(pong_str.c_str());
                    
                    if (!doc.HasParseError() && doc.IsObject() && 
                        doc.HasMember("type") && doc["type"].IsString() &&
                        std::string(doc["type"].GetString()) == "PONG") {
                        handle_pong();
                        std::cout << "[Heartbeat] Received PONG: " << pong_str << std::endl; // ★【启用调试】★
                    }
                } catch (const std::exception& e) {
                    std::cerr << "[Heartbeat] Failed to parse PONG JSON: " << e.what() << std::endl;
                }
            }
        } catch (const zmq::error_t& e) {
            if (e.num() != ETERM && e.num() != EAGAIN) {
                 std::cerr << "[Heartbeat] Failed to receive PONG: " << e.what() << std::endl;
            }
        }

        // 3. 检查连接健康状态
        if (!is_connection_healthy()) {
            if (connection_lost_callback_) {
                std::cerr << "[Heartbeat] Connection lost! Invoking callback." << std::endl;
                connection_lost_callback_();
            }
        }

        // 短暂休眠，避免CPU空转
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    std::cout << "[Heartbeat] Thread finished." << std::endl;
}

void IPCManager::handle_pong() {
    last_pong_time_ = std::chrono::steady_clock::now();
    pongs_received_++;
    // std::cout << "[Heartbeat] Received PONG" << std::endl; // 调试时开启
}

bool IPCManager::is_connection_healthy() const {
    const auto timeout = std::chrono::milliseconds(config_.get_heartbeat_timeout());
    return (std::chrono::steady_clock::now() - last_pong_time_.load()) < timeout;
}

void IPCManager::set_connection_lost_callback(std::function<void()> callback) {
    connection_lost_callback_ = std::move(callback);
}

// ★【修改】★ 只在主命令通道接收业务命令
std::optional<IPCCommand> IPCManager::receive_command(int timeout_ms) {
    try {
        zmq::message_t message;
        // 使用带超时的recv，避免完全阻塞
        command_receiver_->set(zmq::sockopt::rcvtimeo, timeout_ms);
        auto result = command_receiver_->recv(message, zmq::recv_flags::none);

        if (result.has_value() && result.value() > 0) {
            std::string json_data(static_cast<char*>(message.data()), message.size());
            commands_received_++;
            return deserialize_command(json_data);
        }
    } catch (const zmq::error_t& e) {
        if (e.num() != EAGAIN) { // 忽略超时错误
            std::cerr << "[IPC Manager] Receive command failed: " << e.what() << std::endl;
        }
    }
    return std::nullopt;
}

bool IPCManager::send_packet(const PacketInfo& packet) {
    try {
        std::string json_data = serialize_packet(packet);
        zmq::message_t message(json_data.size());
        memcpy(message.data(), json_data.c_str(), json_data.size());

        if (packet_sender_->send(message, zmq::send_flags::dontwait)) {
            packets_sent_++;
            return true;
        }
    } catch (const std::exception& e) {
        std::cerr << "[IPC Manager] Send packet failed: " << e.what() << std::endl;
    }
    return false;
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
