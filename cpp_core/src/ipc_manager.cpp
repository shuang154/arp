#include "ipc_manager.h"
#include "utils.h"
#include <iostream>
#include <sstream>
#include <rapidjson/document.h>
#include <rapidjson/writer.h>
#include <rapidjson/stringbuffer.h>

using namespace rapidjson;

IPCManager::IPCManager() 
    : initialized_(false), packets_sent_(0), commands_received_(0) {
}

IPCManager::~IPCManager() {
    shutdown();
}

bool IPCManager::initialize() {
    // 默认实现，使用硬编码地址（保持兼容性）
    return initialize("ipc:///tmp/arp_spoofer_packets.ipc", "ipc:///tmp/arp_spoofer_commands.ipc");
}

bool IPCManager::initialize(const std::string& packet_addr, const std::string& command_addr) {
    try {
        // 创建ZMQ上下文
        context_ = std::make_unique<zmq::context_t>(1);
        
        // 创建数据包发送socket (PUSH模式)
        packet_sender_ = std::make_unique<zmq::socket_t>(*context_, zmq::socket_type::push);
        packet_sender_->connect(packet_addr);
        packet_sender_->set(zmq::sockopt::sndtimeo, 1000); // 使用新API
        
        // 创建命令接收socket (PULL模式)  
        command_receiver_ = std::make_unique<zmq::socket_t>(*context_, zmq::socket_type::pull);
        command_receiver_->connect(command_addr);
        command_receiver_->set(zmq::sockopt::rcvtimeo, 1); // 使用新API
        
        initialized_ = true;
        std::cout << "[IPC Manager] Initialized successfully. Packet sender: " << packet_addr 
                  << ", Command receiver: " << command_addr << std::endl;
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
        if (result) {
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
        
        return cmd;
        
    } catch (const std::exception& e) {
        std::cerr << "[IPC Manager] Command deserialization failed: " << e.what() << std::endl;
        return std::nullopt;
    }
}
