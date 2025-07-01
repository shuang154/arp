#include "ipc_manager.h"
#include <iostream>
#include <json/json.h>

IPCManager::IPCManager() : packets_sent_(0), commands_sent_(0), initialized_(false) {}

IPCManager::~IPCManager() {
    shutdown();
}

// ★ 关键修正: 修改 initialize 方法以接受来自Python的配置
bool IPCManager::initialize(const std::string& packet_addr, const std::string& command_addr) {
    try {
        context_ = std::make_unique<zmq::context_t>(1);

        // 使用从Python传入的地址，而不是硬编码
        packet_sender_ = std::make_unique<zmq::socket_t>(*context_, zmq::socket_type::push);
        packet_sender_->connect(packet_addr);
        packet_sender_->set(zmq::sockopt::sndtimeo, 1000);

        command_receiver_ = std::make_unique<zmq::socket_t>(*context_, zmq::socket_type::pull);
        command_receiver_->connect(command_addr);
        command_receiver_->set(zmq::sockopt::rcvtimeo, 1);
        
        initialized_ = true;
        std::cout << "[IPC Manager] Initialized successfully. Packet sender connected to " << packet_addr << std::endl;
        return true;
    } catch (const std::exception& e) {
        std::cerr << "[IPC Manager] Initialization failed: " << e.what() << std::endl;
        return false;
    }
}

void IPCManager::shutdown() {
    if (initialized_) {
        packet_sender_.reset();
        command_receiver_.reset();
        context_.reset();
        initialized_ = false;
        std::cout << "[IPC Manager] Shutdown complete" << std::endl;
    }
}

// ★ 关键修正: 修复发送包的逻辑，增强错误处理
bool IPCManager::send_packet(const PacketInfo& packet) {
    if (!initialized_) {
        std::cerr << "[IPC Manager] Not initialized, cannot send packet" << std::endl;
        return false;
    }
    
    try {
        std::string json_data = serialize_packet(packet);
        zmq::message_t message(json_data.size());
        memcpy(message.data(), json_data.c_str(), json_data.size());

        // 使用非阻塞发送，避免程序卡死
        auto result = packet_sender_->send(message, zmq::send_flags::dontwait);
        
        if (result.has_value()) {
            packets_sent_++;
            return true;
        } else {
            // 发送失败，可能是缓冲区满，这在高频发送时是正常的
            return false;
        }
    } catch (const zmq::error_t& e) {
        std::cerr << "[IPC Manager] Send packet ZMQ error: " << e.what() << std::endl;
        return false;
    } catch (const std::exception& e) {
        std::cerr << "[IPC Manager] Send packet error: " << e.what() << std::endl;
        return false;
    }
}

bool IPCManager::send_command(const std::string& command) {
    if (!initialized_) return false;
    
    try {
        zmq::message_t message(command.size());
        memcpy(message.data(), command.c_str(), command.size());
        
        auto result = packet_sender_->send(message, zmq::send_flags::dontwait);
        if (result.has_value()) {
            commands_sent_++;
            return true;
        }
        return false;
    } catch (const std::exception& e) {
        std::cerr << "[IPC Manager] Send command error: " << e.what() << std::endl;
        return false;
    }
}

bool IPCManager::receive_command(std::string& command, int timeout_ms) {
    if (!initialized_) return false;
    
    try {
        zmq::message_t message;
        auto result = command_receiver_->recv(message, zmq::recv_flags::dontwait);
        
        if (result.has_value()) {
            command = std::string(static_cast<char*>(message.data()), message.size());
            return true;
        }
        return false;
    } catch (const std::exception& e) {
        return false;
    }
}
std::string IPCManager::serialize_packet(const PacketInfo& packet) {
    Json::Value json_packet;
    json_packet["timestamp"] = packet.timestamp;
    json_packet["src_ip"] = packet.src_ip;
    json_packet["dst_ip"] = packet.dst_ip;
    json_packet["src_mac"] = packet.src_mac;
    json_packet["dst_mac"] = packet.dst_mac;
    json_packet["protocol"] = packet.protocol;
    json_packet["packet_size"] = packet.packet_size;
    json_packet["raw_data"] = packet.raw_data;
    
    Json::StreamWriterBuilder builder;
    return Json::writeString(builder, json_packet);
}
