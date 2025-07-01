#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <pybind11/chrono.h>
#include "arp_spoofer.h"
#include "packet_sniffer.h"
#include "ipc_manager.h"

namespace py = pybind11;

PYBIND11_MODULE(arp_core_cpp, m) {
    m.doc() = "ARP Spoofer C++ Core Module";
    
    // ★ 关键修正: 更新 PacketSniffer 绑定以匹配新的初始化方法
    py::class_<PacketSniffer>(m, "PacketSniffer")
        .def(py::init<const std::string&>())
        .def("initialize", &PacketSniffer::initialize, 
             "Initialize packet sniffer with IPC addresses",
             py::arg("packet_addr") = "", py::arg("command_addr") = "")
        .def("start_capture", &PacketSniffer::start_capture)
        .def("stop_capture", &PacketSniffer::stop_capture)
        .def("get_total_packets", &PacketSniffer::get_total_packets)
        .def("get_filtered_packets", &PacketSniffer::get_filtered_packets)
        .def("get_interface", &PacketSniffer::get_interface)
        .def("is_running", &PacketSniffer::is_running);
    
    py::class_<ARPSpoofer>(m, "ARPSpoofer")
        .def(py::init<const std::string&>())
        .def("initialize", &ARPSpoofer::initialize)
        .def("shutdown", &ARPSpoofer::shutdown)
        .def("start_spoofing", &ARPSpoofer::start_spoofing)
        .def("stop_spoofing", &ARPSpoofer::stop_spoofing)
        .def("restore_arp", &ARPSpoofer::restore_arp)
        .def("get_active_sessions_count", &ARPSpoofer::get_active_sessions_count)
        .def("get_active_targets", &ARPSpoofer::get_active_targets)
        .def("get_thread_pool_queue_sizes", &ARPSpoofer::get_thread_pool_queue_sizes)
        .def("get_thread_pool_completion_rate", &ARPSpoofer::get_thread_pool_completion_rate);
    
    // ★ 关键修正: 更新 IPCManager 绑定
    py::class_<IPCManager>(m, "IPCManager")
        .def(py::init<>())
        .def("initialize", &IPCManager::initialize)
        .def("shutdown", &IPCManager::shutdown)
        .def("get_packets_sent", &IPCManager::get_packets_sent)
        .def("get_commands_sent", &IPCManager::get_commands_sent);
}
        .def("get_total_sessions", &ARPSpoofer::get_total_sessions, "获取总会话数")
        .def("get_active_sessions_count", &ARPSpoofer::get_active_sessions_count, "获取活跃会话数")
        .def("get_active_targets", &ARPSpoofer::get_active_targets, "获取活跃目标列表")
        .def("get_thread_pool_queue_sizes", &ARPSpoofer::get_thread_pool_queue_sizes, "获取线程池队列大小")
        .def("get_thread_pool_completion_rate", &ARPSpoofer::get_thread_pool_completion_rate, "获取线程池完成率");
    
    // 数据包嗅探器
    py::class_<PacketSniffer>(m, "PacketSniffer")
        .def(py::init<const std::string&>(), "创建数据包嗅探器", py::arg("interface"))
        .def("initialize", &PacketSniffer::initialize, "初始化嗅探器")
        .def("start_capture", &PacketSniffer::start_capture, "开始捕获")
        .def("stop_capture", &PacketSniffer::stop_capture, "停止捕获")
        .def("get_packet_count", &PacketSniffer::get_packet_count, "获取包计数")
        .def("get_arp_packet_count", &PacketSniffer::get_arp_packet_count, "获取ARP包计数");
    
    // 工具函数
    m.def("get_timestamp_ms", &get_timestamp_ms, "获取毫秒时间戳");
    m.def("mac_to_string", [](const std::vector<uint8_t>& mac) {
        if (mac.size() != 6) return std::string("");
        return mac_to_string(mac.data());
    }, "MAC地址转字符串");
}
