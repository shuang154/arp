#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <pybind11/chrono.h>
#include "arp_spoofer.h"
#include "packet_sniffer.h"
#include "ipc_manager.h"
#include "utils.h"

namespace py = pybind11;

PYBIND11_MODULE(arp_core_cpp, m) {
    m.doc() = "ARP Spoofer C++ Core Module";
    
    // ARP欺骗器绑定
    py::class_<ARPSpoofer>(m, "ARPSpoofer")
        .def(py::init<const std::string&>(), "创建ARP欺骗器", py::arg("interface"))
        .def("initialize", &ARPSpoofer::initialize, "初始化欺骗器")
        .def("shutdown", &ARPSpoofer::shutdown, "关闭欺骗器")
        .def("start_spoofing", &ARPSpoofer::start_spoofing, "开始欺骗",
             py::arg("target_ip"), py::arg("gateway_ip"), py::arg("target_mac"), py::arg("gateway_mac"))
        .def("stop_spoofing", &ARPSpoofer::stop_spoofing, "停止欺骗", py::arg("target_ip"))
        .def("restore_arp", &ARPSpoofer::restore_arp, "恢复ARP",
             py::arg("target_ip"), py::arg("gateway_ip"), py::arg("target_mac"), py::arg("gateway_mac"))
        .def("get_active_sessions_count", &ARPSpoofer::get_active_sessions_count, "获取活跃会话数")
        .def("get_active_targets", &ARPSpoofer::get_active_targets, "获取活跃目标列表")
        .def("get_thread_pool_queue_sizes", &ARPSpoofer::get_thread_pool_queue_sizes, "获取线程池队列大小")
        .def("get_thread_pool_completion_rate", &ARPSpoofer::get_thread_pool_completion_rate, "获取线程池完成率");
    
    // 数据包嗅探器绑定
    py::class_<PacketSniffer>(m, "PacketSniffer")
        .def(py::init<const std::string&>(), "创建数据包嗅探器", py::arg("interface"))
        .def("initialize", &PacketSniffer::initialize, "初始化嗅探器",
             py::arg("packet_addr"), py::arg("command_addr"))
        .def("start_capture", &PacketSniffer::start_capture, "开始捕获")
        .def("stop_capture", &PacketSniffer::stop_capture, "停止捕获")
        .def("get_total_packets", &PacketSniffer::get_total_packets, "获取总包数")
        .def("get_filtered_packets", &PacketSniffer::get_filtered_packets, "获取过滤包数")
        .def("get_interface", &PacketSniffer::get_interface, "获取接口名")
        .def("is_running", &PacketSniffer::is_running, "是否正在运行");
    
    // IPC管理器绑定
    py::class_<IPCManager>(m, "IPCManager")
        .def(py::init<>(), "创建IPC管理器")
        .def("initialize", &IPCManager::initialize, "初始化IPC",
             py::arg("packet_addr"), py::arg("command_addr"))
        .def("shutdown", &IPCManager::shutdown, "关闭IPC")
        .def("get_packets_sent", &IPCManager::get_packets_sent, "获取已发送包数")
        .def("get_commands_sent", &IPCManager::get_commands_sent, "获取已发送命令数");
    
    // 工具函数
    m.def("get_timestamp_ms", &get_timestamp_ms, "获取毫秒时间戳");
    m.def("mac_to_string", [](const std::vector<uint8_t>& mac) {
        if (mac.size() != 6) return std::string("");
        return mac_to_string(mac.data());
    }, "MAC地址转字符串");
}
