#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <pybind11/chrono.h>
#include "arp_spoofer.h"
#include "packet_sniffer.h"
#include "thread_pool.h"
#include "utils.h"  // 添加utils头文件

namespace py = pybind11;

/**
 * Python绑定 - 将C++高性能核心暴露给Python
 * 这样Python supervisor可以调用C++核心，获得真正的高性能
 */

PYBIND11_MODULE(arp_core_cpp, m) {
    m.doc() = "ARP Spoofer C++ Core - High Performance Thread Pool Implementation";
    
    // 线程池统计结构
    py::class_<HighPerformanceThreadPool>(m, "ThreadPool")
        .def(py::init<size_t>(), "创建线程池", py::arg("num_threads") = std::thread::hardware_concurrency())
        .def("start", &HighPerformanceThreadPool::start, "启动线程池")
        .def("stop", &HighPerformanceThreadPool::stop, "停止线程池")
        .def("get_thread_count", &HighPerformanceThreadPool::get_thread_count, "获取线程数")
        .def("get_tasks_completed", &HighPerformanceThreadPool::get_tasks_completed, "获取已完成任务数")
        .def("get_tasks_assigned", &HighPerformanceThreadPool::get_tasks_assigned, "获取已分配任务数")
        .def("get_completion_rate", &HighPerformanceThreadPool::get_completion_rate, "获取完成率")
        .def("get_queue_sizes", &HighPerformanceThreadPool::get_queue_sizes, "获取各线程队列大小");
    
    // ARP欺骗器主类
    py::class_<ARPSpoofer>(m, "ARPSpoofer")
        .def(py::init<const std::string&>(), "创建ARP欺骗器", py::arg("interface"))
        .def("initialize", &ARPSpoofer::initialize, "初始化ARP欺骗器")
        .def("shutdown", &ARPSpoofer::shutdown, "关闭ARP欺骗器")
        .def("start_spoofing", &ARPSpoofer::start_spoofing, 
             "开始ARP欺骗攻击",
             py::arg("target_ip"), py::arg("gateway_ip"), 
             py::arg("target_mac"), py::arg("gateway_mac"))
        .def("stop_spoofing", &ARPSpoofer::stop_spoofing, 
             "停止ARP欺骗攻击", py::arg("target_ip"))
        .def("restore_arp", &ARPSpoofer::restore_arp,
             "恢复ARP表",
             py::arg("target_ip"), py::arg("gateway_ip"),
             py::arg("target_mac"), py::arg("gateway_mac"))
        .def("get_total_packets_sent", &ARPSpoofer::get_total_packets_sent, "获取总发送包数")
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
    
    // 版本信息
    m.attr("__version__") = "1.0.0";
    m.attr("__description__") = "High Performance ARP Spoofer with Thread Pool - Real Network Only";
}
