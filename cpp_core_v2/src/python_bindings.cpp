#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <pybind11/chrono.h>
#include "arp_processor.h"

namespace py = pybind11;

/**
 * Python绑定模块
 * 将C++高性能核心暴露给Python使用
 */

PYBIND11_MODULE(arp_core_cpp, m) {
    m.doc() = "High-performance ARP Spoofer C++ Core";

    // Config结构体绑定
    py::class_<Config>(m, "Config")
        .def(py::init<>())
        .def_readwrite("max_worker_threads", &Config::max_worker_threads)
        .def_readwrite("packet_batch_size", &Config::packet_batch_size)
        .def_readwrite("packet_batch_timeout", &Config::packet_batch_timeout)
        .def_readwrite("interface", &Config::interface)
        .def_readwrite("gateway_ip", &Config::gateway_ip)
        .def_readwrite("target_ports", &Config::target_ports)
        .def_readwrite("attack_timeout", &Config::attack_timeout)
        .def_readwrite("max_concurrent_attacks", &Config::max_concurrent_attacks)
        .def_readwrite("cooldown_time", &Config::cooldown_time)
        .def_readwrite("arp_cache_ttl", &Config::arp_cache_ttl)
        .def_readwrite("attack_cache_ttl", &Config::attack_cache_ttl)
        .def_readwrite("target_info_ttl", &Config::target_info_ttl)
        .def_readwrite("packet_ipc_address", &Config::packet_ipc_address)
        .def_readwrite("command_ipc_address", &Config::command_ipc_address);

    // Statistics结构体绑定
    py::class_<Statistics>(m, "Statistics")
        .def(py::init<>())
        .def_readonly("packets_captured", &Statistics::packets_captured)
        .def_readonly("packets_processed", &Statistics::packets_processed)
        .def_readonly("attacks_launched", &Statistics::attacks_launched)
        .def_readonly("attacks_successful", &Statistics::attacks_successful)
        .def_readonly("cache_hits", &Statistics::cache_hits)
        .def_readonly("cache_misses", &Statistics::cache_misses)
        .def_readonly("processing_rate", &Statistics::processing_rate)
        .def_readonly("hit_rate", &Statistics::hit_rate)
        .def_readonly("active_attacks_count", &Statistics::active_attacks_count)
        .def_readonly("uptime", &Statistics::uptime);

    // ARPProcessor核心类绑定
    py::class_<ARPProcessor>(m, "ARPProcessor")
        .def(py::init<const Config&>())
        .def("initialize", &ARPProcessor::initialize, 
             "Initialize the ARP processor")
        .def("start", &ARPProcessor::start, 
             "Start the ARP processor")
        .def("stop", &ARPProcessor::stop, 
             "Stop the ARP processor")
        .def("is_running", &ARPProcessor::is_running, 
             "Check if the processor is running")
        .def("get_statistics", &ARPProcessor::get_statistics, 
             "Get current statistics")
        .def("get_active_attacks", &ARPProcessor::get_active_attacks, 
             "Get list of active attacks")
        .def("update_configuration", &ARPProcessor::update_configuration, 
             "Update processor configuration");

    // 便利函数
    m.def("create_default_config", []() {
        Config config;
        return config;
    }, "Create a default configuration");

    m.def("config_from_dict", [](const py::dict& dict) {
        Config config;
        
        if (dict.contains("max_worker_threads"))
            config.max_worker_threads = dict["max_worker_threads"].cast<int>();
        if (dict.contains("packet_batch_size"))
            config.packet_batch_size = dict["packet_batch_size"].cast<int>();
        if (dict.contains("packet_batch_timeout"))
            config.packet_batch_timeout = dict["packet_batch_timeout"].cast<double>();
        if (dict.contains("interface"))
            config.interface = dict["interface"].cast<std::string>();
        if (dict.contains("gateway_ip"))
            config.gateway_ip = dict["gateway_ip"].cast<std::string>();
        if (dict.contains("attack_timeout"))
            config.attack_timeout = dict["attack_timeout"].cast<int>();
        if (dict.contains("max_concurrent_attacks"))
            config.max_concurrent_attacks = dict["max_concurrent_attacks"].cast<int>();
        if (dict.contains("cooldown_time"))
            config.cooldown_time = dict["cooldown_time"].cast<int>();
        if (dict.contains("arp_cache_ttl"))
            config.arp_cache_ttl = dict["arp_cache_ttl"].cast<int>();
        
        return config;
    }, "Create config from Python dictionary");
}
