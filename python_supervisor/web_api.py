"""
Web API接口
===========
提供HTTP API用于监控和管理系统状态
"""

import logging
import threading
from flask import Flask, jsonify, request
from flask_cors import CORS
from typing import Dict, Any

class WebAPI:
    """Web API服务器 - 适配C++核心"""
    
    def __init__(self, supervisor, config):
        self.supervisor = supervisor  # PythonSupervisor实例
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.app = Flask(__name__)
        CORS(self.app)
        self.server_thread = None
        self.running = False
        
        # 注册路由
        self._register_routes()
    
    def _register_routes(self):
        """注册API路由"""
        
        @self.app.route('/api/status')
        def get_status():
            """获取系统状态"""
            try:
                if self.supervisor:
                    stats = self.supervisor.get_statistics()
                    return jsonify({
                        'status': 'running' if self.supervisor.running else 'stopped',
                        'statistics': stats
                    })
                else:
                    return jsonify({'error': 'Supervisor not available'}), 500
            except Exception as e:
                self.logger.error(f"Status API error: {e}")
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/attacks')
        def get_attacks():
            """获取攻击信息"""
            try:
                if self.supervisor and self.supervisor.cpp_processor:
                    active_attacks = self.supervisor.cpp_processor.get_active_attacks()
                    return jsonify({
                        'active_attacks': active_attacks,
                        'count': len(active_attacks)
                    })
            except Exception as e:
                self.logger.error(f"Attacks API error: {e}")
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/cache')
        def get_cache_info():
            """获取缓存信息"""
            try:
                if self.supervisor and self.supervisor.cpp_processor:
                    # 从C++核心获取缓存统计
                    stats = self.supervisor.cpp_processor.get_statistics()
                    return jsonify({
                        'cache_hits': stats.cache_hits,
                        'cache_misses': stats.cache_misses,
                        'hit_rate': stats.hit_rate
                    })
                else:
                    return jsonify({'error': 'C++ processor not available'}), 500
            except Exception as e:
                self.logger.error(f"Cache API error: {e}")
                return jsonify({'error': str(e)}), 500
    
    def start(self, port: int = 8080):
        """启动Web API服务器"""
        try:
            self.running = True
            self.server_thread = threading.Thread(
                target=self._run_server,
                args=(port,),
                name="WebAPI-Server",
                daemon=True
            )
            self.server_thread.start()
            self.logger.info(f"Web API started on port {port}")
        except Exception as e:
            self.logger.error(f"Failed to start Web API: {e}")
    
    def stop(self):
        """停止Web API服务器"""
        self.running = False
        if self.server_thread and self.server_thread.is_alive():
            self.server_thread.join(timeout=5.0)
        self.logger.info("Web API stopped")
    
    def _run_server(self, port: int):
        """运行Flask服务器"""
        try:
            self.app.run(
                host='127.0.0.1',
                port=port,
                debug=False,
                use_reloader=False,
                threaded=True
            )
        except Exception as e:
            self.logger.error(f"Web API server error: {e}")
