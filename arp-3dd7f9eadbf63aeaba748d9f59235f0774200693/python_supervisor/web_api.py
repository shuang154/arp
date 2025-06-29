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
    """Web API服务器"""
    
    def __init__(self, state_cache, config):
        self.state_cache = state_cache
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
                stats = self.state_cache.get_statistics()
                return jsonify({
                    'status': 'running',
                    'statistics': stats,
                    'active_attacks': len(self.state_cache.get_active_attacks()),
                    'successful_attacks': len(self.state_cache.get_successful_attacks())
                })
            except Exception as e:
                self.logger.error(f"Status API error: {e}")
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/attacks')
        def get_attacks():
            """获取攻击信息"""
            try:
                return jsonify({
                    'active_attacks': self.state_cache.get_active_attacks(),
                    'successful_attacks': self.state_cache.get_successful_attacks(),
                    'attack_sessions': [
                        {
                            'target_ip': session.target_ip,
                            'start_time': session.start_time,
                            'duration': session.duration,
                            'attack_type': session.attack_type,
                            'status': session.status
                        }
                        for session in self.state_cache.get_attack_sessions().values()
                    ]
                })
            except Exception as e:
                self.logger.error(f"Attacks API error: {e}")
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/cache')
        def get_cache_info():
            """获取缓存信息"""
            try:
                return jsonify(self.state_cache.get_statistics())
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
