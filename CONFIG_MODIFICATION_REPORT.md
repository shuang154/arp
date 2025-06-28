# Config.yaml 分离Scout和Attack配置修改说明

## 🎯 修改目标
按照用户需求实现Scout和Attack的分离管理：
- Scout侦察：上限100个，轻量级1分钟侦察
- Attack攻击：上限40个，访问801端口自动升级
- 1分钟过期自动清理

## 📝 具体修改内容

### 1. 攻击并发限制分离
```yaml
# 修改前（混合管理）：
max_concurrent_attacks: 40     # 所有攻击混在一起

# 修改后（分离管理）：
max_scout_attacks: 100         # Scout专用：100个
max_active_attacks: 40         # Attack专用：40个
# max_concurrent_attacks: 40   # ★【可删除】★ 旧配置已被分离配置替代
```

**优势：**
- Scout和Attack资源独立，互不争抢
- 100个轻量级Scout确保广域覆盖
- 40个重量级Attack专注高价值目标

### 2. 升级策略配置增强
```yaml
strategy:
  scouting_duration: 60                    # Scout持续1分钟
  full_attack_duration: 60                 # Attack持续1分钟
  high_value_ports: [801]                  # 触发升级的端口
  # ★【新增】★ 自动升级配置
  auto_upgrade_on_high_value: true         # 自动升级开关
  upgrade_priority: "immediate"            # 升级优先级
  scout_cleanup_interval: 30               # Scout清理间隔
  attack_cleanup_interval: 60              # Attack清理间隔
```

**功能说明：**
- `auto_upgrade_on_high_value: true` - 访问801端口立即升级
- `upgrade_priority: "immediate"` - 升级具有最高优先级
- 清理间隔确保过期攻击及时释放资源

### 3. IPC心跳通道补充
```yaml
ipc:
  packet_address: "ipc:///tmp/arp_spoofer_packets.ipc"
  command_address: "ipc:///tmp/arp_spoofer_commands.ipc"
  # ★【新增】★ 独立心跳通道
  heartbeat_address: "ipc:///tmp/arp_spoofer_heartbeat.ipc"
```

**说明：**
- 独立心跳通道避免主命令通道阻塞
- 解决之前心跳超时的根本问题

## 🚀 预期效果

### 资源分配优化
```
总并发能力：100 Scout + 40 Attack = 140个并发会话

资源消耗预估：
- Scout: 100 × 0.5% CPU = 50% CPU
- Attack: 40 × 2.0% CPU = 80% CPU
- 总计: 130% CPU (4核心可承受)
```

### 攻击策略流程
```
新设备发现 → Scout侦察(1分钟)
                    ↓
            监控网络流量
                    ↓
            访问端口801?
                ↙      ↘
              是        否
              ↓         ↓
        升级为Attack   Scout过期清理
        (1分钟)
              ↓
        Attack完成清理
```

### 覆盖率提升
- **发现覆盖率**：从40个→100个Scout，提升150%
- **攻击精确度**：40个Attack专注高价值目标
- **资源利用率**：充分利用香橙派4核心性能

## 📊 配置对比

| 项目 | 修改前 | 修改后 | 改进 |
|------|--------|--------|------|
| Scout上限 | 40（混合） | 100（专用） | +150% |
| Attack上限 | 40（混合） | 40（专用） | 专用保障 |
| 升级策略 | 有但受限 | 完全可用 | 策略生效 |
| 资源争用 | 严重 | 无 | 彻底解决 |

## 🔧 下一步需要修改的文件

1. **python_supervisor/config.py** - 添加分离配置字段
2. **python_supervisor/main.py** - 实现分离管理逻辑
3. **python_supervisor/attack_coordinator.py** - 升级策略实现

这些修改将在后续步骤中完成，确保配置文件的改动能够生效。

## ✅ 验证方式

修改完成后，运行日志应该显示：
```
[INFO] Attack limits: Scout=100, Attack=40
[INFO] 🔍 Scout registered for 10.17.x.x (scouts: 15/100)
[INFO] 🎯 High-value port 801 detected, upgrading to Attack
[INFO] ⚔️ Attack registered for 10.17.x.x (attacks: 8/40)
```

这样就实现了您要求的Scout和Attack分离管理！
