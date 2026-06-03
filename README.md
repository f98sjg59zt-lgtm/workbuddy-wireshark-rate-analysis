# Wireshark Transmission Rate Analysis

**WorkBuddy 自定义 Skill** — 基于 tshark 的 TCP 传输速率瓶颈分析工具，执行 10 步结构化分析流水线。

## 功能概述

针对「实测传输速率远低于理论 BDP 上限」的场景，对 PCAP/PCAPNG 抓包文件执行 10 步结构化分析流水线：

1. **会话概览** — 流量统计、会话识别、时间跨度
2. **实际最大速率统计** — 各方向吞吐量
3. **分方向 RTT 分析** — 往返时延分布
4. **理论最大速率计算（双方法）** — BDP 法 + 瓶颈法
5. **实际 vs 理论对比** — 利用率评估
6. **Expert 速率关联扫描** — 异常事件关联
7. **窗口在途对比** — 窗口瓶颈检测
8. **时间模式聚类** — 时间维度特征提取
9. **三层瓶颈判定** — TCP 层 / 应用层 / 网络层定位
10. **根因结论与调优建议** — 可落地方案

**适用协议**：TCP（SSH/scp、HTTP、自定义 TCP 协议）

**前置条件**：
- tshark 已安装
- 待分析的 pcap/pcapng 文件路径已知

## 安装方式

### 方法一：WorkBuddy 直接导入

1. 将本仓库的 `Wireshark Transmission Rate Analysis` 文件夹下载为 zip
2. 打开 WorkBuddy → **技能管理** → **上传技能包**
3. 选择解压后的文件夹，确认导入

### 方法二：手动安装

1. 复制 `Wireshark Transmission Rate Analysis` 文件夹到 `~/.workbuddy/skills/` 目录下
2. 重启 WorkBuddy 或刷新技能列表

## 触发关键词

```
传输速率慢 | 速率瓶颈 | PCAP 分析 | 数据包分析 | BIF 分析 |
RTT 分析 | 抓包分析 | pcap 分析 | TCP 速率慢 | 窗口分析 | 在途字节
```

## 文件结构

```
Wireshark Transmission Rate Analysis/
├── SKILL.md                    # 核心 Skill 定义文件
├── examples/
│   └── case-study-ssh-transfer.md    # SSH 传输案例研究
└── references/
    ├── input-template.md        # 用户输入模板
    ├── report-template.md       # 输出报告模板
    ├── resources.md             # 资源与参考资料
    └── tshark-cheatsheet.md     # tshark 常用命令速查
```

## 使用示例

在 WorkBuddy 对话中输入类似以下内容即可触发：

> "帮我分析这个 pcap 文件的传输速率瓶颈：/path/to/capture.pcapng"

Skill 会自动引导你完成抓包点位置确认、网络信息收集，然后执行完整 10 步分析流水线并输出报告。

## License

MIT License
