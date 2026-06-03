---
name: Wireshark Transmission Rate Analysis
description: 专项 PCAP 数据包速率瓶颈分析工具。基于 Wireshark/tshark 对抓包文件执行 10 步结构化分析流水线——从会话概览、实际最大速率统计、分方向 RTT 分析、理论最大速率计算（双方法）、实际 vs 理论对比、Expert 速率关联扫描、窗口在途对比、时间模式聚类到三层瓶颈判定，最终输出根因结论与可落地的调优建议。适用于 TCP 传输速率远低于理论 BDP 上限的场景（SSH/HTTP/自定义协议），不支持 UDP 限速分析。触发关键词：传输速率慢、速率瓶颈、PCAP 分析、数据包分析、BIF 分析、RTT 分析、抓包分析、pcap 分析、TCP 速率慢、窗口分析、在途字节。
agent_created: true
---

# 传输速率慢 — 数据包分析专项 Skill

## 概述

针对「实测传输速率远低于理论 BDP 上限」的场景，对 PCAP/PCAPNG 抓包文件执行 10 步结构化分析流水线，定位瓶颈位于 **TCP 层、应用层还是网络层**，并输出可落地的优化方案。

**适用协议**：TCP（SSH/scp、HTTP、自定义 TCP 协议）  
**不适用**：UDP 限速分析、纯丢包排查（丢包率 >1% 应先用其他工具排查链路质量）

## 前置条件

- tshark 已安装，可直接调用命令行
- 待分析的 pcap/pcapng 文件路径已知
- 具备以下基本网络信息（缺失项标注「未知」）：
  - 数据流向（哪个 IP 发往哪个 IP）
  - 抓包点位置（发送端/接收端/中间镜像）

> 📋 用户输入模板见 [`references/input-template.md`](references/input-template.md)

---

## 分析前确认：抓包点位置

> ⚠️ 抓包点位置直接影响 BIF 可靠性、RTT 解读方向、rwnd 读取可信度。**必须在开始分析前确认。**

### 流程

```
┌──────────────────────────────────────────────────┐
│  1. 主动询问用户                                    │
│     "抓包文件是在哪一端采集的？                      │
│      A. 发送端      B. 接收端                       │
│      C. 中间镜像端口  D. 不确定"                     │
├──────────────────────────────────────────────────┤
│  2. 若用户提供（A/B/C） → 直接采用，置信度 高         │
├──────────────────────────────────────────────────┤
│  3. 若用户选 D 或未提供 → TTL 自动推断（见下方）       │
└──────────────────────────────────────────────────┘
```

### TTL 自动推断方法

```bash
# 对两个方向分别统计最常见的 TTL 值
tshark -r <pcap_file> -Y "ip.src==<A端IP> && ip.dst==<B端IP>" \
  -T fields -e ip.ttl | sort -n | uniq -c | sort -rn | head -5

tshark -r <pcap_file> -Y "ip.src==<B端IP> && ip.dst==<A端IP>" \
  -T fields -e ip.ttl | sort -n | uniq -c | sort -rn | head -5
```

**推断规则**：

| A→B 最常见 TTL | B→A 最常见 TTL | 推断 | 置信度 |
|:--|:--|:--|:--|
| 64 / 128 / 255 | 非初始值 | **A 端抓包** | 🟡 推断（非 100%） |
| 非初始值 | 64 / 128 / 255 | **B 端抓包** | 🟡 推断（非 100%） |
| 两者均为初始值 | 两者均为初始值 | **无法判定**（同网段/虚拟链路） | 🔴 不确定 |
| 两者均非初始值 | 两者均非初始值 | **中间链路抓包** | 🟡 推断（非 100%） |

> ⚠️ **声明**：TTL 推断基于常见操作系统默认值（Linux/Android=64, Windows=128, 网络设备=255），以下情况可能误判：
> - 发送端主动修改了初始 TTL
> - 中间设备（如负载均衡器）重写了 TTL
> - 隧道封装（VXLAN/GRE/IPsec）增加额外 IP 头

> 📄 输出格式见 [`references/report-template.md`](references/report-template.md) 第 2 节「抓包点确认」

---

## 10 步分析流水线

每步必须输出：**使用的命令/过滤器 → 原始数据摘要 → 解读与判断**。

---

### Step 1：会话概览

**目的**：确认主流量方向、会话数量和流量分布，获取各流平均速率。

```bash
tshark -r <pcap_file> -q -z conv,tcp
```

`conv,tcp` 输出已包含 `Bits/s A→B` 和 `Bits/s B→A` 列。

> 📄 输出格式见 [`references/report-template.md`](references/report-template.md) 第 3 节「会话概览」

**判断要点**：
- 确认主流量方向与用户描述是否一致
- 若存在多条并发流，评估各流对带宽的竞争关系
- 补充协议分层：`tshark -r <pcap> -q -z io,phs`
- 记录每个 TCP 流的流编号：
  ```bash
  tshark -r <pcap> -T fields -e tcp.stream -Y "ip.addr==<IP> && tcp.port==<port>" | sort -u
  ```

> 🔍 本步骤结束后，确认抓包点（参见「分析前确认」）。后续步骤中 BIF 可信度、RTT 解读方向均依赖此信息。

#### Step 1b：多流竞争诊断（可选）

> ⚠️ **触发条件**：`conv,tcp` 显示 ≥2 条有效数据流时，**必须执行本步骤**。单流场景跳过。

**目的**：判定多流共存的瓶颈是「流间不公平竞争」还是「各流独立受限」。

> 📄 输出格式（含竞争模式判定表）见 [`references/report-template.md`](references/report-template.md) 第 3b 节「多流竞争诊断」

**1b-1 — 按时间窗口对比各流吞吐量**：

```bash
# 对每条流按 100ms 窗口导出吞吐量
for STREAM in 0 1 2 3; do
  tshark -r <pcap_file> -q -z "io,stat,0.1,tcp.stream==$STREAM&&ip.src==<发送端IP>" | \
    awk '/^[0-9]/{print $1, $3}' > "stream_${STREAM}_rate.txt"
done
```

**1b-2 — 总速率饱和度检测**：

```bash
# 将各流同一窗口的吞吐量求和，看是否逼近链路带宽上限
paste stream_0_rate.txt stream_1_rate.txt stream_2_rate.txt stream_3_rate.txt | \
  awk '{total=$2+$4+$6+$8; if(total>max) max=total; print $1, total} END{print "总速率峰值=", max}'
```

**1b-3 — 不公平度检测**：

```bash
# 统计各流独立的最大速率和均值，计算标准差
for STREAM in 0 1 2 3; do
  awk '{sum+=$2; cnt++; if($2>max) max=$2} END{printf "流%d 均值=%.1fMbps 峰值=%.1fMbps\n", '$STREAM', sum/cnt/1e6, max/1e6}' stream_${STREAM}_rate.txt
done
```

**关键判断**：
- **竞争饱和 + 不公平** → 瓶颈在流调度/ECMP/策略，各流单看效率低是竞争结果而非自身缺陷
- **竞争饱和 + 公平** → 正常多流竞争，调优方向是增加并行度或提升链路带宽
- **不饱和** → 瓶颈不在竞争，回到各流独立分析流程

---

### Step 2：实际真实最大传输速率

**目的**：对 Step 1 中每条 TCP 流，统计实际真实传输的 **最大瞬时速率**（非平均），作为后续与理论速率对比的基准。

**方法**：按 100ms 间隔统计吞吐量，取最大值：

```bash
tshark -r <pcap_file> -q -z "io,stat,0.1,tcp.stream==<N>&&ip.src==<发送端IP>"
```

或从原始数据精确计算：

```bash
tshark -r <pcap_file> -Y "tcp.stream==<N> && ip.src==<发送端IP>" \
  -T fields -e frame.time_relative -e tcp.len | \
  awk -F'\t' '
  { interval=int($1/0.1); bytes[interval]+=$2 }
  END {
    max_rate=0; sum_rate=0; cnt=0;
    for(i in bytes) {
      rate=bytes[i]*8*10;    # bits/s (100ms → ×10)
      if(rate>max_rate) max_rate=rate;
      sum_rate+=rate; cnt++;
    }
    avg_rate=sum_rate/cnt;
    printf "流%-2d | 平均速率=%.1f Mbps | 最大速率=%.1f Mbps\n", <N>, avg_rate/1e6, max_rate/1e6
  }'
```

> 📄 输出格式见 [`references/report-template.md`](references/report-template.md) 第 4 节「实际最大传输速率」

**判断要点**：
- 最大速率远高于平均速率 → 存在间歇性停顿（应用层供给或拥塞控制削减）
- 最大速率 ≈ 平均速率 → 传输稳定，瓶颈可能在上限限制
- ⚠️ **抓包点影响**：中间链路或接收端抓包时，观测到的速率可能受镜像丢包、采样精度影响，实际最大速率 ≤ 观测值

---

### Step 3：RTT 分析——**必须分方向！**

> ⚠️ **核心陷阱**：`tcp.analysis.ack_rtt` 挂在 **ACK 的发送者** 上，不是数据包的发送者！

**方向 1 — 物理网络 RTT**（服务端发出的 ACK）：
```bash
tshark -r <pcap_file> -Y "ip.src == <服务端IP> && tcp.analysis.ack_rtt > 0" \
  -T fields -e tcp.analysis.ack_rtt | sort -n | \
  awk '{a[NR]=$1} END{print "p50="a[int(NR*0.5)],"p90="a[int(NR*0.9)],"p99="a[int(NR*0.99)],"max="a[NR]}'
```

**方向 2 — 应用层处理延迟**（客户端发出的 ACK）：
```bash
tshark -r <pcap_file> -Y "ip.src == <客户端IP> && tcp.analysis.ack_rtt > 0" \
  -T fields -e tcp.analysis.ack_rtt | sort -n | \
  awk '{a[NR]=$1} END{print "p50="a[int(NR*0.5)],"p90="a[int(NR*0.9)],"p99="a[int(NR*0.99)],"max="a[NR]}'
```

> 📄 输出格式见 [`references/report-template.md`](references/report-template.md) 第 5 节「RTT 分方向分析」

**判断要点**：
- 若服务端 RTT（物理）远小于客户端 RTT（应用），瓶颈在应用层
- 若两者都很大（>10ms），瓶颈在网络路径
- 若 p99 >> p50，说明存在间歇性抖动
- ⚠️ **抓包点影响**：中间链路抓包时，`ack_rtt` 测量的是抓包点到对端的 RTT，非端到端 RTT，物理 RTT 可能被低估

> 💡 更多 RTT/WScale 命令见 [`references/tshark-cheatsheet.md`](references/tshark-cheatsheet.md)

---

### Step 4：理论最大传输速率计算

**目的**：使用两种方法计算每条 TCP 流的理论最大吞吐量。

#### 前置数据获取

```bash
# 1) 接收窗口 rwnd（服务端→客户端方向的 window_size）
tshark -r <pcap_file> -Y "tcp.stream==<N> && ip.src==<服务端IP> && tcp.window_size>0" \
  -T fields -e tcp.window_size | sort -n | \
  awk '{a[NR]=$1} END{print "rwnd_p50="a[int(NR*0.5)],"rwnd_max="a[NR]}'

# 2) MSS（从 SYN/SYN-ACK 中提取）
tshark -r <pcap_file> -Y "tcp.stream==<N> && tcp.flags.syn==1" -T fields -e tcp.options.mss_val

# 3) 丢包率 p
total=$(tshark -r <pcap_file> -Y "tcp.stream==<N> && ip.src==<发送端IP> && tcp.len>0" | wc -l | tr -d ' ')
retrans=$(tshark -r <pcap_file> -Y "tcp.stream==<N> && tcp.analysis.retransmission" | wc -l | tr -d ' ')
echo "丢包率=$(echo "scale=6; $retrans/$total" | bc)"

# 4) RTT（使用 Step 3 物理 RTT 的 p50）
```

> 💡 更多 rwnd/MSS/丢包率命令见 [`references/tshark-cheatsheet.md`](references/tshark-cheatsheet.md)

> ⚠️ **抓包点影响**：若在中间链路或接收端抓包，服务端发来的 `window_size` 可能已经过中间设备修改或受抓包延迟影响，rwnd 读数可信度取决于抓包点位置。

#### 方法一（理想化）：窗口/RTT 模型

$$最大吞吐量 ≈ rwnd / RTT$$

**计算示例**：rwnd=24KB, RTT=200μs → 24576×8/0.0002 ≈ **983 Mbps**

#### 方法二（实用型）：Mathis 公式

$$最大吞吐量 = \frac{MSS}{RTT} \times \frac{1}{\sqrt{p}}$$

其中 MSS=最大分段大小，RTT=物理往返时间，p=丢包率（0<p<1）。

**计算示例**：MSS=1460B, RTT=200μs, p=0.000732 → (1460×8/0.0002)×(1/√0.000732) ≈ **2158 Mbps**

> ⚠️ Mathis 公式假设 TCP Reno 理想行为，AQM/ECN/CUBIC/BBR 等会使结果偏离。

> 📄 输出格式见 [`references/report-template.md`](references/report-template.md) 第 6 节「理论最大速率计算」

**判断要点**：
- 方法一更贴近实际可达上限；方法二在丢包率极低时会显著偏高
- 后续 Step 5 使用 **方法一的结果** 作为理论基准

---

### Step 5：实际 vs 理论最大传输速率对比

**目的**：量化传输效率，判断瓶颈类型。

> 📄 输出格式（含效率判定标准表）见 [`references/report-template.md`](references/report-template.md) 第 7 节「实际 vs 理论速率对比」

**核心判断**：
- 效率低但方法一数值高（rwnd 大 + RTT 小）→ **应用层是瓶颈**，TCP 准备了足够的"跑道"但应用层没填满
- 效率低且方法一数值也低 → **TCP/网络层是瓶颈**
- 效率高 → TCP 参数已充分优化，进一步提速需换协议/并行传输

---

### Step 6：Expert Info 扫描与分析

**目的**：快速定位异常事件，**着重分析与传输速率相关的异常项**。

```bash
tshark -r <pcap_file> -q -z expert
```

> 📄 输出格式（含异常统计表 + 速率关联判断标准）见 [`references/report-template.md`](references/report-template.md) 第 8 节「Expert Info 扫描」

**判断标准**：
- 重传率 < 0.1%：路径干净，排除网络丢包
- 重传率 0.1-1%：链路轻度丢包，可能贡献部分降速
- 重传率 > 1%：链路质量问题，优先排查物理层
- ZeroWindow > 0：接收端处理能力不足
- Window Full > 0：发送端受窗口约束 → 关联 Step 7 分析

> 💡 如需按流精确定位重传分布和 WScale 值，见 [`references/tshark-cheatsheet.md`](references/tshark-cheatsheet.md)

---

### Step 7：窗口与在途字节（rwnd vs BIF）对比

**目的**：判断 TCP 接收窗口（rwnd）是否限制了发送方的在途数据量（BIF）。

**7a — 接收窗口（rwnd）分布**：
```bash
tshark -r <pcap_file> -Y "ip.src == <服务端IP> && tcp.window_size > 0" \
  -T fields -e tcp.window_size | sort -n | \
  awk '{a[NR]=$1} END{print "p50="a[int(NR*0.5)],"p75="a[int(NR*0.75)],"p90="a[int(NR*0.9)],"max="a[NR]}'
```

**7b — 在途字节（BIF）分布**：
```bash
tshark -r <pcap_file> -Y "ip.src == <客户端IP> && tcp.analysis.bytes_in_flight" \
  -T fields -e tcp.analysis.bytes_in_flight | sort -n | \
  awk '{a[NR]=$1} END{print "p50="a[int(NR*0.5)],"p75="a[int(NR*0.75)],"p90="a[int(NR*0.9)],"p99="a[int(NR*0.99)],"max="a[NR]}'
```

> 📄 输出格式见 [`references/report-template.md`](references/report-template.md) 第 9 节「窗口与在途字节对比」

**核心判断逻辑**：
- **BIF 频繁触顶 rwnd**：TCP 流控是瓶颈 → 调大 rwnd 或减少 RTT
- **BIF 远小于 rwnd**：TCP 层无瓶颈 → 瓶颈在应用层或拥塞控制（cwnd 限制）
- **BIF 最大值远超 rwnd**：通常由 TSO 合并或 SSH/TLS 加密流自有流控层产生

> ⚠️ **BIF 可信度**（依据「分析前确认」的抓包点位置判定）：
> - **发送端抓包**（🟢 高置信度）→ BIF 真实可信，精确反映在途数据量
> - **接收端/中间链路抓包**（🟡/🔴）→ BIF 容易高估，不可作为精确判定依据，相关结论必须加注「BIF 可信度有限」

> ⚠️ **WScale 未知声明**：若 pcap 不含 SYN/SYN-ACK，窗口扩大因子未知，所有窗口相关结论必须标注「WScale 未知，窗口可能远大于观测值」。

> 💡 更多窗口/BIF/WScale 命令见 [`references/tshark-cheatsheet.md`](references/tshark-cheatsheet.md)

---

### Step 8：时间模式分析——定位「等待事件」

**目的**：识别发送端是否存在周期性停顿，区分「TCP 层拥塞控制削减」和「应用层供给限速」。

**8a — 提取发送端数据包时间间隔**：
```bash
tshark -r <pcap_file> -Y "ip.src == <客户端IP> && tcp.len > 0" \
  -T fields -e frame.number -e frame.time_relative -e tcp.len -e tcp.time_delta
```

**8b — 标记「大间隙」并聚类**（间隔 >5ms 标记为间隙点）：

```bash
tshark -r <pcap_file> -Y "ip.src == <客户端IP> && tcp.len > 0" \
  -T fields -e frame.time_relative -e tcp.len -e tcp.time_delta | \
  awk -F'\t' '
  BEGIN { cluster=0; cluster_bytes=0; cluster_pkts=0; cluster_start=0; prev_time=0 }
  {
    time=$1; len=$2; delta=$3;
    if (cluster_pkts == 0) { cluster_start = time; }
    if (delta > 0.005 && cluster_pkts > 0) {
      # 间隙前的簇持续时间 = 上一个包的时间 - 簇开始时间
      duration = prev_time - cluster_start;
      if (duration > 0) {
        rate = (cluster_bytes * 8) / duration / 1000;
        printf "簇%-3d | 字节=%-10d | 包数=%-5d | 间隙=%-7.2fms | 等效速率=%-8.0fKbps\n",
          cluster, cluster_bytes, cluster_pkts, delta*1000, rate;
      } else {
        printf "簇%-3d | 字节=%-10d | 包数=%-5d | 间隙=%-7.2fms | 等效速率=(单包)\n",
          cluster, cluster_bytes, cluster_pkts, delta*1000;
      }
      cluster++; cluster_bytes=0; cluster_pkts=0;
      cluster_start = time;
    }
    cluster_bytes += len; cluster_pkts++;
    prev_time = time;
  }
  END {
    if (cluster_bytes > 0) {
      duration = prev_time - cluster_start;
      if (duration > 0) {
        rate = (cluster_bytes * 8) / duration / 1000;
        printf "簇%-3d | 字节=%-10d | 包数=%-5d | 间隙=尾簇 | 等效速率=%-8.0fKbps\n",
          cluster, cluster_bytes, cluster_pkts, rate;
      } else {
        printf "簇%-3d | 字节=%-10d | 包数=%-5d | 间隙=尾簇\n",
          cluster, cluster_bytes, cluster_pkts;
      }
    }
  }'
```

> 📄 输出格式见 [`references/report-template.md`](references/report-template.md) 第 10 节「时间模式分析」

**核心判断**：
- **间隙呈固定周期** → 应用层限速模式（SSH 通道窗口 refill / 应用层读写循环）
- **间隙随机分布** → TCP 拥塞控制或网络抖动
- **间隙与 RTT 数量级相当** → 可能是接收端窗口更新延迟
- **等效速率始终低于 BDP 理论值** → 发送端供给能力不足

---

### Step 9：三层瓶颈综合判定

基于 Step 1-8 的数据，逐层判定：

> 📄 输出格式见 [`references/report-template.md`](references/report-template.md) 第 11 节「三层瓶颈判定」

```
┌─────────────────────────────────────────────────┐
│                  TCP 层瓶颈判定                    │
├─────────────────────────────────────────────────┤
│ rwnd 是否限制 BIF？         → [是/否，证据：BIF_p90 / rwnd_max]  │
│ 拥塞控制是否频繁削减？       → [是/否，BIF 骤降次数/周期]           │
│ 重传是否贡献降速？           → [是/否，重传率___%]               │
│ Window Full 是否出现？      → [是/否，频次]                    │
│ WScale 是否已知？            → [是/否，窗口结论置信度]            │
├─────────────────────────────────────────────────┤
│                 应用层瓶颈判定                      │
├─────────────────────────────────────────────────┤
│ 是否呈周期性等待？           → [是/否，周期=___ms]              │
│ 等待期间在做什么？            → [推测：加密/磁盘IO/窗口update]     │
│ 等效发送速率上限？           → [___Mbps，来源：簇等效速率]        │
│ 实际/理论效率(方法一)？      → [___%，来自 Step 5]            │
├─────────────────────────────────────────────────┤
│                 网络层瓶颈判定                      │
├─────────────────────────────────────────────────┤
│ 物理 RTT 是否过大？          → [是/否，p50=___μs]             │
│ 链路带宽是否已满载？          → [是/否]                       │
│ MTU/分片是否异常？           → [是/否]                       │
│ 丢包率是否影响 Mathis 上限？  → [是/否，p=___%]               │
├─────────────────────────────────────────────────┤
│              抓包点与结论置信度                    │
├─────────────────────────────────────────────────┤
│ 抓包点位置：                  → [A端 / B端 / 中间链路]         │
│ 判定来源：                    → [用户确认 / TTL推断]           │
│ 置信度：                      → [🟢高 / 🟡推断 / 🔴不确定]    │
└─────────────────────────────────────────────────┘
```

**判定优先级**：应用层 > TCP 层 > 网络层（绝大多数传输速率慢的根因在应用层或 TCP 配置）

---

### Step 10：结论 + 调优建议

> 📄 按 [`references/report-template.md`](references/report-template.md) 第 12 节「结论与建议」的格式输出：一句话根因 → 三层瓶颈总结表 → 理论速率对比总结 → 优化方案表（P0/P1 按可行性排序）→ 分析声明。

---

## ⚠️ 分析禁忌（必须遵守）

### R1 — RTT 方向陷阱
- `tcp.analysis.ack_rtt` 挂在 **ACK 的发送者**上
- **服务端发出的 ACK** → 物理链路 RTT（用于 BDP/Mathis 计算）
- **客户端发出的 ACK** → 应用层处理延迟（不能用于理论速率计算）

### R2 — WScale 未知声明
- 若 pcap 不含 SYN/SYN-ACK，WScale 值为 -1（未知）
- 所有窗口相关结论必须标注「WScale 未知，窗口可能更大」

### R3 — 加密流陷阱
- SSH/TLS 在 TCP 上有自己的流控层
- 若发包呈明显周期性（15-65ms 间隙），先怀疑应用层

### R4 — 理论速率公式选择
- **方法一（理想化）**：`rwnd / RTT`（更贴近实际可达上限）
- **方法二（Mathis）**：`(MSS / RTT) × (1 / √p)`（丢包率极低时会显著偏高）
- RTT 必须用物理 RTT（R1 的正确方向）

### R5 — BIF 抓包点依赖
- 发送端抓包：BIF 可信；接收端/中间链路抓包：容易高估
- 抓包点由「分析前确认」章节统一判定，所有 BIF 相关结论必须标注可信度
- 若 TTL 推断无法确定（🔴 不确定），BIF 结论必须保守：仅作为参考，不做精确判定

### R6 — 最大速率计算粒度
- Step 2 的 100ms 间隔是经验值，可通过 `io,stat,<interval>` 调整
- 粒度过大（>1s）会平滑掉瞬时峰值；粒度过小（<10ms）可能产生虚假高值

---

## 子文件索引

| 文件                                                                           | 内容             | 使用时机                          |
| :--------------------------------------------------------------------------- | :------------- | :---------------------------- |
| [`references/input-template.md`](references/input-template.md)               | 用户输入模板         | 分析开始前，按模板收集用户信息               |
| [`references/report-template.md`](references/report-template.md)             | 输出报告模板（完整格式）   | 每步输出前 Read 对应节查看格式            |
| [`references/tshark-cheatsheet.md`](references/tshark-cheatsheet.md)         | 常用 tshark 命令速查 | Step 3/4/6/7 中按 `💡` 提示查看补充命令 |
| [`references/resources.md`](references/resources.md)                         | 关联 Skill 索引    | 遇到非 TCP 协议（如 UDP）、未知协议时查看     |
| [`examples/case-study-ssh-transfer.md`](examples/case-study-ssh-transfer.md) | 完整实战案例         | 首次使用或不确定分析思路时先 Read，对照案例执行    |
