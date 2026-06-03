# 常用 tshark 命令速查

## 基础统计

```bash
# 会话统计（含平均 bits/s）
tshark -r <pcap> -q -z conv,tcp

# 协议分层
tshark -r <pcap> -q -z io,phs

# Expert Info
tshark -r <pcap> -q -z expert

# 抓包元信息
capinfos <pcap>

# IO 统计（按 100ms 间隔，针对指定流）
tshark -r <pcap> -q -z "io,stat,0.1,tcp.stream==<N>"
```

## TCP 专项

```bash
# 流编号
tshark -r <pcap> -T fields -e tcp.stream -Y "ip.addr==X && ip.addr==Y" | sort -u

# RTT（服务端视角 = 物理RTT）
tshark -r <pcap> -Y "ip.src==<服务端> && tcp.analysis.ack_rtt>0" \
  -T fields -e tcp.analysis.ack_rtt | sort -n | \
  awk '{a[NR]=$1} END{print "p50="a[int(NR*0.5)],"p90="a[int(NR*0.9)],"p99="a[int(NR*0.99)]}'

# RTT（客户端视角 = 应用延迟）
tshark -r <pcap> -Y "ip.src==<客户端> && tcp.analysis.ack_rtt>0" \
  -T fields -e tcp.analysis.ack_rtt | sort -n | \
  awk '{a[NR]=$1} END{print "p50="a[int(NR*0.5)],"p90="a[int(NR*0.9)],"p99="a[int(NR*0.99)]}'

# 接收窗口
tshark -r <pcap> -Y "ip.src==<服务端> && tcp.window_size>0" \
  -T fields -e tcp.window_size | sort -n | \
  awk '{a[NR]=$1} END{print "p50="a[int(NR*0.5)],"p90="a[int(NR*0.9)],"max="a[NR]}'

# 在途字节
tshark -r <pcap> -Y "ip.src==<客户端> && tcp.analysis.bytes_in_flight" \
  -T fields -e tcp.analysis.bytes_in_flight | sort -n | \
  awk '{a[NR]=$1} END{print "p50="a[int(NR*0.5)],"p90="a[int(NR*0.9)],"p99="a[int(NR*0.99)],"max="a[NR]}'

# MSS
tshark -r <pcap> -Y "tcp.stream==<N> && tcp.flags.syn==1" -T fields -e tcp.options.mss_val

# 丢包率
total=$(tshark -r <pcap> -Y "tcp.stream==<N> && ip.src==<发送端> && tcp.len>0" | wc -l | tr -d ' ')
retrans=$(tshark -r <pcap> -Y "tcp.stream==<N> && tcp.analysis.retransmission" | wc -l | tr -d ' ')
echo "丢包率=$(echo "scale=4; $retrans/$total*100" | bc)%"

# TCP 流图形数据导出
tshark -r <pcap> -q -z "tcp.stream_graph,round_trip_time,0"
```

## 诊断深化

```bash
# WScale（窗口扩大因子）— 判断 rwnd 是否可信
tshark -r <pcap> -Y "tcp.flags.syn==1 || tcp.flags.syn==1&&tcp.flags.ack==1" \
  -T fields -e frame.number -e ip.src -e tcp.srcport -e tcp.dstport -e tcp.options.wscale

# 按流统计重传 — 精准定位丢包最严重的流
tshark -r <pcap> -q -z "conv,tcp" | head -1
tshark -r <pcap> -Y "tcp.analysis.retransmission" -T fields -e tcp.stream | sort | uniq -c | sort -rn

# 时间间隙快速查看 — Step 8 前置探测，判断是否存在周期性停顿
tshark -r <pcap> -Y "ip.src==<发送端IP> && tcp.len>0" \
  -T fields -e frame.time_relative -e tcp.time_delta | \
  awk -F'\t' '{if($2>0.005) gaps++; total++} END{printf "总包=%d 间隙>5ms=%d (%.1f%%)\n", total, gaps, gaps/total*100}'
```

## 指定流过滤

```bash
# 先找流编号
tshark -r <pcap> -T fields -e tcp.stream -Y "ip.addr==X && ip.addr==Y" | sort -u

# 对流 N 操作
tshark -r <pcap> -Y "tcp.stream==<N>" -w stream_N.pcap
```
