# Objective 2 — Attack, Detect, and Stop

Run recorded on 2026-09-25. Commands below are for the indicated VM; none requires changing the four-switch Mininet topology. The screenshots for submission are kept in the lab document.

## 2.1 — PacketIn flood attempt

The Mininet script discovers the OpenFlow controller from `s1`'s OVS configuration, ignoring the separate passive controller entry. It opens one TCP connection from the Mininet VM's internal address, negotiates OpenFlow 1.3 as a temporary switch, and writes crafted PacketIn messages containing ARP packets. It uses Python `socket` and `struct` for packet construction.

```bash
# Mininet VM: discovery only
sudo python3 ~/lab4-session/attack.py

# Mininet VM: the demonstrated burst
sudo python3 ~/lab4-session/attack.py --send --count 200 --rate 250 --source-port 4100
```

The script reported `10.224.78.132:6653`, sent 200/200 messages from `10.224.76.126:4100`, and the SDN monitor counted 200 from that same connection. The alert fired at 101 within five seconds.

## 2.2 — Observed controller and network behavior

```bash
# Mininet VM: a longer observation window
sudo python3 ~/lab4-session/attack.py --send --count 3000 --rate 100 --source-port 4101

# Mininet CLI: normal connectivity while the burst is running
pingall

# SDN VM: controller REST responsiveness
curl -sS -o /dev/null -w 'HTTP %{http_code}; time=%{time_total}s\n' http://127.0.0.1:8080/wm/core/controller/switches/json
```

The reported Mininet result was **0% dropped (12/12 received)**. Repeated REST checks returned HTTP 200 in roughly **0.003–0.007 s**. A later 10,000-message run at 2,000/s did not produce a visible REST response-time change. Normal `pingall` traffic itself produced small PacketIn counts on the four real switch connections. This run did **not** demonstrate a service outage or measurable REST slowdown. Existing installed flows may help forwarding continue; that explanation was not independently proven by this test.

The sender's `Sent` output confirms TCP writes, and the monitor confirms OpenFlow-framed messages on the wire. Neither alone establishes how many messages Floodlight handled. The script's handshake-completed message is based on its responses to controller requests, not on checking Floodlight's registered-switch list. A stronger controller-side check for a future run is to compare this cumulative counter immediately before and after the burst, without `pingall` between reads:

```bash
curl -sS http://127.0.0.1:8080/wm/core/counter/ControllerCounters/packet-in/json
```

## 2.3 — Detection

```bash
# SDN VM: alert only; no firewall change
sudo python3 ~/lab4-session/monitor.py --interface ens33 --threshold 100 --window 5 --refresh 1
```

The monitor groups PacketIns by source IP/port and destination IP/port. It keeps timestamps in a rolling five-second deque and alerts once per connection when the count **exceeds** 100. The demonstrated attack triggered:

```text
ALERT: 101 PacketIn messages from 10.224.76.126:4100 within 5.0s (limit 100).
```

Normal switch connections showed only a few PacketIns in comparable five-second periods, supporting the chosen threshold. The monitor reports a wire-level flood; it does not by itself prove denial of service.

## 2.4 — Automatic mitigation

```bash
# SDN VM: enable automatic blocking before starting the burst
sudo python3 ~/lab4-session/monitor.py --interface ens33 --threshold 100 --window 5 --refresh 1 --auto-block

# Mininet VM: separate shell
sudo python3 ~/lab4-session/attack.py --send --count 3000 --rate 100 --source-port 4102

# SDN VM: inspect the installed rule and packet counter
sudo iptables -S INPUT | grep lab4-packetin-auto-block
sudo iptables -L INPUT -v -n --line-numbers | head -8
```

At 101 PacketIns from `10.224.76.126:4102`, the monitor printed its alert and `MITIGATION: INPUT DROP installed`. The attack connection's monitor total stayed at 101; the sender timed out after printing `Sent 600/3000 PacketIns`. A read-only firewall check confirmed this rule at line 1 of `INPUT` with **18 packets / 3020 bytes** dropped:

```text
-A INPUT -s 10.224.76.126/32 -d 10.224.78.132/32 -p tcp -m tcp --sport 4102 --dport 6653 -m comment --comment lab4-packetin-auto-block -j DROP
```

The rule counters and stable monitor total provide the block evidence; the sender timeout alone would not. The rule matches only this source IP/port and destination IP/port, not the four normal switch connections.

## 2.5 — Legitimate connectivity

With the above rule still installed, the user ran `pingall` in the Mininet CLI and reported **0% dropped (12/12 received)**. A subsequent read-only check confirmed the attack-specific DROP rule was still present. Connectivity **continued** during mitigation; there had been no observed pre-mitigation outage to recover from.

## 2.6 — Alternative mitigation

A controller could rate-limit PacketIn messages per OpenFlow connection, delaying or discarding excess PacketIns while allowing other control messages. This is more selective than an iptables rule that blocks the entire connection. The tradeoff is controller implementation and processing cost, plus the risk that a low limit discards legitimate bursts. The [ONF security report](https://opennetworking.org/wp-content/uploads/2018/11/secperf_report_2.pdf) recommends rate limiting controller interfaces as DoS protection.

## Cleanup after capturing the 2.4 and 2.5 screenshots

The lab-specific firewall rule persists after the monitor stops. Once its screenshots and connectivity check are complete, remove **only that exact rule** on the SDN VM:

```bash
sudo iptables -D INPUT -s 10.224.76.126/32 -d 10.224.78.132/32 -p tcp --sport 4102 --dport 6653 -m comment --comment lab4-packetin-auto-block -j DROP
```

Do not flush the INPUT chain; it contains unrelated system rules.
