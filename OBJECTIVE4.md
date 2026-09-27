# Objective 4: routing and firewall

## Current setup

- Floodlight is running on the SDN VM. Its default forwarding module was disabled before the two-switch Mininet topology was started.
- The Flask app is at `/home/sdn/lab4-session/webapp/app.py` on the SDN VM and listens on `0.0.0.0:5000`.
- Open `http://100.110.3.67:5000/routing` to use the routing page. The web browser reaches the SDN VM through Tailscale; OpenFlow between the two VMs continues to use the internal network.
- The live topology uses s1 port 1 for `10.0.0.1`, s1 port 2 for `10.0.0.3`, s2 port 1 for `10.0.0.2`, s2 port 2 for `10.0.0.4`, and port 3 on both switches for the inter-switch link. This was checked against Mininet host interfaces and OVS port numbers.

## 4.4: Static Routing

The Routing page has a form for an individual flow. It accepts DPID, priority, In-Port, Ethernet type, destination IP, and either flood or a specific output port. The server validates the inputs and sends a JSON entry to Floodlight's `/wm/staticentrypusher/json` endpoint. It displays entries returned by `/wm/staticentrypusher/list/all/json`.

The **Install full policy** button installs 22 named entries at priority 100: six port-specific ARP flood entries and sixteen port-specific IPv4 forwarding entries. The same names are reused when the button is pressed again. For each destination IP, the output port is its local host port or port 3 if the destination is on the other switch.

The policy was installed from the web page. Floodlight listed 22 entries, and OVS showed 11 priority-100 entries on each switch. Direct pings between all 12 directed host pairs succeeded with two packets received per pair (24/24 packets). The single-flow form was also exercised with one lower-priority entry; that test entry was removed afterward, leaving the 22-entry policy.

### Screenshots to capture in your own Mininet terminal

```text
mininet> pingall
mininet> sh ovs-ofctl -O OpenFlow13 dump-flows s1
mininet> sh ovs-ofctl -O OpenFlow13 dump-flows s2
```

Capture the Routing page with its **22 visible** entry count, then capture the `pingall` result and both switch flow dumps. The switch dumps should show the ARP `FLOOD` rules and IPv4 `output` rules with priority 100; they also include the controller's existing priority-0 table-miss entry. If `pingall` does not show 0% dropped, stop and inspect the flow dumps before moving to the firewall objective.

### Suggested explanation for the lab document

> With Floodlight's default forwarding module disabled, the controller did not create forwarding paths automatically. I used the Python web application's Static Routing page to send static entries through Floodlight's northbound REST API. The two-switch policy installs ARP flood rules for host address resolution and IPv4 rules that match destination IP and ingress port, then output to the local host or the inter-switch link. Floodlight listed 22 entries, and both switch tables showed 11 priority-100 entries. Direct host-to-host checks passed for all 12 directed pairs. My `pingall` screenshot records the final full-connectivity result.

The last sentence should be kept only after you run and capture `pingall` yourself.

## 4.5: Firewall through static OpenFlow entries

Open `http://100.110.3.67:5000/firewall`. When entering from Static Routing, the page clears the old static entries and installs one priority-1, match-all drop entry on each switch. Floodlight's existing priority-0 controller table-miss entries remain below these drops. Returning to or reloading the Firewall page preserves installed permits. The **Reset to default deny** button explicitly clears permits and reinstalls the two drops. Reinstall the routing policy from the Routing page if you later need to demonstrate full connectivity again.

The form contains all seven requested inputs: source switch DPID, priority, In-Port, Ethernet type, source IP, destination IP, and Layer 4 protocol. For this four-host lab it accepts IPv4 (`0x0800`) and ICMP, TCP, or UDP. It checks that the source DPID and In-Port belong to the source host. A permit builds directed ARP and IPv4 rules along the host path in both directions. The ARP rules match the selected address pair; the IPv4 rules additionally match `ip_proto`. A pair on different switches receives eight permit flows, all at priority 100 with explicit output ports. Other traffic reaches the priority-1 drop. The web app uses Floodlight's static-entry REST API; its built-in firewall remains disabled.

The live check selected s1 (`00:00:00:00:00:00:00:01`), priority `100`, In-Port `1`, Ethernet type `0x0800`, source `10.0.0.1`, destination `10.0.0.2`, and protocol ICMP (`1`). Before permitting, `.1 → .2` lost both test pings. After permitting, `.1 → .2` and `.2 → .1` each received 2/2; `.1 → .3` and `.3 → .4` each received 0/2. Floodlight listed ten lab firewall entries: two default drops and eight permits. OVS showed the corresponding priority-1 drop and priority-100 ARP/ICMP entries on both switches. Floodlight reported `firewall disabled` for its built-in module.

### Screenshots to capture for 4.5

1. Open the Firewall page and capture **ACTIVE ON S1 + S2**, the two **Default drop** rows, and **2 visible**. In Mininet, run `h1s1 ping -c 2 -W 1 10.0.0.2`; capture its 100% loss.
2. Enter the values above and press **Add permit rule**. Capture the success message and **10 visible** entry table. Revisiting the Firewall page preserves these rules; press **Reset to default deny** when you want to remove them.
3. In Mininet, run the following commands and capture the success and failure lines together:

```text
mininet> h1s1 ping -c 2 -W 1 10.0.0.2
mininet> h1s2 ping -c 2 -W 1 10.0.0.1
mininet> h1s1 ping -c 2 -W 1 10.0.0.3
mininet> h2s1 ping -c 2 -W 1 10.0.0.4
mininet> sh ovs-ofctl -O OpenFlow13 dump-flows s1
mininet> sh ovs-ofctl -O OpenFlow13 dump-flows s2
```

The first two pings should succeed, and the last two should fail. The flow dumps should show priority-100 pair-specific ARP/ICMP forwarding above priority-1 drops. A full `pingall` is expected to have 2 successful directed host pairs out of 12, or about 83% dropped; use the individual pings to make clear which pair was permitted.

### Suggested explanation for the lab document

> I implemented the Firewall page with static OpenFlow entries through Floodlight's REST API. Opening the page cleared the previous routing policy and installed priority-1 match-all drop rules on both switches, so all host traffic was blocked. I then entered s1, priority 100, In-Port 1, IPv4, source 10.0.0.1, destination 10.0.0.2, and ICMP. The app installed eight higher-priority ARP and ICMP entries along the forward and return paths. Both directions of the chosen pair passed 2/2 pings, while two unrelated pairs received 0/2. The controller's built-in firewall stayed disabled; the switch flow tables enforced this policy.
