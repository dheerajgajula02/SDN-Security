# SDN Security Lab

This private repository contains the scripts and text evidence for the current Lab 4 run.

- `monitor.py` runs on the SDN controller VM and counts OpenFlow PacketIn messages on its internal `ens33` interface.
- `attack.py` runs on the Mininet VM. Without `--send`, it only discovers the controller. With `--send`, it sends a bounded PacketIn burst from one source port.
- `monitorlog.log` is the Objective 1 baseline capture.
- [`OBJECTIVE2.md`](OBJECTIVE2.md) records the Objective 2 commands, observations, and evidence limits.

The VMs are reached through Tailscale for SSH administration. OpenFlow traffic between them uses their internal addresses (`10.224.76.126` and `10.224.78.132`).
