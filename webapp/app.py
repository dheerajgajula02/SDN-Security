"""Objective 4 web console for the SDN lab."""

import hashlib
import ipaddress
import json
import time

import requests
from flask import Flask, redirect, render_template, request, url_for


app = Flask(__name__)
app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
CONTROLLER_SWITCHES_URL = "http://127.0.0.1:8080/wm/core/controller/switches/json"
STATIC_ENTRIES_URL = "http://127.0.0.1:8080/wm/staticentrypusher/json"
STATIC_ENTRIES_LIST_URL = "http://127.0.0.1:8080/wm/staticentrypusher/list/all/json"
STATIC_ENTRIES_CLEAR_URL = "http://127.0.0.1:8080/wm/staticentrypusher/clear/all/json"
LAB_SWITCHES = {
    "s1": "00:00:00:00:00:00:00:01",
    "s2": "00:00:00:00:00:00:00:02",
}
LAB_HOSTS = {
    "s1": {1: "10.0.0.1", 2: "10.0.0.3"},
    "s2": {1: "10.0.0.2", 2: "10.0.0.4"},
}


class PolicyError(Exception):
    """A controller response or operator input prevented a policy change."""


def connected_dpids():
    response = requests.get(CONTROLLER_SWITCHES_URL, timeout=3)
    response.raise_for_status()
    switches = response.json()
    if not isinstance(switches, list):
        raise PolicyError("The controller returned an unexpected switch list.")
    return set(item["switchDPID"] for item in switches if "switchDPID" in item)


def integer_field(value, label, minimum, maximum):
    try:
        number = int(value)
    except (TypeError, ValueError):
        raise PolicyError("{} must be a whole number.".format(label))
    if not minimum <= number <= maximum:
        raise PolicyError("{} must be between {} and {}.".format(label, minimum, maximum))
    return number


def destination_field(value, eth_type):
    value = (value or "").strip()
    if not value and eth_type == "0x0806":
        return None
    try:
        return str(ipaddress.IPv4Address(value))
    except ipaddress.AddressValueError:
        raise PolicyError("Destination IP must be a valid IPv4 address.")


def flow_entry(name, dpid, priority, in_port, eth_type, destination, action,
               output_port=None):
    """Create the JSON shape expected by this Floodlight static entry pusher."""
    entry = {
        "name": name,
        "switch": dpid,
        "active": "true",
        "priority": str(priority),
        "eth_type": eth_type,
        "actions": "output=flood" if action == "flood" else "output={}".format(output_port),
    }
    if in_port is not None:
        entry["in_port"] = str(in_port)
    if destination:
        entry["ipv4_dst" if eth_type == "0x0800" else "arp_tpa"] = destination
    return entry


def push_entry(entry):
    response = requests.post(STATIC_ENTRIES_URL, data=json.dumps(entry),
                             headers={"Content-Type": "application/json"}, timeout=5)
    response.raise_for_status()
    try:
        status = response.json().get("status")
    except ValueError:
        raise PolicyError("Floodlight returned an unreadable response.")
    if status != "Entry pushed":
        raise PolicyError("Floodlight rejected {}: {}".format(entry["name"], status))


def static_entries(prefix):
    response = requests.get(STATIC_ENTRIES_LIST_URL, timeout=4)
    response.raise_for_status()
    data = response.json()
    if not isinstance(data, dict):
        raise PolicyError("The controller returned an unexpected entry list.")
    entries = []
    for dpid, switch_entries in data.items():
        # This Floodlight build returns a list of one-name objects per switch.
        # Accept a map as well to keep the page useful with other builds.
        groups = switch_entries if isinstance(switch_entries, list) else [switch_entries]
        for group in groups:
            if not isinstance(group, dict):
                continue
            for name, entry in group.items():
                if not name.startswith(prefix) or not isinstance(entry, dict):
                    continue
                match = entry.get("match") or {}
                instructions = entry.get("instructions") or {}
                apply_actions = instructions.get("instruction_apply_actions") or {}
                protocol = match.get("ip_proto")
                try:
                    protocol_label = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(
                        int(protocol, 0), protocol) if protocol else None
                except (TypeError, ValueError):
                    protocol_label = protocol
                entries.append({
                    "name": name,
                    "dpid": dpid,
                    "entry": {
                        "in_port": match.get("in_port", "any"),
                        "eth_type": match.get("eth_type", "—"),
                        "ipv4_src": match.get("ipv4_src"),
                        "ipv4_dst": match.get("ipv4_dst"),
                        "arp_spa": match.get("arp_spa"),
                        "arp_tpa": match.get("arp_tpa"),
                        "ip_proto": match.get("ip_proto"),
                        "protocol_label": protocol_label,
                        "actions": apply_actions.get("actions") or "drop",
                        "priority": entry.get("priority", "—"),
                    },
                })
    return sorted(entries, key=lambda item: (item["dpid"], item["name"]))


def routing_entries():
    return static_entries("lab4-route-")


def firewall_entries():
    return static_entries("lab4-fw-")


def firewall_mode_needs_initialization(entries):
    """Entering from routing starts deny; revisiting firewall preserves permits."""
    names = {item["name"] for item in entries}
    drops = {"lab4-fw-default-s1", "lab4-fw-default-s2"}
    return (any(name.startswith("lab4-route-") for name in names)
            or not drops.issubset(names))


def wait_for_entries(names, prefix="lab4-route-"):
    """Floodlight stores entries asynchronously, so wait briefly for its list API."""
    deadline = time.time() + 4
    while time.time() < deadline:
        entries = static_entries(prefix)
        if set(names).issubset(set(item["name"] for item in entries)):
            return entries
        time.sleep(0.2)
    raise PolicyError("Floodlight accepted the entries, but they are not all visible in its inventory yet.")


def manual_entry(form, allowed_dpids):
    dpid = (form.get("dpid") or "").strip()
    if dpid not in allowed_dpids:
        raise PolicyError("Choose a switch that is currently connected to Floodlight.")
    priority = integer_field(form.get("priority"), "Priority", 1, 65535)
    in_port = integer_field(form.get("in_port"), "In-Port", 1, 65535)
    eth_type = (form.get("eth_type") or "").strip().lower()
    if eth_type not in ("0x0800", "0x0806"):
        raise PolicyError("Ethernet type must be IPv4 (0x0800) or ARP (0x0806).")
    destination = destination_field(form.get("destination_ip"), eth_type)
    action = (form.get("action") or "").strip().lower()
    if action not in ("flood", "output"):
        raise PolicyError("Choose flood or a specific output port.")
    output_port = None
    if action == "output":
        output_port = integer_field(form.get("output_port"), "Output port", 1, 65535)
        if output_port == in_port:
            raise PolicyError("Output port must differ from In-Port.")
    entry = flow_entry("", dpid, priority, in_port, eth_type, destination,
                       action, output_port)
    fingerprint = hashlib.sha1(json.dumps(entry, sort_keys=True).encode("utf-8")).hexdigest()[:12]
    entry["name"] = "lab4-route-manual-{}".format(fingerprint)
    return entry


def complete_policy(priority):
    """Build port-scoped ARP and IPv4 paths for linear,2,2 (port 3 is the link)."""
    entries = []
    for switch_name, dpid in sorted(LAB_SWITCHES.items()):
        local_hosts = LAB_HOSTS[switch_name]
        for in_port in (1, 2, 3):
            entries.append(flow_entry(
                "lab4-route-{}-arp-in{}".format(switch_name, in_port),
                dpid, priority, in_port, "0x0806", None, "flood"))
        for destination in ("10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"):
            local_port = next((port for port, ip in local_hosts.items()
                               if ip == destination), None)
            output_port = local_port if local_port is not None else 3
            for in_port in (1, 2, 3):
                if in_port == output_port:
                    continue
                entries.append(flow_entry(
                    "lab4-route-{}-dst{}-in{}".format(
                        switch_name, destination.replace(".", "-"), in_port),
                    dpid, priority, in_port, "0x0800", destination,
                    "output", output_port))
    return entries


def clear_static_entries():
    """Clear the preceding lab policy before activating default deny."""
    response = requests.get(STATIC_ENTRIES_CLEAR_URL, timeout=5)
    response.raise_for_status()
    try:
        status = response.json().get("status")
    except ValueError:
        raise PolicyError("Floodlight returned an unreadable clear response.")
    if status != "Deleted all flows/groups.":
        raise PolicyError("Floodlight did not clear static entries: {}".format(status))
    deadline = time.time() + 5
    while time.time() < deadline:
        if not static_entries(""):
            return
        time.sleep(0.2)
    raise PolicyError("Old static entries are still visible in Floodlight.")


def default_drop_policy(allowed_dpids):
    if not set(LAB_SWITCHES.values()).issubset(allowed_dpids):
        raise PolicyError("Both lab switches must be connected to activate default deny.")
    clear_static_entries()
    drops = []
    for switch_name, dpid in sorted(LAB_SWITCHES.items()):
        # With no actions and no match, this priority-1 flow drops every packet.
        drops.append({"name": "lab4-fw-default-{}".format(switch_name),
                      "switch": dpid, "active": "true", "priority": "1"})
    for entry in drops:
        push_entry(entry)
    wait_for_entries([entry["name"] for entry in drops], "lab4-fw-")


def ipv4_field(value, label):
    try:
        return str(ipaddress.IPv4Address((value or "").strip()))
    except ipaddress.AddressValueError:
        raise PolicyError("{} must be a valid IPv4 address.".format(label))


def host_location(ip):
    for switch_name, ports in LAB_HOSTS.items():
        for port, host_ip in ports.items():
            if ip == host_ip:
                return switch_name, port
    raise PolicyError("Source and destination must be one of the four lab host IPs.")


def path_between(start, finish):
    start_switch, start_port = host_location(start)
    finish_switch, finish_port = host_location(finish)
    if start_switch == finish_switch:
        return [(start_switch, start_port, finish_port)]
    return [(start_switch, start_port, 3), (finish_switch, 3, finish_port)]


def firewall_permit_policy(form, allowed_dpids):
    source_dpid = (form.get("dpid") or "").strip()
    if source_dpid not in allowed_dpids or source_dpid not in LAB_SWITCHES.values():
        raise PolicyError("Choose a connected lab switch as the source DPID.")
    priority = integer_field(form.get("priority"), "Priority", 2, 65535)
    in_port = integer_field(form.get("in_port"), "In-Port", 1, 3)
    eth_type = (form.get("eth_type") or "").strip().lower()
    if eth_type != "0x0800":
        raise PolicyError("Layer 4 protocol matching requires IPv4 Ethernet type 0x0800.")
    source = ipv4_field(form.get("source_ip"), "Source IP")
    destination = ipv4_field(form.get("destination_ip"), "Destination IP")
    if source == destination:
        raise PolicyError("Choose two different hosts.")
    source_switch, source_port = host_location(source)
    host_location(destination)
    if source_dpid != LAB_SWITCHES[source_switch] or in_port != source_port:
        raise PolicyError("Source DPID and In-Port must match the selected source host.")
    protocol = (form.get("protocol") or "").strip()
    if protocol not in ("1", "6", "17"):
        raise PolicyError("Choose ICMP, TCP, or UDP as the Layer 4 protocol.")

    pair = sorted((source, destination))
    key = hashlib.sha1("{}|{}|{}".format(pair[0], pair[1], protocol)
                       .encode("utf-8")).hexdigest()[:10]
    entries = []
    for direction, start, finish in (("forward", source, destination),
                                     ("return", destination, source)):
        for step, (switch_name, ingress, egress) in enumerate(path_between(start, finish), 1):
            common = {"switch": LAB_SWITCHES[switch_name], "active": "true",
                      "priority": str(priority), "in_port": str(ingress),
                      "actions": "output={}".format(egress)}
            stem = "lab4-fw-allow-{}-{}-{}-{}".format(key, direction, step, switch_name)
            arp = dict(common, name=stem + "-arp", eth_type="0x0806",
                       arp_spa=start, arp_tpa=finish)
            ipv4 = dict(common, name=stem + "-ip", eth_type=eth_type,
                        ipv4_src=start, ipv4_dst=finish, ip_proto=protocol)
            entries.extend((arp, ipv4))
    return entries, {"source": source, "destination": destination,
                     "protocol": {"1": "ICMP", "6": "TCP", "17": "UDP"}[protocol]}


def controller_status():
    """Return a small, safe status summary for the navigation bar."""
    try:
        response = requests.get(CONTROLLER_SWITCHES_URL, timeout=1.5)
        response.raise_for_status()
        switches = response.json()
        if not isinstance(switches, list):
            raise ValueError("Unexpected switch response")
        return {"online": True, "switch_count": len(switches)}
    except (requests.RequestException, ValueError):
        return {"online": False, "switch_count": 0}


@app.context_processor
def inject_controller_status():
    return {"controller": controller_status()}


@app.route("/")
def home():
    return render_template("index.html", page="home")


@app.route("/routing")
def routing():
    return routing_page()


@app.route("/routing", methods=["POST"])
def routing_post():
    return routing_page()


def routing_page():
    error = None
    notice = None
    entries = []
    try:
        dpids = connected_dpids()
    except (requests.RequestException, ValueError, KeyError, PolicyError):
        dpids = set()
        error = "Floodlight is unavailable. Check that the controller is running."

    if request.method == "POST" and not error:
        try:
            operation = request.form.get("operation")
            if operation == "add":
                entry = manual_entry(request.form, dpids)
                push_entry(entry)
                wait_for_entries([entry["name"]])
                notice = "Added {} to switch {}.".format(entry["name"], entry["switch"])
            elif operation == "complete":
                if not set(LAB_SWITCHES.values()).issubset(dpids):
                    raise PolicyError("Both lab switches must be connected before installing the full policy.")
                priority = integer_field(request.form.get("policy_priority"),
                                         "Priority", 1, 65535)
                policy = complete_policy(priority)
                for entry in policy:
                    push_entry(entry)
                wait_for_entries([entry["name"] for entry in policy])
                notice = "Installed {} static flows across s1 and s2. Run pingall in Mininet to verify connectivity.".format(len(policy))
            else:
                raise PolicyError("Unknown routing operation.")
        except (PolicyError, requests.RequestException, ValueError) as exc:
            error = "Routing update failed: {}".format(exc)

    try:
        entries = routing_entries()
    except (PolicyError, requests.RequestException, ValueError):
        if not error:
            error = "Could not read static entries from Floodlight."
    return render_template("routing.html", page="routing", error=error,
                           notice=notice, entries=entries, lab_switches=LAB_SWITCHES,
                           connected_dpids=dpids,
                           lab_ready=set(LAB_SWITCHES.values()).issubset(dpids),
                           values=request.form)


@app.route("/firewall", methods=["GET", "POST"])
def firewall():
    error = None
    notice = None
    entries = []
    try:
        dpids = connected_dpids()
    except (requests.RequestException, ValueError, KeyError, PolicyError):
        dpids = set()
        error = "Floodlight is unavailable. Check that the controller is running."

    if not error:
        try:
            if request.method == "GET":
                if firewall_mode_needs_initialization(static_entries("")):
                    default_drop_policy(dpids)
                    notice = "Default deny is active on both switches. The previous static routing policy was cleared."
                elif request.args.get("reset") == "done":
                    notice = "Firewall policy reset to default deny on both switches."
            else:
                operation = request.form.get("operation")
                if operation == "reset":
                    default_drop_policy(dpids)
                    return redirect(url_for("firewall", reset="done"))
                if operation != "permit":
                    raise PolicyError("Unknown firewall operation.")
                if firewall_mode_needs_initialization(static_entries("")):
                    raise PolicyError("Open the Firewall page to activate default deny before adding a permit.")
                policy, details = firewall_permit_policy(request.form, dpids)
                for entry in policy:
                    push_entry(entry)
                wait_for_entries([entry["name"] for entry in policy], "lab4-fw-")
                notice = "Allowed {} between {} and {} in both directions with {} static flows.".format(
                    details["protocol"], details["source"], details["destination"], len(policy))
        except (PolicyError, requests.RequestException, ValueError) as exc:
            error = "Firewall update failed: {}".format(exc)

    try:
        entries = firewall_entries()
    except (PolicyError, requests.RequestException, ValueError):
        if not error:
            error = "Could not read firewall entries from Floodlight."
    installed = {item["name"] for item in entries}
    default_active = {"lab4-fw-default-s1", "lab4-fw-default-s2"}.issubset(installed)
    return render_template("firewall.html", page="firewall", error=error,
                           notice=notice, entries=entries, lab_switches=LAB_SWITCHES,
                           connected_dpids=dpids,
                           lab_ready=set(LAB_SWITCHES.values()).issubset(dpids),
                           default_active=default_active, values=request.form)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
