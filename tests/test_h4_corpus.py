"""H4: false-positive rate of output redaction on a realistic Proxmox JSON corpus.

The corpus is generated (seeded) from the shapes the tools return per the Proxmox VE API
viewer: cluster resources/status, nodes, node status, VM and CT lists and configs, storage
content, tasks + task logs, snapshots, pools, firewall, network, disks + SMART, apt, HA,
replication, backup jobs, access users/groups/roles/ACLs/domains, certificates, rrddata,
ceph, SDN, notifications. It contains no PHI and no secrets outside secret-named keys, so
every redaction outside those keys is a false positive.
"""

import json
import random
import uuid

from proxmox_mcp import output
from proxmox_mcp.phi import detect_phi

R = random.Random(20261024)  # noqa: S311 - seeded corpus, not crypto
NODES = ["pve01", "pve02", "pve-prod-03", "hv4"]
STORES = ["local", "local-lvm", "ceph-rbd", "pbs-backup", "nfs-iso", "zfs-tank"]


def mac():
    return "BC:24:11:" + ":".join(f"{R.randrange(256):02X}" for _ in range(3))


def upid(node, typ, vmid, user="root@pam"):
    return (
        f"UPID:{node}:{R.randrange(16**8):08X}:{R.randrange(16**8):08X}:{R.randrange(0x60000000, 0x6A000000):08X}"
        f":{typ}:{vmid}:{user}:"
    )


def ts():
    return R.randrange(1_600_000_000, 1_800_000_000)


def size():
    return R.choice([2**30, 8 * 2**30, 32 * 2**30, 107374182400, R.randrange(10**6, 10**13)])


def vm_config(vmid):
    return {
        "name": f"web-{vmid}",
        "cores": R.choice([1, 2, 4, 8]),
        "memory": str(R.choice([2048, 4096, 16384])),
        "sockets": 1,
        "cpu": "x86-64-v2-AES",
        "ostype": R.choice(["l26", "win11", "win2k22"]),
        "net0": f"virtio={mac()},bridge=vmbr0,firewall=1,tag={R.randrange(2, 4000)}",
        "net1": f"e1000={mac().lower()},bridge=vmbr1",
        "scsi0": f"{R.choice(STORES)}:vm-{vmid}-disk-0,iothread=1,size={R.choice([32, 64, 500])}G,ssd=1",
        "efidisk0": f"local-lvm:vm-{vmid}-disk-1,efitype=4m,pre-enrolled-keys=1,size=4M",
        "tpmstate0": f"local-lvm:vm-{vmid}-disk-2,size=4M,version=v2.0",
        "ide2": "nfs-iso:iso/ubuntu-24.04.1-live-server-amd64.iso,media=cdrom,size=2708862K",
        "boot": "order=scsi0;ide2;net0",
        "scsihw": "virtio-scsi-single",
        "agent": "1,fstrim_cloned_disks=1",
        "smbios1": f"uuid={uuid.UUID(int=R.getrandbits(128))}",
        "vmgenid": str(uuid.UUID(int=R.getrandbits(128))),
        "meta": f"creation-qemu=9.0.2,ctime={ts()}",
        "numa": 0,
        "onboot": 1,
        "keyboard": "en-us",
        "ipconfig0": f"ip=10.{R.randrange(256)}.{R.randrange(256)}.{R.randrange(2, 250)}/24,gw=10.0.0.1",
        "ciuser": "ubuntu",
        "cipassword": "**********",
        "sshkeys": "ssh-ed25519%20AAAAC3NzaC1lZDI1NTE5AAAAI",
        "description": R.choice(
            [
                "Web frontend. Owner: platform team. Ticket INC-20240115-0042. Rebuilt 2024-03-02.",
                "# Notes\n- patched 2024-06-11 (kernel 6.8.12-4-pve)\n- backup nightly 01:00, keep-last=7\n",
                "Do not migrate during business hours. Contact on-call x4412. RAM 16 GiB, disk 500G thin.",
                "Created from template 9000 on 2025-01-20T10:22:31Z by terraform (bpg/proxmox 0.66.1).",
                "VLAN 120, fw group web-dmz, ports 80/443. Serial S4EWNX0R123456. Asset tag 004512.",
                "Windows Server 2022 Datacenter, KMS activated, build 20348.2340, last patch 10/08/2024.",
                "Migrated from VMware vm-1042 (moref vm-1042) on 2024-11-03; old MAC 00:50:56:9a:12:34.",
            ]
        ),
        "tags": R.choice(
            ["prod;web", "dev", "db;postgres-16", "k8s;worker;zone-b", "dmz", "backup-excluded"]
        ),
        "hostpci0": "0000:01:00.0,pcie=1,x-vga=1",
        "usb0": "host=046d:c52b",
        "serial0": "socket",
        "digest": f"{R.getrandbits(160):040x}",
        "lock": R.choice(["backup", "snapshot", "migrate"]),
    }


def ct_config(vmid):
    return {
        "hostname": f"ct-{vmid}.lan",
        "arch": "amd64",
        "cores": 2,
        "memory": 1024,
        "swap": 512,
        "ostype": "debian",
        "rootfs": f"local-lvm:vm-{vmid}-disk-0,size=8G",
        "mp0": "/mnt/pve/nfs,mp=/srv/data,backup=0",
        "unprivileged": 1,
        "features": "nesting=1,keyctl=1",
        "net0": f"name=eth0,bridge=vmbr0,hwaddr={mac()},ip=dhcp,ip6=auto,type=veth",
        "description": "Pi-hole DNS for VLAN 10\nupdated 2025-02-14\n",
        "tags": "dns;infra",
        "lxc": [
            ["lxc.cgroup2.devices.allow", "c 10:200 rwm"],
            ["lxc.mount.entry", "/dev/net dev/net none bind,create=dir"],
        ],
        "digest": f"{R.getrandbits(160):040x}",
    }


def task_log():
    lines = [
        "INFO: starting new backup job: vzdump 100 --mode snapshot --storage pbs-backup --notes-template '{{guestname}}'",
        "INFO: Starting Backup of VM 100 (qemu)",
        "INFO: Backup started at 2025-03-14 01:00:02",
        "INFO: status = running",
        "INFO: VM Name: web-100",
        "INFO: include disk 'scsi0' 'local-lvm:vm-100-disk-0' 32G",
        "INFO: creating Proxmox Backup Server archive 'vm/100/2025-03-14T01:00:02Z'",
        "INFO:  12% (3.9 GiB of 32.0 GiB) in 3s, read: 1.3 GiB/s, write: 210.7 MiB/s",
        "INFO: 100% (32.0 GiB of 32.0 GiB) in 1m 41s, read: 324.4 MiB/s, write: 77.2 MiB/s",
        "INFO: backup is sparse: 18.12 GiB (56%) total zero data",
        "INFO: transferred 32.00 GiB in 101 seconds",
        "INFO: archive file size: 7.21GB",
        "INFO: Finished Backup of VM 100 (00:01:45)",
        "TASK OK",
        "trying to acquire lock...",
        " OK",
        "migration finished successfully (duration 00:00:21)",
        "2025-03-14 01:02:11 starting migration of VM 101 to node 'pve02' (10.0.0.12)",
        "2025-03-14 01:02:13 migration status: active (transferred 1.1 GiB of 4.0 GiB), total 4.0 GiB",
        '  Logical volume "vm-102-disk-0" created.',
        "Formatting '/var/lib/vz/images/103/vm-103-disk-0.raw', fmt=raw size=34359738368",
        "TASK ERROR: command 'apt-get update' failed: exit code 100",
        "Get:1 http://download.proxmox.com/debian/pve bookworm InRelease [2,771 B]",
        "Fetched 1,234 kB in 2s (617 kB/s)",
        "update-initramfs: Generating /boot/initrd.img-6.8.12-4-pve",
        "zfs: scrub repaired 0B in 00:12:31 with 0 errors on Sun Mar 9 00:36:32 2025",
        "smartctl 7.3 2022-02-28 r5338 [x86_64-linux-6.8.12-4-pve] (local build)",
        "Serial Number:    S4EWNX0R123456",
        "LU WWN Device Id: 5 002538 e40123456",
        "Firmware Version: 2B2QEXM7",
        "User Capacity:    1,000,204,886,016 bytes [1.00 TB]",
        "ceph-osd: osd.3 fsid 6c1f3a2e-9d1b-4c5e-8f0a-1234567890ab up",
        "HEALTH_WARN 1 pool(s) have no replicas configured",
        "corosync[1234]:   [TOTEM ] A new membership (1.2a3) was formed. Members joined: 2",
        "qmeventd[987]: Starting cleanup for 105",
        "pvescheduler[4321]: starting task " + upid("pve01", "vzdump", "", "root@pam"),
        "acme: order https://acme-v02.api.letsencrypt.org/acme/order/123456789/987654321 is valid",
        "cert fingerprint 3E:7A:91:0C:55:12:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD",
        "dns: _acme-challenge.pve01.example.com TXT 'Zx3yQ9pL2kM8vB7nR4tW1sE6uH0cF5gJ'",
        "kernel: [123456.789012] vmbr0: port 3(tap100i0) entered forwarding state",
        "kernel: EDAC MC0: 1 CE memory read error on CPU_SrcID#0_Ha#0_Chan#1_DIMM#0 (channel:1 slot:0 page:0x123456 offset:0x0)",
        "pmxcfs[1111]: [status] notice: received log",
        "lvm: thin pool data usage 81.32%",
        "Phone home disabled; telemetry off since 01/04/2024",
        "Rebooting at 03:00 on 2025-04-01 per CHG-2025-0042",
        "RRD update error /var/lib/rrdcached/db/pve2-vm/100: illegal attempt",
    ]
    return [{"n": i + 1, "t": t} for i, t in enumerate(R.sample(lines, len(lines)))]


def build_corpus():
    c = {}
    c["cluster_resources"] = (
        [
            {
                "id": f"qemu/{v}",
                "type": "qemu",
                "vmid": v,
                "node": R.choice(NODES),
                "name": f"web-{v}",
                "status": "running",
                "maxmem": size(),
                "mem": size(),
                "maxdisk": size(),
                "disk": 0,
                "cpu": R.random(),
                "maxcpu": 4,
                "uptime": R.randrange(10**7),
                "netin": size(),
                "netout": size(),
                "template": 0,
                "tags": "prod;web",
                "hastate": "started",
                "pool": "web",
            }
            for v in range(100, 400)
        ]
        + [
            {
                "id": f"storage/{n}/{s}",
                "type": "storage",
                "storage": s,
                "node": n,
                "plugintype": "lvmthin",
                "content": "images,rootdir",
                "status": "available",
                "shared": 0,
                "maxdisk": size(),
                "disk": size(),
            }
            for n in NODES
            for s in STORES
        ]
        + [
            {
                "id": f"sdn/{n}/localnetwork",
                "type": "sdn",
                "sdn": "localnetwork",
                "node": n,
                "status": "ok",
            }
            for n in NODES
        ]
    )
    c["cluster_status"] = [
        {
            "type": "cluster",
            "name": "prod",
            "nodes": 4,
            "quorate": 1,
            "version": 12,
            "id": "cluster",
        }
    ] + [
        {
            "type": "node",
            "name": n,
            "id": f"node/{n}",
            "ip": f"10.0.0.{11 + i}",
            "level": "c",
            "local": int(i == 0),
            "nodeid": i + 1,
            "online": 1,
        }
        for i, n in enumerate(NODES)
    ]
    c["node_status"] = {
        "uptime": 1234567,
        "loadavg": ["0.52", "0.61", "0.70"],
        "cpu": 0.0423,
        "cpuinfo": {
            "model": "AMD EPYC 7313P 16-Core Processor",
            "cores": 16,
            "sockets": 1,
            "cpus": 32,
            "mhz": "2999.998",
            "flags": "fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov",
            "hvm": "1",
            "user_hz": 100,
        },
        "memory": {"total": 134997270528, "used": 61234556928, "free": 73762713600},
        "kversion": "Linux 6.8.12-4-pve #1 SMP PREEMPT_DYNAMIC PMX 6.8.12-4 (2024-11-06T15:04Z)",
        "pveversion": "pve-manager/8.3.0/c1689ccb1065a83b",
        "boot-info": {"mode": "efi", "secureboot": 0},
        "current-kernel": {
            "machine": "x86_64",
            "release": "6.8.12-4-pve",
            "sysname": "Linux",
            "version": "#1 SMP PREEMPT_DYNAMIC PMX 6.8.12-4 (2024-11-06T15:04Z)",
        },
        "rootfs": {"total": 100861726720, "used": 12345678912, "avail": 83456789012},
        "ksm": {"shared": 0},
    }
    c["vm_configs"] = {v: vm_config(v) for v in range(100, 160)}
    c["ct_configs"] = {v: ct_config(v) for v in range(200, 220)}
    c["storage_content"] = (
        [
            {
                "volid": f"{s}:vm-{v}-disk-{d}",
                "format": R.choice(["raw", "qcow2"]),
                "size": size(),
                "vmid": v,
                "ctime": ts(),
                "content": "images",
            }
            for s in ("local-lvm", "ceph-rbd")
            for v in range(100, 140)
            for d in (0, 1)
        ]
        + [
            {
                "volid": f"pbs-backup:backup/vm/{v}/2025-03-1{d}T01:00:02Z",
                "format": "pbs-vm",
                "size": size(),
                "vmid": v,
                "ctime": ts(),
                "content": "backup",
                "verification": {"state": "ok", "upid": upid("pve01", "verify", "")},
                "notes": f"web-{v} nightly",
                "encrypted": "3e:7a:91:0c:55:12:ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd",
                "protected": 0,
            }
            for v in range(100, 140)
            for d in range(5)
        ]
        + [
            {
                "volid": "nfs-iso:iso/virtio-win-0.1.262.iso",
                "format": "iso",
                "size": 708263936,
                "ctime": ts(),
            },
            {
                "volid": "local:vztmpl/debian-12-standard_12.7-1_amd64.tar.zst",
                "format": "tzst",
                "size": 126538974,
            },
        ]
    )
    c["tasks"] = [
        {
            "upid": upid(
                R.choice(NODES),
                t,
                v,
                R.choice(["root@pam", "dev@pve!mcp", "alice@corp.example!ci"]),
            ),
            "type": t,
            "id": str(v),
            "user": "root@pam",
            "starttime": ts(),
            "endtime": ts(),
            "status": R.choice(["OK", "WARNINGS: 1"]),
            "node": R.choice(NODES),
            "pid": R.randrange(10**6),
            "pstart": R.randrange(10**9),
        }
        for t in ("qmstart", "vzdump", "qmigrate", "vncproxy", "qmsnapshot", "aptupdate")
        for v in range(100, 140)
    ]
    c["task_log"] = task_log()
    c["snapshots"] = [
        {"name": n, "description": d, "snaptime": ts(), "vmstate": 0, "parent": "pre-upgrade"}
        for n, d in [
            ("pre-upgrade", "before apt dist-upgrade 2025-01-07"),
            ("pre-patch-2024-11", "KB5044284 rollback point"),
            ("current", "You are here!"),
            ("golden", "template baseline v3.2.1 build 20250214.1"),
        ]
    ]
    c["pools"] = [
        {
            "poolid": p,
            "comment": cm,
            "members": [{"id": "qemu/100", "type": "qemu", "vmid": 100, "node": "pve01"}],
        }
        for p, cm in [
            ("web", "Public web tier"),
            ("db", "Postgres 16 cluster, RPO 15 min"),
            ("radiology", "PACS viewers (no PHI on hypervisor)"),
            ("lab", "Scratch VMs, wiped monthly"),
        ]
    ]
    c["firewall"] = [
        {
            "pos": i,
            "type": "in",
            "action": "ACCEPT",
            "proto": "tcp",
            "dport": str(p),
            "source": f"10.{i}.0.0/16",
            "comment": f"allow {p} from office",
            "enable": 1,
            "log": "nolog",
            "digest": f"{R.getrandbits(160):040x}",
        }
        for i, p in enumerate([22, 80, 443, 8006, 3128, 5900, 3389, 9100])
    ]
    c["network"] = [
        {
            "iface": "vmbr0",
            "type": "bridge",
            "cidr": "10.0.0.11/24",
            "gateway": "10.0.0.1",
            "bridge_ports": "enp1s0f0",
            "autostart": 1,
            "active": 1,
            "families": ["inet"],
            "method": "static",
            "cidr6": "fd00:10::11/64",
        },
        {
            "iface": "enp1s0f0",
            "type": "eth",
            "hwaddr": "3c:ec:ef:12:34:56",
            "active": 1,
            "exists": 1,
        },
        {
            "iface": "bond0",
            "type": "bond",
            "slaves": "enp2s0f0 enp2s0f1",
            "bond_mode": "802.3ad",
            "bond-xmit-hash-policy": "layer3+4",
        },
    ]
    c["disks"] = [
        {
            "devpath": f"/dev/nvme{i}n1",
            "model": "Samsung SSD 980 PRO 1TB",
            "serial": f"S5GXNF0R{R.randrange(10**6):06d}X",
            "wwn": f"eui.002538{R.getrandbits(40):010x}",
            "size": 1000204886016,
            "health": "PASSED",
            "type": "nvme",
            "wearout": 98,
            "by_id_link": f"/dev/disk/by-id/nvme-Samsung_SSD_980_PRO_1TB_S5GXNF0R{R.randrange(10**6):06d}X",
            "rpm": 0,
            "gpt": 1,
            "vendor": "Samsung",
            "used": "ZFS",
        }
        for i in range(4)
    ] + [
        {
            "devpath": "/dev/sda",
            "model": "WDC_WD40EFRX-68N32N0",
            "serial": "WD-WCC7K1234567",
            "wwn": "0x50014ee2b1234567",
            "size": 4000787030016,
            "health": "PASSED",
            "type": "hdd",
            "rpm": 5400,
        }
    ]
    c["smart"] = {
        "type": "ata",
        "health": "PASSED",
        "attributes": [
            {
                "id": " 5",
                "name": "Reallocated_Sector_Ct",
                "value": 100,
                "worst": 100,
                "threshold": 10,
                "raw": "0",
                "flags": "PO--CK",
            },
            {
                "id": "194",
                "name": "Temperature_Celsius",
                "value": 67,
                "raw": "33 (Min/Max 18/45)",
                "flags": "-O---K",
            },
            {
                "id": "241",
                "name": "Total_LBAs_Written",
                "value": 99,
                "raw": "123456789012",
                "flags": "-O--CK",
            },
        ],
    }
    c["apt"] = [
        {
            "Package": p,
            "Version": v,
            "OldVersion": o,
            "Origin": "Proxmox",
            "Priority": "optional",
            "Section": "admin",
            "Title": t,
            "Arch": "amd64",
        }
        for p, v, o, t in [
            ("pve-manager", "8.3.1", "8.3.0", "Proxmox Virtual Environment Management Tools"),
            ("proxmox-kernel-6.8", "6.8.12-5", "6.8.12-4", "Latest Proxmox Kernel Image"),
            ("libpve-common-perl", "8.2.9", "8.2.8", "Proxmox VE base library"),
            (
                "zfsutils-linux",
                "2.2.6-pve1",
                "2.2.4-pve1",
                "command-line tools to manage OpenZFS filesystems",
            ),
        ]
    ]
    c["ha"] = [
        {
            "sid": f"vm:{v}",
            "state": "started",
            "group": "prefer-pve01",
            "max_restart": 1,
            "max_relocate": 1,
            "comment": "HA web",
            "digest": f"{R.getrandbits(160):040x}",
            "type": "vm",
        }
        for v in range(100, 110)
    ]
    c["replication"] = [
        {
            "id": f"{v}-0",
            "target": "pve02",
            "schedule": "*/15",
            "rate": 50,
            "guest": v,
            "jobnum": 0,
            "last_sync": ts(),
            "duration": 3.52,
            "fail_count": 0,
            "type": "local",
        }
        for v in range(100, 110)
    ]
    c["backup_jobs"] = [
        {
            "id": "backup-1a2b3c4d-5e6f",
            "schedule": "sun 01:00",
            "storage": "pbs-backup",
            "mode": "snapshot",
            "enabled": 1,
            "all": 1,
            "compress": "zstd",
            "notes-template": "{{guestname}} {{vmid}}",
            "prune-backups": "keep-daily=7,keep-weekly=4,keep-monthly=6",
            "mailnotification": "failure",
            "next-run": ts(),
            "comment": "Nightly to PBS (2.5 TB quota)",
        }
    ]
    c["users"] = [
        {
            "userid": u,
            "enable": 1,
            "expire": 0,
            "firstname": f,
            "lastname": ln,
            "email": e,
            "comment": cm,
            "realm-type": rt,
            "groups": "admins",
            "tokens": [{"tokenid": "mcp", "expire": 0, "privsep": 1, "comment": "broker"}],
            "keys": "x!yubico",
            "tfa-locked-until": 0,
        }
        for u, f, ln, e, cm, rt in [
            ("root@pam", "", "", "ops@example.com", "Built-in superuser", "pam"),
            ("alice@corp", "Alice", "Ng", "alice@example.com", "SRE lead", "openid"),
            ("svc-backup@pve", "", "", "", "service account for PBS", "pve"),
        ]
    ]
    c["acl"] = [
        {
            "path": "/pool/web",
            "roleid": "PVEVMUser",
            "type": "user",
            "ugid": "alice@corp",
            "propagate": 1,
        },
        {
            "path": "/vms/100",
            "roleid": "PVEAuditor",
            "type": "token",
            "ugid": "root@pam!mcp",
            "propagate": 0,
        },
    ]
    c["roles"] = [
        {
            "roleid": "PVEVMUser",
            "privs": "VM.Audit,VM.Console,VM.Backup,VM.PowerMgmt,VM.Config.CDROM",
            "special": 1,
        }
    ]
    c["domains"] = [
        {
            "realm": "corp",
            "type": "openid",
            "comment": "Entra ID",
            "issuer-url": "https://login.microsoftonline.com/"
            f"{uuid.UUID(int=R.getrandbits(128))}/v2.0",
            "client-id": str(uuid.UUID(int=R.getrandbits(128))),
            "client-key": "should-be-redacted-by-key",
            "autocreate": 1,
            "username-claim": "email",
        }
    ]
    c["certificates"] = [
        {
            "filename": "pveproxy-ssl.pem",
            "fingerprint": ":".join(f"{R.randrange(256):02X}" for _ in range(32)),
            "issuer": "/C=US/O=Let's Encrypt/CN=R11",
            "subject": "/CN=pve01.example.com",
            "notbefore": ts(),
            "notafter": ts(),
            "san": ["pve01.example.com", "10.0.0.11"],
            "public-key-type": "rsaEncryption",
            "public-key-bits": 2048,
            "pem": "-----BEGIN CERTIFICATE-----\nMIIFazCCA1OgAwIBAgIUQ\n-----END CERTIFICATE-----\n",
        }
    ]
    c["rrd"] = [
        {
            "time": 1712345000 + 60 * i,
            "cpu": R.random(),
            "maxcpu": 4,
            "mem": R.random() * 1e10,
            "netin": R.random() * 1e6,
            "diskread": R.random() * 1e7,
        }
        for i in range(200)
    ]
    c["ceph"] = {
        "health": {"status": "HEALTH_OK"},
        "fsid": str(uuid.UUID(int=R.getrandbits(128))),
        "osdmap": {"num_osds": 12, "num_up_osds": 12, "epoch": 4123},
        "pgmap": {
            "bytes_total": 12001464115200,
            "bytes_used": 3456789012345,
            "num_pgs": 513,
            "read_bytes_sec": 12345678,
            "write_op_per_sec": 456,
        },
    }
    c["sdn"] = [
        {
            "zone": "evpn1",
            "type": "evpn",
            "controller": "evpnctl",
            "vrf-vxlan": 4000,
            "mtu": 1450,
            "ipam": "pve",
            "peers": "10.0.0.11,10.0.0.12",
        },
        {"vnet": "vnet100", "zone": "evpn1", "tag": 100100, "alias": "web tier", "type": "vnet"},
    ]
    c["notifications"] = [
        {
            "name": "mail-to-root",
            "type": "sendmail",
            "mailto-user": ["root@pam"],
            "comment": "default",
            "from-address": "pve@example.com",
        },
        {
            "name": "gotify-ops",
            "type": "gotify",
            "server": "https://gotify.example.com",
            "token": "redacted-by-key",
        },
    ]
    c["cloudinit"] = [
        {"key": "ciuser", "value": "ubuntu"},
        {"key": "ipconfig0", "value": "ip=dhcp"},
        {"key": "nameserver", "value": "10.0.0.53"},
        {"key": "searchdomain", "value": "corp.example"},
    ]
    c["agent_info"] = {
        "result": {
            "version": "8.2.2",
            "supported_commands": [{"name": "guest-ping", "enabled": True}],
        }
    }
    c["version"] = {"version": "8.3.0", "release": "8.3", "repoid": "c1689ccb1065a83b"}
    return c


def _walk(a, b, path, out):
    """Compare original a with redacted b; record (path, original, redacted) for each scanned string."""
    if isinstance(a, dict):
        assert isinstance(b, dict) and len(a) == len(b), path
        for (ka, va), (kb, vb) in zip(a.items(), b.items(), strict=True):
            out.append((path + ("<key>",), ka, kb))
            if output.is_secret_key(ka):
                assert vb == "[REDACTED]", path + (ka,)
                continue  # intended: secret-named key
            _walk(va, vb, path + (ka,), out)
    elif isinstance(a, list):
        assert isinstance(b, list) and len(a) == len(b), path
        for i, (va, vb) in enumerate(zip(a, b, strict=True)):
            _walk(va, vb, path + (i,), out)
    elif isinstance(a, str):
        out.append((path, a, b))
    else:
        assert a == b, path


def _measure():
    corpus = json.loads(
        json.dumps(build_corpus())
    )  # what the client actually hands to render_result
    seen = []
    _walk(corpus, output.redact(corpus), (), seen)
    return len(seen), [s for s in seen if s[1] != s[2]]


def test_false_positive_rate_on_proxmox_corpus(capsys):
    total, fps = _measure()
    assert total > 5000
    with capsys.disabled():
        print(
            f"\n[H4 corpus] strings+keys scanned: {total}, changed: {len(fps)}, "
            f"false-positive rate: {len(fps) / total:.4%}"
        )
        for fp in fps[:20]:
            print("  FP:", fp)
    assert not fps


def test_corpus_not_refused_as_phi_on_write():
    corpus = build_corpus()
    for name in (
        "vm_configs",
        "ct_configs",
        "pools",
        "snapshots",
        "firewall",
        "network",
        "backup_jobs",
    ):
        assert detect_phi(corpus[name]) is None, name


def test_corpus_secret_keys_still_redacted():
    out = output.render_result(build_corpus())
    assert "should-be-redacted-by-key" not in out and "redacted-by-key" not in out
