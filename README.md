# Linux Commands

Purpose: a single-page, production-ready cheatsheet for Linux/SRE triage.
Optimized for fast on-call use: concise flags, copy-paste recipes, brief notes,
and clear risk callouts.

Quick Navigation
- [Binaries & ELF](#binaries--elf)
- [Text & Data Utilities](#text--data-utilities)
- [Networking](#networking)
- [Kernel & Tracing](#kernel--tracing)
- [Disk & Filesystems](#disk--filesystems)
- [Processes & Scheduling](#processes--scheduling)
- [CPU](#cpu)
- [Memory](#memory)
- [Logs & Systemd](#logs--systemd)
- [Security & Audit](#security--audit)
- [Containers & Namespaces](#containers--namespaces)
- [Incident Playbooks](#incident-playbooks)

Tip: Use your editor/browser search to jump to any command by its number, e.g., "## 41. lsof".

## Binaries & ELF

Cheat Card
- Linked libs: `ldd /path/to/bin` (security caveat: may execute code in rare cases)
- ELF headers/sections: `readelf -h /bin/ls`; sections: `readelf -S /bin/ls`
- Symbols (prefer readelf): `readelf -Ws /bin/ls | grep ' FUNC '`; dynamic: `readelf -Ws -d /bin/ls`
- Disassemble: `objdump -d /bin/ls | less` (add `-M intel` for Intel syntax)
- Symbols via nm: `nm -D /bin/ls | grep symbol_name`
- Requires: binutils (readelf/objdump/nm)

## 1. ldd

List shared library dependencies of executables and shared objects.
- Basic: `ldd /path/to/bin`
- Security caveat: may execute code in rare cases; avoid on untrusted binaries.
- Alternative: `LD_TRACE_LOADED_OBJECTS=1 /lib64/ld-linux-x86-64.so.2 /path/to/bin` (still uses loader)

## Text & Data Utilities

Cheat Card
- Search recursively: `grep -RIn --exclude-dir .git 'pattern' .`; context: `-C2`
- Edit in-place: `sed -i.bak -E 's/old/new/g' file` (backup)
- Summarize data: `awk -F, '{a[$1]+=$2} END{for(k in a) print k,a[k]}' file.csv`
- JSON parse: `jq -r '.items[].metadata.name' file.json`
- Compare dirs: `diff -ruN dir_old dir_new | less -R`
- Transform text: `tr -s ' ' | cut -d, -f1,3 | xargs -n1 echo`
- Safe temp: `mktemp -d` for dirs; files: `mktemp`
- Reverse lines: `rev <file` (quick visual check)

## 2. grep

- search for one or more expressions: `grep -E 'hello|world' temp`
- search for one or more words: `grep -Ew 'hello|world' temp`
- search for suffix matches: `grep -E 'hello(world|lolo)' temp`
- search for suffixes matching regex: `grep -E 'hello[0-9]{3,}' temp`
- recursive search in tree: `grep -RIn --exclude-dir .git --exclude='*.log' 'pattern' .`
- fixed strings (fast) and ignore case: `grep -Fni 'literal text' file`
- context lines: `grep -R --color -n -C2 'pattern' .` (or `-A` after, `-B` before)
- binary-skip and file names only: `grep -rI -l 'pattern' .`

## 3. sed

What it does: stream editor for non-interactive find/replace, line edits, and range selections.

- In-place with backup: `sed -i.bak -E 's/old/new/g' file`
- Delete matching lines: `sed -i '/pattern/d' file`
- Print lines between markers: `sed -n '/BEGIN/,/END/p' file`
- Replace with capture groups: `sed -E 's/([0-9]{4})-([0-9]{2})-([0-9]{2})/\3-\2-\1/' file`
- Insert before/after match:
  - Before: `sed '/pattern/i\\inserted before' file`
  - After:  `sed '/pattern/a\\appended after' file`
- Trim trailing spaces: `sed -i 's/[ \t]\+$//' file`
- Multiple edits: `sed -E -e 's/foo/bar/g' -e '/tmp/d' file`

## 4. awk

What it does: text processing and quick data summarization using fields and expressions.

- Default FS is whitespace; set CSV FS: `awk -F, '...' file.csv`
- Select fields: `awk '{print $1, $3}' file`
- Filter rows: `awk '$5 > 100 {print $1, $5}' file`
- Sum a column: `awk '{s+=$3} END{print s}' file`
- Group and sum by key: `awk '{a[$1]+=$2} END{for (k in a) print k, a[k]}' file`
- Pretty print: `awk '{printf "%-20s %10d\n", $1, $2}' file`
- Count unique values: `awk '{c[$1]++} END{for (k in c) print k, c[k]}' file`

## Networking

Cheat Card
- Ports→PIDs: `ss -ltnp`; established only: `ss -tn state established`
- TCP detail: `ss -i dst <ip>` (rtt, cwnd, retrans)
- Path/source IP: `ip route get <dest>`; counters: `ip -s link show <iface>`
- Latency/loss: `mtr -ezbw <dest>`; quick traceroute ICMP: `traceroute -I <dest>`
- Targeted capture: `tcpdump -ni <iface> tcp port 443` (or `port 53`, `icmp`)
- DNS: `resolvectl query <name>` or `dig <name> A +short`

## 5. ping

- Compat: Linux; Root: may require CAP_NET_RAW depending on system; Requires: iputils-ping.

- `-4`: ping IPv4 only
- `-6`: ping IPv6 only
- `-A`: adapts to roundtrip time
- `-b`: allow pinging broadcast addresses
- `-I`: ping through an interface
- `-M`: set PMTU strategy
- `-s`: set packetsize (default is 56B)
- `-t`: set IP time-to-live

- `ping 224.0.0.1`: ping multicast address

Notes:
- Using average `rtt` values, you can determine whether there are huge variations
  causing jitter, especially in RT applications
- ping will report duplications, however, duplicate packets should never occur,
  and seem to be caused by inappropriate link-level retransmissions
- ping will report damaged packets, suggesting broken hardware in the network
Requires: iputils-ping.

## 6. ip

- Compat: Linux; Root: not required for reads; Requires: iproute2.

- `ip addr`: Show information for all addresses
- `ip addr show dev wlo1`: Display information only for device wlo1

- `ip link`: Show information for all interfaces
- `ip link show dev wlo1`: Display information only for device wlo1

- `ip -s`: Display interface statistics (packets dropped, received, sent, etc.)

- Quick recipes:
  - Path and source IP: `ip route get <dest>`
  - Interface counters: `ip -s link show <iface>` (rx/tx errors, drops)
  - Neighbors/ARP: `ip neigh` and `ip neigh show dev <iface>`
  - Multicast: `ip maddr` or `ip maddr show dev <iface>`

Example
```bash
# Query path and chosen source IP
ip route get 8.8.8.8
# Expect: 8.8.8.8 via 192.168.1.1 dev wlo1 src 192.168.1.23
```

- `ip route`: List all of the route entries in the kernel
- `ip route add`: Add a route entry to the kernel routing table
- `ip route replace`: Replace an existing route (add if not present)

- `ip maddr`: Display multicast information for all devices
- `ip maddr show dev wlo1`

- `ip neigh show dev wlo1`: check for reachability of specific interfaces   
Requires: iproute2.

## 7. arp

- Compat: Legacy; prefer `ip neigh`; Requires: net-tools.

- `arp`: show all ARP table entries
- `arp -d address`: delete ARP entry for address
- `arp -s address hw_addr`: set up new table entry
Note: legacy from net-tools; prefer `ip neigh`. Requires: net-tools.

## 8. arping

- Compat: Linux; Root/CAP_NET_RAW required; Package: arping (iputils-arping on some distros).

- `arping -I wlo1 192.168.0.1`: send ARP requests to host
- `arping -D -I wlo1 192.168.0.15`: check for duplicate MAC address
Requires: arping (iputils-arping on some distros).

## 9. ethtool

- Compat: Linux; Root for changing settings, read stats usually ok; Requires: ethtool.

- `ethtool -S wlo1`: print network statistics
Requires: ethtool.

## 10. ss

- Compat: Linux; Modern replacement for netstat; Requires: iproute2.

- `ss -a`: show all sockets
- `ss -o`: show all sockets with timer information
- `ss -p`: show process using the socket
- `ss -t|-u|-4|-6`
- `ss -ltnp`: list listening TCP sockets with PIDs
- `ss -tn state established`: show established TCP only
- `ss -tn sport = :443` or `ss -tn dport = :443`: filter by port
- `ss -s`: summary stats (TCP states, mem)
- `ss -i`:
  - `ts`: show string "ts" if the timestamp option is set
  - `sack`: show string "sack" if the sack option is set
  - `ecn`: show string "ecn" if the explicit congestion notification option is set
  - `ecnseen`: show string "ecnseen" if the saw ecn flag is found in received packets
  - `fastopen`: show string "fastopen" if the fastopen option is set
  - `cong_alg`: the congestion algorithm name, the default congestion algorithm is "cubic"
  - `wscale:<snd_wscale>:<rcv_wscale>`: if window scale option is used, this field
    shows the send scale factor and receive scale factor
  - `rto:<icsk_rto>`: tcp re-transmission timeout value, the unit is millisecond
  - `backoff:<icsk_backoff>`: used for exponential backoff re-transmission, the
    actual re-transmission timeout value is icsk_rto << icsk_backoff
  - `rtt:<rtt>/<rttvar>`: rtt is the average round trip time, rttvar is the mean
    deviation of rtt, their units are millisecond
  - `ato:<ato>`: ack timeout, unit is millisecond, used for delay ack mode
  - `mss:<mss>`: max segment size
  - `cwnd:<cwnd>`: congestion window size
  - `pmtu:<pmtu>`: path MTU value
  - `ssthresh:<ssthresh>`: tcp congestion window slow start threshold
  - `bytes_acked:<bytes_acked>`: bytes acked
  - `bytes_received:<bytes_received>`: bytes received
  - `segs_out:<segs_out>`: segments sent out
  - `segs_in:<segs_in>`: segments received
  - `send <send_bps>bps`: egress bps
  - `lastsnd:<lastsnd>`: how long time since the last packet sent, the unit is millisecond
  - `lastrcv:<lastrcv>`: how long time since the last packet received, the unit is millisecond
  - `lastack:<lastack>`: how long time since the last ack received, the unit is millisecond
- `ss -A tcp,udp`: dump socket tables
Requires: iproute2.

## 37. tcpdump

Compat: Linux; Root/CAP_NET_RAW required for captures; Requires: tcpdump.
What it does: capture packets for inspection and troubleshooting. Requires: tcpdump.

- Interface and no name resolution: `tcpdump -ni <iface>`
- Host or subnet: `tcpdump -ni <iface> host <ip>`; `tcpdump -ni <iface> net 10.0.0.0/8`
- Ports/protocols: `tcpdump -ni <iface> tcp port 443` or `udp port 53`
- SYNs only (new TCP handshakes):
```bash
# New TCP handshakes only (SYN without ACK)
tcpdump -ni <iface> 'tcp[tcpflags] & (tcp-syn) != 0 and tcp[tcpflags] & (tcp-ack) == 0'
```
- DNS queries: `tcpdump -ni <iface> port 53`
- ICMP reachability: `tcpdump -ni <iface> icmp`
```bash
# Requires: tcpdump
# Capture full packets to a file
tcpdump -ni <iface> -s 0 -w capture.pcap

# Rotate captures every 5m, keep 6 files
tcpdump -ni <iface> -s 0 -G 300 -W 6 -w 'cap-%Y%m%d%H%M%S.pcap'
```

## 38. mtr

Compat: Linux; May need root/CAP_NET_RAW for certain probe types; Requires: mtr.
What it does: combines ping and traceroute to visualize latency and loss per hop.

- Run with extra info: `mtr -ezbw <dest>`
- Report mode (one-off): `mtr -ezbwrc 10 <dest>`
Requires: mtr.

## 39. traceroute

- Compat: Linux; Requires: traceroute; TCP mode may need CAP_NET_RAW/root.

- `traceroute -I`: use ICMP echo for probes
- `traceroute -T`: use TCP SYN for probes
Requires: traceroute.

## 40. nicstat

- Compat: Linux; Not widely packaged; Consider `sar -n`/`ethtool -S` alternatives.

- nicstat prints out network statistics for all network cards (NICs), including
  packets, kilobytes per second, average packet sizes and more.
- `nicstat -t`: show CPU stats
- `nicstat`: show network interface stats
Requires: nicstat (may need third-party repo/source on some distros).

<details>
<summary>Metrics reference (click to expand)</summary>

  - `Time` - The time corresponding to the end of the sample shown, in HH:MM:SS format (24-hour clock).
  - `Int` - The interface name.
  - `rKB/s, InKB` - Kilobytes/second read (received).
  - `wKB/s, OutKB` - Kilobytes/second written (transmitted).
  - `rMbps, RdMbps` - Megabits/second read (received).
  - `wMbps, WrMbps` - Megabits/second written (transmitted).
  - `rPk/s, InSeg, InDG` - Packets (TCP Segments, UDP Datagrams)/second read (received).
  - `wPk/s, OutSeg, OutDG` - Packets (TCP Segments, UDP Datagrams)/second written (transmitted).
  - `rAvs` - Average size of packets read (received).
  - `wAvs` - Average size of packets written (transmitted).
  - `%Util` - Percentage utilization of the interface. For full-duplex
    interfaces, this is the greater of rKB/s or wKB/s as a percentage of the
    interface speed. For half-duplex interfaces, rKB/s and wKB/s are summed.
  - `%rUtil, %wUtil` - Percentage utilization for bytes read and written, respectively.
  - `Sat` - Saturation. This the number of errors/second seen for the interface
    - an indicator the interface may be approaching saturation. This statistic
    is combined from a number of kernel statistics. It is recommended to use
    the '-x' option to see more individual statistics (those mentioned below)
    when attempting to diagnose a network issue.
  - `IErr` - Packets received that could not be processed because they contained errors
  - `OErr` - Packets that were not successfully transmitted because of errors
  - `Coll` - Ethernet collisions during transmit.
  - `NoCP` - No-can-puts. This is when an incoming packet can not be put to the
    process reading the socket. This suggests the local process is unable to
    process incoming packets in a timely manner.
  - `Defer` - Defer Transmits. Packets without collisions where first transmit
    attempt was delayed because the medium was busy.
  - `Reset` - tcpEstabResets. The number of times TCP connections have made a
    direct transition to the CLOSED state from either the ESTABLISHED state or
    the CLOSE-WAIT state.
  - `AttF` - tcpAttemptFails - The number of times that TCP connections have
    made a direct transition to the CLOSED state from either the SYN-SENT state
    or the SYN-RCVD state, plus the number of times TCP connections have made a
    direct transition to the LISTEN state from the SYN-RCVD state.
  - `%ReTX` - Percentage of TCP segments retransmitted - that is, the number of
    TCP segments transmitted containing one or more previously transmitted
    octets.
  - `InConn` - tcpPassiveOpens - The number of times that TCP connections have
    made a direct transition to the SYN-RCVD state from the LISTEN state.
  - `OutCon` - tcpActiveOpens - The number of times that TCP connections have
    made a direct transition to the SYN-SENT state from the CLOSED state.
  - `Drops` - tcpHalfOpenDrop + tcpListenDrop + tcpListenDropQ0. tcpListenDrop
    and tcpListenDropQ0 - Number of connections dropped from the completed
    connection queue and incomplete connection queue, respectively.
    tcpHalfOpenDrops - Number of connections dropped after the initial SYN
    packet was received.

</details>

## 41. nslookup

- Compat: Legacy; prefer `dig`/`resolvectl`; Requires: dnsutils/bind-utils.

query Internet name servers interactively

- `nslookup <domain>`
- Note: legacy tool. Prefer `dig` for detailed queries or `resolvectl` on
  systemd-based systems. Requires: dnsutils/bind-utils (for nslookup/dig).
- Quick equivalents: `dig <domain> A +short`; `resolvectl query <domain>`

## 42. host

- Compat: Linux; Requires: bind9-host/bind-utils.

host is a simple utility for performing DNS lookups. It is normally used to
convert names to IP addresses and vice versa.

- `host <domain>`
- Examples: `host -t A <domain>`; reverse lookup: `host <ip>`
- Tip: for more control, use `dig` (if installed) or `resolvectl`.
Requires: bind9-host (Debian/Ubuntu) or bind-utils.

## 43. iwconfig

- Compat: Legacy; prefer `iw`; Requires: wireless-tools.

- `iwconfig wlo1`: show WLAN config:
- Note: `iwconfig` is legacy (wireless-tools). Prefer `iw` for modern drivers,
  e.g., `iw dev`, `iw dev wlo1 link`.
Requires: wireless-tools. Modern alternative: iw.

```
wlo1      IEEE 802.11  ESSID:"NETGEAR97"  
      Mode:Managed  Frequency:2.462 GHz  Access Point: C4:04:15:58:60:C7   
      Bit Rate=72.2 Mb/s   Tx-Power=20 dBm   
      Retry short limit:7   RTS thr=2347 B   Fragment thr:off
      Power Management:off
      Link Quality=70/70  Signal level=-32 dBm  
      Rx invalid nwid:0  Rx invalid crypt:0  Rx invalid frag:0
      Tx excessive retries:0  Invalid misc:22932   Missed beacon:0
```

## 44. brctl

- Compat: Legacy; prefer `ip link` and `bridge`; Requires: bridge-utils.

- brctl is used to set up, maintain, and inspect the ethernet bridge configuration in the linux kernel.
Legacy: prefer `ip link add name br0 type bridge` and `bridge` (iproute2) tooling.
Requires: bridge-utils.

## Kernel & Tracing

Cheat Card
- Kernel logs: `dmesg -T -l err,crit,alert,emerg`
- Syscalls: `strace -ttT -p <pid> -f -e trace=network,file`
- Modules: `lsmod | head`, `modprobe <name>` (caution), `sysctl -a | grep tcp`
 - Optional advanced:
```bash
# perf (if installed)
perf top
perf record -g -p <pid>; perf report

# bpftrace one-liner (Requires: bpftrace)
bpftrace -e 'tracepoint:syscalls:sys_enter_openat { @[comm] = count(); }'
```

## 11. dmesg

- Compat: Linux; May be restricted by `kernel.dmesg_restrict`; Requires: util-linux.

- `dmesg --level=<LEVEL>`
  where `<LEVEL>` is:
  - `emerg` - system is unusable.
  - `alert` - action must be taken immediately.
  - `crit` - critical conditions.
  - `err` - error conditions.
  - `warn` - warning conditions.
  - `notice` - normal but significant condition.
  - `info` - informational.
  - `debug` - debug-level messages.
- `dmesg -k`: print kernel messages
- `dmesg -f=<FACILITY>`
  where `<FACILITY>` is:        
  - `kern`: Kernel messages.
  - `user`: User-level messages.
  - `mail`: Mail system.
  - `daemon`: System daemons.
  - `auth`: Security/authorization messages.
  - `syslog`: Internal syslogd messages.
  - `lpr`: Line printer subsystem.
  - `news`: Network news subsystem.
- `dmesg -T`: human readable timestamps

## 12. lsmod

- Compat: Linux; Lists modules without root; Requires: kmod.

- Show loaded kernel modules and sizes/dependencies.
- Quick peek: `lsmod | head`
- Module info (version, params): `modinfo <module>`

## 13. modprobe

- Compat: Linux; Root required; Caution: can destabilize systems; Requires: kmod.

Add or remove modules from the Linux kernel.
- Load: `modprobe <module>`; with params: `modprobe <module> key=value`
- Unload: `modprobe -r <module>` (fails if in use)
- Caution: loading/unloading modules can destabilize systems; prefer persistent
  config and ensure module compatibility.

## Disk & Filesystems

Cheat Card
- Space/inodes: `df -h` and `df -i`; biggest dirs: `du -xhd1 /path | sort -h`
- IO saturation: `iostat -xz 1`; per-proc IO: `pidstat -d 1`, `iotop -oPa`
- Devices/FS: `lsblk -o NAME,TYPE,SIZE,ROTA,MOUNTPOINT,MODEL`; mounts: `findmnt`
- Mount ops: `mount --bind olddir newdir`; remount ro: `mount -o remount,ro /mnt`

Inventory and health
- Device tree: `lsblk -o NAME,TYPE,SIZE,FSTYPE,MOUNTPOINT,MODEL`
- Identify filesystem UUID/TYPE: `blkid`
- SMART check (if supported): `smartctl -H /dev/sdX` and `smartctl -a /dev/sdX` (Requires: smartmontools)
- NVMe info: `nvme list`; `nvme smart-log /dev/nvme0` (Requires: nvme-cli)

Notes
- iostat quick view (Requires: sysstat): `iostat -xz 1` (watch `await`, `%util`, `r/s`, `w/s`)
- findmnt: show mount hierarchy or lookup by target: `findmnt /mount/point`

- adds or removes modules from the Linux Kernel
- Caution: loading/unloading modules can destabilize systems; prefer persistent
  config and ensure module compatibility.

## 14. dd (DANGER: DESTRUCTIVE — READ FIRST)

- Compat: Linux; Root required for raw devices; Highly destructive when writing; Requires: coreutils.

- Danger: dd will overwrite data with no confirmation. Double-check devices
  (e.g., `/dev/sdX`) and consider read-only or safer alternatives first. Use
  `lsblk`, `blkid` to verify targets.
- Safer tips: for copies, consider `pv` to visualize throughput; for imaging,
  `dcfldd`; for testing, prefer non-destructive reads.

```bash
# Danger: wipes target disk. Verify device with lsblk/blkid.
dd if=/dev/zero of=/dev/sda bs=4k status=progress
```

```bash
# Verify a drive is zeroed (non-zero bytes check)
dd if=/dev/sda status=none | hexdump -C | grep -q '[^00]' || echo "All zeros"
```

```bash
# Fill a file with random data (example size)
dd if=/dev/urandom of=myfile bs=6703104 count=1 status=progress
```

```bash
# Danger: clone a partition to another (same size/align). Verify both!
dd if=/dev/sda3 of=/dev/sdb3 bs=4096 status=progress conv=fsync
```

```bash
# Danger: write an image to a USB device. Verify device path first!
dd if=/path/to/bootimage.img of=/dev/sdc bs=4M status=progress conv=fsync
```

```bash
# Quick r/w benchmark for a file (non-destructive read + temp write)
dd if=/home/$user/bigfile of=/dev/null status=progress
dd if=/dev/zero of=/home/$user/bigfile bs=1M count=1000 oflag=dsync status=progress
```

```bash
# Sequential device read throughput sample (approx 1 GiB)
dd if=/dev/sda of=/dev/null bs=1024k count=1024 status=progress
```

```bash
# Create a swapfile (example: 8 GiB), then mkswap + swapon
dd if=/dev/zero of=swapfile bs=1MiB count=$((8*1024)) status=progress
```

## 15. jq

- Compat: Linux; Requires: jq package.

What it does: parse/query/transform JSON on the command line. Requires: jq.

- Pretty-print: `jq . file.json`
- Extract field list: `jq -r '.items[].metadata.name' file.json`
- Filter by condition: `jq '.[] | select(.status=="RUNNING")' file.json`
- Transform and count: `jq '[.[] | .level] | group_by(.) | map({level: .[0], count: length})' file.json`
- Sort and top N: `jq 'sort_by(.time) | reverse | .[0:5]' file.json`
- From journald: `journalctl -o json | jq -r 'select(.PRIORITY<=3) | .MESSAGE'`
```bash
# Requires: jq — show high-priority messages from journald
journalctl -o json | jq -r 'select(.PRIORITY<=3) | .MESSAGE'
```
- Keys and length: `jq 'keys, length' file.json`

## 16. diff

- Compat: Linux; Requires: diffutils.

- unified diff: `diff -u old.txt new.txt`
- recursive dirs: `diff -ruN dir_old dir_new`
- ignore whitespace changes: `diff -u -w old new`
- handle CRLF: `diff -u --strip-trailing-cr a b`
- color (if supported): `diff --color=auto -u a b`
- apply a patch: `patch -p1 < change.diff`

## 17. uname

- Compat: Linux; Requires: coreutils.

- get all details about the computer

## 18. sync/fsync

- Compat: Linux; `sync` is user command; `fsync` is a syscall.

- `fsync` is a syscall that flushes a file's in-memory data and metadata to
  storage. From the shell, use `sync` (flush all dirty data) or `syncfs` (flush
  a filesystem) when available.

## 19. mkswap

- Compat: Linux; Root required; Requires: util-linux.

- `-c`: check if blocks are corrupted
- `-p`: set pagesize

## 20. fsck

- Compat: Linux; Root required; Avoid on mounted filesystems; Requires: e2fsprogs for ext*.

- check for file system consistency:
  - The superblock is checked for inconsistencies in:
    - File system size
    - Number of inodes
    - Free-block count
    - Free-inode count
  - Each inode is checked for inconsistencies in:
    - Format and type
    - Link count
    - Duplicate block
    - Bad block numbers
    - Inode size
- see: https://docs.oracle.com/cd/E19455-01/805-7228/6j6q7uf0e/index.html
- Caution: avoid running fsck on a mounted filesystem (except with specific fs
  support); prefer read-only mounts or maintenance windows.

Extended notes
- ext* specifics: `e2fsck` checks ext2/3/4; use `-f` to force, `-n` for read-only,
  `-p` for preen (auto-fix safe issues). Requires: e2fsprogs.
- Bad blocks (DANGER): `badblocks` scans devices for bad sectors; write-mode is
  destructive. Prefer read-only first.

Examples
```bash
# Read-only badblocks scan (non-destructive)
sudo badblocks -sv /dev/sdX

# DANGER: write-mode destructive scan — data loss
sudo badblocks -wsv /dev/sdX

# ext* filesystem check (read-only)
sudo e2fsck -fn /dev/sdXN
```

## 21. mount

- Compat: Linux; Root required unless user mounts configured; Requires: util-linux.

- `mount -a [-t type] [-O optlist]`: mount all FSs mentioned in fstab to be mounted
- `-o`: override the settings in fstab
- `mount --bind olddir newdir`: remount part of the hierarchy elsewhere
- `mount --move`: move mounted tree to another place
- Caution: `--bind/--move` and remounts can impact running services; ensure
  correct `fstab` for persistence and have rollback plan.

## 22. umount

- Compat: Linux; Root required for system mounts; Requires: util-linux.

- unmount from a mountpoint

## 23. chown

- `chown root:staff /u`: change owner and group

## 24. sysctl

- Compat: Linux; Root required for `-w`; Persistence via `/etc/sysctl.d`; Requires: procps.

- configure kernel parameters at runtime
- `sysctl -a | grep "tcp"`
- Caution: `sysctl -w` changes take effect immediately; persist only via
  `/etc/sysctl.d/*.conf` after validation.
- Read a key: `sysctl net.ipv4.tcp_congestion_control`
- Set a key (runtime): `sysctl -w vm.swappiness=10`
- Persist: create `/etc/sysctl.d/99-local.conf` with `vm.swappiness = 10`, then `sysctl --system`

## 25. iotop

- Compat: Linux; Root required; Needs kernel taskstats/delay accounting; Python tool.

- `iotop -o`: only show threads doing I/O
- `iotop -p <PID1>,<PID2>,...`: list of processes to monitor
- `iotop -a`: show accumulated IO rather than diff
Requires: iotop.

## 26. netstat

- Compat: Legacy; prefer `ss`; Requires: net-tools.

## Processes & Scheduling

Cheat Card
- Top offenders: `ps -eo pid,ppid,user,%cpu,%mem,cmd --sort=-%cpu | head`
- Threads view: `top -H` or `ps -Lp <pid> -o pid,tid,pcpu,comm`
- Target processes:
```bash
# Preview before signaling
pgrep -a <name>

# Then send a scoped, safe signal (example: TERM)
pkill -TERM -u <user> -f '<exact-pattern>'
```
- Over time: `pidstat -u 1 -p <pid>` (CPU) and `pidstat -d 1` (IO)
- Find PIDs: `pidof <proc>`; list threads: `ps -Lp <pid>`
- Niceness: start `nice -n 10 cmd`; adjust: `renice -n 10 -p <pid>`
- Locks: `/proc/locks` shows current file locks (read-only)
- Sessions: users `who`; recent logins `last | head`
- Schedule: `crontab -l` list; `crontab -e` edit

- Deprecated in many distros; prefer `ss`.
- Common mappings:
  - `netstat -tulpn` -> `ss -tulpn`
  - `netstat -anp` -> `ss -anp`
  - `netstat -s` -> `ss -s`

## 27. top

- Compat: Linux; Requires: procps.

- Dynamic process view with CPU, memory, and load summaries.
- Key CPU line fields: `us` (user), `sy` (system), `ni`, `id` (idle), `wa`
  (iowait), `hi/si` (IRQ/softIRQ), `st` (steal).
- Key per-proc fields: `%CPU`, `%MEM`, `VIRT` (virtual), `RES` (resident), `SHR` (shared), `TIME+` (CPU time).

- `top -E m|g`: scale as mega|giga bytes
- `top -H`: thread-mode
- `top -i`: show idle processes
- `top -o RES|VIRT|SWAP`, etc: sort by attribute
- `top -O`: output fields: print all available sort-attributes
- `top -p pid1,pid2,...`: monitor only these PIDs
- `top -1`: show per-CPU stats

## 28. vmstat

- Compat: Linux; Requires: procps.

Useful to get so/si information

- Report virtual memory statistics
- `vmstat -a`: number active/inactive memory
- `vmstat --stats`: various statistics

Interpretation tips
- `r` runnable > number of CPUs indicates run-queue contention.
- `b` blocked processes (often IO wait); correlate with `%wa` in top/mpstat.
- `si/so` swap in/out: sustained non-zero values indicate memory pressure.
- Use `vmstat 1` for near-real-time view.

## 29. strace

- Compat: Linux; May be restricted by ptrace scope; Requires: strace.

Trace system calls and signals.
- Attach to a PID: `strace -ttT -p <pid> -f -e trace=network,file,fsync,clock,nanosleep`
- Run a program under strace: `strace -o strace.log -s 200 -vv -f -ttT your_cmd --arg`
- Syscall time summary: `strace -c -p <pid>`
- Filter a path: `strace -ttT -e trace=file -P /etc/resolv.conf -p <pid>`
- Notes: `-f` follows forks; `-ttT` adds timestamps and syscall durations; `-s` increases string size.
- trace system calls and signals

## 30. slabtop

- Compat: Linux; Requires: procps.

- `slabtop`: display kernel slab cache information in real time
- Sort by size: `slabtop -s c`; one-shot: `slabtop -o`

## 31. uptime

- Compat: Linux; Requires: procps.

- information about how long the system has been up, and load averages

## 32. htop

- Compat: Linux; Requires: htop package.

- like top, but prettier

## 33. ps

- Compat: Linux; Requires: procps.

Cheat Card
- Top CPU: `ps -eo pid,ppid,user,%cpu,%mem,cmd --sort=-%cpu | head`
- Top RSS: `ps -eo pid,user,rss,cmd --sort=-rss | head`
- Tree view: `ps -ejH` (or `ps axjf`)
- By command: `ps -C nginx -o pid,ppid,cmd,%mem,%cpu`
- Threads of a PID: `ps -Lp <pid> -o pid,tid,pcpu,comm`

- `ps aux`: show all processes
- `ps axjf` - print process tree
- `ps a` - Lift the BSD-style "only yourself" restriction
- `ps -A` - select all processes
- `ps -d` - select all processes except session leaders
- `ps g` - select all processes including session leaders
- `ps Ta` - all process associated with this terminal
- `ps r` - restrict to running processes
- `ps --pid pidlist` - restrict to pidlist processes
- `ps -s|--sid` - select by session ID
- `ps t ttylist` - select by TTY list
- `ps U|-U` - select by effective user-id
- `ps s` - display signals
- `ps f` - ASCII art process hierarchy

- `ps ax -o rss,pid,user,pcpu,command --sort -%cpu`: sort by %cpu
- `ps ax -o rss,pid,user,pcpu,command --sort -rss`: sort by rss

process states:
- `D` - uninterruptible sleep (usually IO)
- `I` - Idle kernel thread
- `R` - running or runnable (on run queue)
- `S` - interruptible sleep (waiting for an event to complete)
- `T` - stopped by job control signal
- `t` - stopped by debugger during the tracing
- `W` - paging (not valid since the 2.6.xx kernel)
- `X` - dead (should never be seen)
- `Z` - defunct ("zombie") process, terminated but not reaped by its parent

see STANDARD FORMAT SPECIFIERS in `man ps`

## CPU

Cheat Card
- CPU saturation: `mpstat -P ALL 1` (sys/iowait/irq/soft)
- Per-core view in top: `top -1`; over time per PID: `pidstat -u 1 -p <pid>`
- Interrupt spikes: `mpstat -I CPU 1`

## 34. mpstat

- Compat: Linux; Requires: sysstat.

The mpstat command writes to standard output activities for each available
processor, processor 0 being the first one. Global average activities among all
processors are also reported.
Requires: sysstat.

Interpretation tips
- High `%iowait`: CPUs idle while waiting on disk IO (check iostat).
- High `%irq/%soft`: heavy interrupts/softirqs (often network or storage).
- High `%steal`: hypervisor stealing time (noisy neighbor in a VM).
- Compare per-core: hotspots can be isolated to specific cores (affinity).

- `CPU`: Processor number. The keyword all indicates that statistics are
  calculated as averages among all processors.
- `%usr`: Show the percentage of CPU utilization that occurred while executing at
  the user level (application).
- `%nice`: Show the percentage of CPU utilization that occurred while executing
  at the user level with nice priority.
- `%sys`: Show the percentage of CPU utilization that occurred while executing at
  the system level (kernel). Note that this does not include time spent
  servicing hardware and software interrupts.
- `%iowait`: Show the percentage of time that the CPU or CPUs were idle during
  which the system had an outstanding disk I/O request.
- `%irq`: Show the percentage of time spent by the CPU or CPUs to service hardware interrupts.
- `%soft`: Show the percentage of time spent by the CPU or CPUs to service software interrupts.
- `%steal`: Show the percentage of time spent in involuntary wait by the virtual
  CPU or CPUs while the hypervisor was servicing another virtual processor.
- `%guest`: Show the percentage of time spent by the CPU or CPUs to run a virtual processor.
- `%gnice`: Show the percentage of time spent by the CPU or CPUs to run a niced guest.

- `mpstat -I`: report interrupt stats
  - # of interrupts per CPU
  - # of times a particular interrupt occurred

## Memory

Cheat Card
- Snapshot: `free -h --wide`; paging: `vmstat -a 1` (si/so)
- Per-proc memory: `ps -eo pid,user,rss,cmd --sort=-rss | head`; deep dive: `pmap -x <pid>`
- OOM evidence: `dmesg -T | grep -i oom` or `journalctl -k -g OOM`

## 35. free

- Compat: Linux; Requires: procps.

- `used` - Used memory (calculated as total - free - buffers - cache)
- `free` - Unused memory (MemFree and SwapFree in /proc/meminfo)
- `shared` - Memory used (mostly) by tmpfs (Shmem in /proc/meminfo)
- `buffers` - Memory used by kernel buffers (Buffers in /proc/meminfo)
- `cache` - Memory used by the page cache and slabs (Cached and SReclaimable in /proc/meminfo)
- `buff/cache` - Sum of buffers and cache
- `available` - Estimation of how much memory is available for starting new
  applications, without swapping. Unlike the data provided by the cache or free
  fields, this field takes into account page cache and also that not all
  reclaimable memory slabs will be reclaimed due to items being in use
  (MemAvailable in /proc/meminfo, available on kernels 3.14, emulated on
  kernels 2.6.27+, otherwise the same as free)

- `free -l`: show low-high memory breakdown
- `free --wide`: show free memory stats

Interpretation tips
- `available` approximates memory free for new apps without swapping; don't confuse `free` with usable memory.
- High `buff/cache` is normal; it's the page cache and reclaimable slabs.

Examples
- Human-readable snapshot: `free -h --wide`
- Example output:
  ```
                total        used        free      shared  buff/cache   available
  Mem:           31Gi        2.1Gi       22Gi        312Mi       7.2Gi        28Gi
  Swap:           8Gi           0B        8Gi
  ```

## 36. sar

- Compat: Linux; Requires: sysstat; history needs `sadc` enabled.

Cheat Card
- CPU load/queue: `sar -q 1 5`; memory: `sar -r 1 5`
- IO bw/ops: `sar -b 1 5`; per-device: `sar -d 1 5` (watch `await`, `%util`)
- Network: `sar -n DEV 1 5`; TCP: `sar -n TCP,ETCP 1 5`
- Paging: `sar -B 1 5` (`pgsteal`, `pgscan`, `majflt/s`)

Requires: sysstat (includes pidstat).

<details>
<summary>Field reference (click to expand)</summary>

- `sar -B`: report paging stats
  - `gpgin/s` - Total number of kilobytes the system paged in from disk per second.
  - `pgpgout/s` - Total number of kilobytes the system paged out to disk per second.
- `fault/s` - Number of page faults (major + minor) made by the system per
  second. This is not a count of page faults that generate I/O, because some
  page faults can be resolved without I/O.
  - `majflt/s` - Number of major faults the system has made per second, those
    which have required loading a memory page from disk.
  - `pgfree/s` - Number of pages placed on the free list by the system per second.
  - `pgscank/s` - Number of pages scanned by the kswapd daemon per second.
  - `pgscand/s` - Number of pages scanned directly per second.
  - `pgsteal/s` - Number of pages the system has reclaimed from cache (pagecache
    and swapcache) per second to satisfy its memory demands.
  - `%vmeff` - Calculated as pgsteal / pgscan, this is a metric of the
    efficiency of page reclaim. If it is near 100% then almost every page coming
    off the tail of the inactive list is being reaped. If it gets too low (e.g.
    less than 30%) then the virtual memory is having some difficulty. This
    field is displayed as zero if no pages have been scanned during the
    interval of time.

- `sar -b`: Report I/O and transfer rate statistics.
  - `tps` - Total number of transfers per second that were issued to physical
    devices. A transfer is an I/O request to a physical device. Multiple
    logical requests can be combined into a single I/O request to the device. A
    transfer is of indeterminate size.
  - `rtps` - Total number of read requests per second issued to physical devices.
  - `wtps` - Total number of write requests per second issued to physical devices.
  - `bread/s` - Total amount of data read from the devices in blocks per second.
    Blocks are equivalent to sectors and therefore have a size of 512 bytes.
  - `bwrtn/s` - Total amount of data written to devices in blocks per second.

- `sar -d`: report activity for each block device
- `tps` - Total number of transfers per second that were issued to physical
  devices. A transfer is an I/O request to a physical device. Multiple logical
  requests can be combined into a single I/O request to the device. A transfer
  is of indeterminate size.
  - `rkB/s` - Number of kilobytes read from the device per second.
  - `wkB/s` - Number of kilobytes written to the device per second.
  - `areq-sz` - The average size (in kilobytes) of the I/O requests that were
    issued to the device. Note: In previous versions, this field was known as
    avgrq-sz and was expressed in sectors.
  - `aqu-sz` - The average queue length of the requests that were issued to the
    device. Note: In previous versions, this field was known as avgqu-sz.
  - `await` - The average time (in milliseconds) for I/O requests issued to the
    device to be served. This includes the time spent by the requests in queue
    and the time spent servicing them.
  - `svctm` - The average service time (in milliseconds) for I/O requests that
    were issued to the device. Warning! Do not trust this field any more. This
    field will be removed in a future sysstat version.
  - `%util` - Percentage of elapsed time during which I/O requests were issued
    to the device (bandwidth utilization for the device). Device saturation
    occurs when this value is close to 100% for devices serving requests
    serially. But for devices serving requests in parallel, such as RAID arrays
    and modern SSDs, this number does not reflect their performance limits.

- `sar -F`: display stats. for currently mounted FSs:
  - `MBfsfree` - Total amount of free space in megabytes (including space available only to privileged user).
  - `MBfsused` - Total amount of space used in megabytes.
  - `%fsused` - Percentage of filesystem space used, as seen by a privileged user.
  - `%ufsused` - Percentage of filesystem space used, as seen by an unprivileged user.
  - `Ifree` - Total number of free file nodes in filesystem.
  - `Iused` - Total number of file nodes used in filesystem.
  - `%Iused` - Percentage of file nodes used in filesystem.

- `sar -m`: power management statistics:
  - `MHz` - Instantaneous CPU clock frequency in MHz.

  With the FAN keyword, statistics about fans speed are reported. The following values are displayed:
  - `rpm` - Fan speed expressed in revolutions per minute.
  - `drpm` - This field is calculated as the difference between current fan
    speed (rpm) and its low limit (fan_min).
  - `DEVICE` - Sensor device name.

  With the FREQ keyword, statistics about CPU clock frequency are reported. The following value is displayed:
  - `wghMHz` - Weighted average CPU clock frequency in MHz. Note that the
    cpufreq-stats driver must be compiled in the kernel for this option to work.

  With the IN keyword, statistics about voltage inputs are reported. The following values are displayed:
  - `inV` - Voltage input expressed in Volts.
  - `%in` - Relative input value. A value of 100% means that voltage input has
    reached its high limit (in_max) whereas a value of 0% means that it has
    reached its low limit (in_min).
  - `DEVICE` - Sensor device name. 
  
  With the USB keyword, the sar command takes a snapshot of all the USB devices
  currently plugged into the system. At the end of the report, sar will display
  a summary of all those USB devices. The following values are displayed:
  - `BUS` - Root hub number of the USB device.
  - `idvendor` - Vendor ID number (assigned by USB organization).
  - `idprod` - Product ID number (assigned by Manufacturer).
  - `maxpower` - Maximum power consumption of the device (expressed in mA).
  - `manufact` - Manufacturer name.
  - `product` - Product name.

- `sar -n DEV`:
  - `IFACE` - Name of the network interface for which statistics are reported.
  - `rxpck/s` - Total number of packets received per second.
  - `txpck/s` - Total number of packets transmitted per second.
  - `rxkB/s` - Total number of kilobytes received per second.
  - `txkB/s` - Total number of kilobytes transmitted per second.
  - `rxcmp/s` - Number of compressed packets received per second (for cslip etc.).
  - `txcmp/s` - Number of compressed packets transmitted per second.
  - `rxmcst/s` - Number of multicast packets received per second.
  - `%ifutil` - Utilization percentage of the network interface. For
    half-duplex interfaces, utilization is calculated using the sum of rxkB/s
    and txkB/s as a percentage of the interface speed. For full-duplex, this is
    the greater of rxkB/S or txkB/s.

- `sar -n EDEV`:
  - `IFACE` - Name of the network interface for which statistics are reported.
  - `rxerr/s` - Total number of bad packets received per second.
  - `txerr/s` - Total number of errors that happened per second while transmitting packets.
  - `coll/s` - Number of collisions that happened per second while transmitting packets.
  - `rxdrop/s` - Number of received packets dropped per second because of a lack of space in linux buffers.
  - `txdrop/s` - Number of transmitted packets dropped per second because of a lack of space in linux buffers.
  - `txcarr/s` - Number of carrier-errors that happened per second while transmitting packets.
  - `rxfram/s` - Number of frame alignment errors that happened per second on received packets.
  - `rxfifo/s` - Number of FIFO overrun errors that happened per second on received packets.
  - `txfifo/s` - Number of FIFO overrun errors that happened per second on transmitted packets.

- `sar -n ICMP`:
  - `imsg/s` - The total number of ICMP messages which the entity received per
    second [icmpInMsgs]. Note that this counter includes all those counted by
    ierr/s.
  - `omsg/s` - The total number of ICMP messages which this entity attempted to
    send per second [icmpOutMsgs]. Note that this counter includes all those
    counted by oerr/s.
  - `iech/s` - The number of ICMP Echo (request) messages received per second [icmpInEchos].
  - `iechr/s` - The number of ICMP Echo Reply messages received per second [icmpInEchoReps].
  - `oech/s` - The number of ICMP Echo (request) messages sent per second [icmpOutEchos].
  - `oechr/s` - The number of ICMP Echo Reply messages sent per second [icmpOutEchoReps].
  - `itm/s` - The number of ICMP Timestamp (request) messages received per second [icmpInTimestamps].
  - `itmr/s` - The number of ICMP Timestamp Reply messages received per second [icmpInTimestampReps].
  - `otm/s` - The number of ICMP Timestamp (request) messages sent per second [icmpOutTimestamps].
  - `otmr/s` - The number of ICMP Timestamp Reply messages sent per second [icmpOutTimestampReps].
  - `iadrmk/s` - The number of ICMP Address Mask Request messages received per second [icmpInAddrMasks].
  - `oadrmk/s` - The number of ICMP Address Mask Request messages sent per second [icmpOutAddrMasks].
  - `oadrmkr/s` - The number of ICMP Address Mask Reply messages sent per second [icmpOutAddrMaskReps].

- `sar -n EICMP`: Extended ICMP stats (errors, dest unreachable, time exceeded).
  Focus on spikes in `ierr/s` and `oerr/s`, and patterns in unreachable/time-
  exceeded when debugging path issues.

- `sar -n EIP`: Extended IPv4 stats (header errors, addr errors, discards, no
  routes, reassembly, fragment fails). Use to spot header errors and routing/
  no-route conditions.

- `sar -n IP6`: IPv6 per-protocol counters (receive/deliver/forward, multicast,
  fragmentation). Check for anomalies similar to IPv4.

- `sar -n EIP6`: Extended IPv6 errors and routing stats (header/addr errors,
  discards, no routes, reassembly/frag). Useful for IPv6-specific
  troubleshooting.

- `sar -n SOCK`:
  - `totsck` - Total number of sockets used by the system.
  - `tcpsck` - TCP sockets in use; `tcp-tw` - TIME_WAIT sockets.

- `sar -n SOFT`:
  - `total/s` - The total number of network frames processed per second.
  - `dropd/s` - The total number of network frames dropped per second because
    there was no room on the processing queue.
  - `squeezd/s` - The number of times the softirq handler function terminated
    per second because its budget was consumed or the time limit was reached,
    but more work could have been done.
  - `rx_rps/s` - The number of times the CPU has been woken up per second to
    process packets via an inter-processor interrupt.
  - `flw_lim/s` - The number of times the flow limit has been reached per
    second. Flow limiting is an optional RPS feature that can be used to limit
    the number of packets queued to the backlog for each flow to a certain
    amount. This can help ensure that smaller flows are processed even though
    much larger flows are pushing packets in.

- `sar -n TCP`:
  - `active/s` - The number of times TCP connections have made a direct
    transition to the SYN-SENT state from the CLOSED state per second
    [tcpActiveOpens].
  - `passive/s` - The number of times TCP connections have made a direct
    transition to the SYN-RCVD state from the LISTEN state per second
    [tcpPassiveOpens].
  - `iseg/s` - The total number of segments received per second, including those
    received in error [tcpInSegs]. This count includes segments received on
    currently established connections.
  - `oseg/s` - The total number of segments sent per second, including those on
    current connections but excluding those containing only retransmitted octets
    [tcpOutSegs].

- `sar -n ETCP`:
  - `atmptf/s` - The number of times per second TCP connections have made a
    direct transition to the CLOSED state from either the SYN-SENT state or the
    SYN-RCVD state, plus the number of times per second TCP connections have
    made a direct transition to the LISTEN state from the SYN-RCVD state
    [tcpAttemptFails].
  - `estres/s` - The number of times per second TCP connections have made a
    direct transition to the CLOSED state from either the ESTABLISHED state or
    the CLOSE-WAIT state [tcpEstabResets].
  - `retrans/s` - The total number of segments retransmitted per second - that
    is, the number of TCP segments transmitted containing one or more
    previously transmitted octets [tcpRetransSegs].
  - `isegerr/s` - The total number of segments received in error (e.g., bad TCP
    checksums) per second [tcpInErrs].
  - `orsts/s` - The number of TCP segments sent per second containing the RST flag [tcpOutRsts].

- `sar -n UDP`:
  - `idgm/s` - The total number of UDP datagrams delivered per second to UDP users [udpInDatagrams].
  - `odgm/s` - The total number of UDP datagrams sent per second from this entity [udpOutDatagrams].
  - `noport/s` - The total number of received UDP datagrams per second for which
    there was no application at the destination port [udpNoPorts].
  - `idgmerr/s` - The number of received UDP datagrams per second that could not
    be delivered for reasons other than the lack of an application at the
    destination port [udpInErrors].

- `sar -n UDP6`:
  - `idgm6/s` - The total number of UDP datagrams delivered per second to UDP users [udpInDatagrams].
  - `odgm6/s` - The total number of UDP datagrams sent per second from this entity [udpOutDatagrams].
  - `noport6/s` - The total number of received UDP datagrams per second for
    which there was no application at the destination port [udpNoPorts].
  - `idgmer6/s` - The number of received UDP datagrams per second that could not
    be delivered for reasons other than the lack of an application at the
    destination port [udpInErrors].

- `sar -q`:
  - `runq-sz` - Run queue length (number of tasks waiting for run time).
  - `plist-sz` - Number of tasks in the task list.
  - `ldavg-1` - System load average for the last minute. The load average is
    calculated as the average number of runnable or running tasks (R state), and
    the number of tasks in uninterruptible sleep (D state) over the specified
    interval.
  - `ldavg-5` - System load average for the past 5 minutes.
  - `ldavg-15` - System load average for the past 15 minutes.
  - `blocked` - Number of tasks currently blocked, waiting for I/O to complete.

- `sar -r`:
  - `kbmemfree` - Amount of free memory available in kilobytes.
  - `kbavail` - Estimate of how much memory in kilobytes is available for
    starting new applications, without swapping. The estimate takes into account
    that the system needs some page cache to function well, and that not all
    reclaimable memory slabs will be reclaimable, due to items being in use. The
    impact of those factors will vary from system to system.
- `kbmemused` - Amount of used memory in kilobytes (calculated as total
  installed memory - kbmemfree - kbbuffers - kbcached - kbslab).
  - `%memused` - Percentage of used memory.
  - `kbbuffers` - Amount of memory used as buffers by the kernel in kilobytes.
  - `kbcached` - Amount of memory used to cache data by the kernel in kilobytes.
- `kbcommit` - Amount of memory in kilobytes needed for current workload. This
  is an estimate of how much RAM/swap is needed to guarantee that there never is
  out of memory.
- `%commit` - Percentage of memory needed for current workload in relation to
  the total amount of memory (RAM+swap). This number may be greater than 100%
  because the kernel usually overcommits memory.
- `kbactive` - Amount of active memory in kilobytes (memory that has been used
  more recently and usually not reclaimed unless absolutely necessary).
- `kbinact` - Amount of inactive memory in kilobytes (memory which has been less
  recently used. It is more eligible to be reclaimed for other purposes).
  - `kbdirty` - Amount of memory in kilobytes waiting to get written back to the disk.
  - `kbanonpg` - Amount of non-file backed pages in kilobytes mapped into userspace page tables.
  - `kbslab` - Amount of memory in kilobytes used by the kernel to cache data structures for its own use.
  - `kbkstack` - Amount of memory in kilobytes used for kernel stack space.
  - `kbpgtbl` - Amount of memory in kilobytes dedicated to the lowest level of page tables.
  - `kbvmused` - Amount of memory in kilobytes of used virtual address space.

- `sar -S`:
  - `kbswpfree` - Amount of free swap space in kilobytes.
  - `kbswpused` - Amount of used swap space in kilobytes.
  - `%swpused` - Percentage of used swap space.
- `kbswpcad` - Amount of cached swap memory in kilobytes. This is memory that
  once was swapped out, is swapped back in but still also is in the swap area
  (if memory is needed it doesn't need to be swapped out again because it is
  already in the swap area. This saves I/O).
  - `%swpcad` - Percentage of cached swap memory in relation to the amount of used swap space.

- `sar -u`:
- `%user` - Percentage of CPU utilization that occurred while executing at the
  user level (application). Note that this field includes time spent running
  virtual processors.
- `%usr` - Percentage of CPU utilization that occurred while executing at the
  user level (application). Note that this field does NOT include time spent
  running virtual processors.
- `%nice` - Percentage of CPU utilization that occurred while executing at the
  user level with nice priority.
- `%system` - Percentage of CPU utilization that occurred while executing at the
  system level (kernel). Note that this field includes time spent servicing
  hardware and software interrupts.
- `%sys` - Percentage of CPU utilization that occurred while executing at the
  system level (kernel). Note that this field does NOT include time spent
  servicing hardware or software interrupts.
- `%iowait` - Percentage of time that the CPU or CPUs were idle during which the
  system had an outstanding disk I/O request.
- `%steal` - Percentage of time spent in involuntary wait by the virtual CPU or
  CPUs while the hypervisor was servicing another virtual processor.
  - `%irq` - Percentage of time spent by the CPU or CPUs to service hardware interrupts.
  - `%soft` - Percentage of time spent by the CPU or CPUs to service software interrupts.
  - `%guest` - Percentage of time spent by the CPU or CPUs to run a virtual processor.
  - `%gnice` - Percentage of time spent by the CPU or CPUs to run a niced guest.
- `%idle` - Percentage of time that the CPU or CPUs were idle and the system did
  not have an outstanding disk I/O request.

- `sar -v`:
  - `dentunusd` - Number of unused cache entries in the directory cache.
  - `file-nr` - Number of file handles used by the system.
  - `inode-nr` - Number of inode handlers used by the system.
  - `pty-nr` - Number of pseudo-terminals used by the system.

- `sar -W`: Report swapping statistics. The following values are displayed:
  - `pswpin/s` - Total number of swap pages the system brought in per second.
  - `pswpout/s` - Total number of swap pages the system brought out per second.

- `sar -w`: Report task creation and system switching activity.
  - `proc/s` - Tasks created per second; `cswch/s` - context switches per second.

- `sar -y`: Report TTY devices activity. The following values are displayed:
- `rcvin/s` - Number of receive interrupts per second for current serial line.
  Serial line number is given in the TTY column.
  - `xmtin/s` - Number of transmit interrupts per second for current serial line.
  - `framerr/s` - Number of frame errors per second for current serial line.
  - `prtyerr/s` - Number of parity errors per second for current serial line.
  - `brk/s` - Number of breaks per second for current serial line.
  - `ovrun/s` - Number of overrun errors per second for current serial line.

</details>

## 45. pidstat

- Compat: Linux; Requires: sysstat.

- monitor individual tasks currently being managed
Requires: sysstat.

Cheat Card
- CPU by PID: `pidstat -u 1 -p <pid>` (watch `%usr/%system/%wait`)
- IO by PID: `pidstat -d 1 -p <pid>` (check `kB_rd/s`, `kB_wr/s`, `iodelay`)
- Memory faults: `pidstat -r 1 -p <pid>` (watch `majflt/s`)
- Threads: `pidstat -t -u 1 -p <pid>`

- `pidstat -d`:
  - Key fields: `kB_rd/s`, `kB_wr/s`, `iodelay` (IO wait), `kB_ccwr/s` (cancelled writes).

- `pidstat -R`: Report realtime priority and scheduling policy information. The
  following values may be displayed:
  - Key fields: `prio`, `policy`.

- `pidstat -r`: Report page faults and memory utilization.

  When reporting statistics for individual tasks, the following values may be displayed:
  - Key fields: `majflt/s` (major faults), `RSS`, `%MEM`.

  When reporting global statistics for tasks and all their children, the following values may be displayed:
  - With children: `majflt-nr`, `minflt-nr` summarize faults.

- `pidstat -s`: Report stack utilization. The following values may be displayed:
  - Key fields: `StkRef` (used), `StkSize` (reserved).

- `pidstat -t`: Also display statistics for threads associated with selected tasks. List process and threads

- `pidstat -u`: Report CPU utilization.

  When reporting statistics for individual tasks, the following values may be displayed:
  - Key fields: `%usr`, `%system`, `%wait`, `%CPU`, `CPU`.

  When reporting global statistics for tasks and all their children, the following values may be displayed:
  - With children: `usr-ms`, `system-ms`, `guest-ms` summarize CPU time.

## 46. lsof

- Compat: Linux; May require root to see all descriptors; Requires: lsof.

```
# List all open files
lsof

# Processes using a file? (fuser equivalent)
lsof /path/to/file

# Open files within a directory
lsof +D /path

# Files by user
lsof -u name
lsof -u name1,name2
lsof -u name1 -u name2

# By program name
lsof -c apache

# AND'ing selection conditions
lsof -u www-data -c apache

# By pid
lsof -p 1

# Except certain pids
lsof -p ^1

# TCP and UDP connections
lsof -i
lsof -i tcp # TCP connections
lsof -i udp # UDP connections

# By port
lsof -i :25
lsof -i :smtp
lsof -i udp:53
lsof -i tcp:80

# All network activity by a user
lsof -a -u name1 -i

lsof -N # NFS use
lsof -U # UNIX domain socket use

# List PIDs
lsof -t -i
# Danger: broad kill; preview and scope carefully before use
kill -9 $(lsof -t -i) # Kill all programs w/network activity
```
Requires: lsof.

## 51. pmap

- Compat: Linux; Requires: procps; `-X` needs procps-ng.

- `pmap 29740 -X`: show
  Address,Perm,Offset,Device,Inode,Size,Rss,Pss,Referenced,Anonymous,LazyFree,
  ShmemPmdMapped,Shared_Hugetlb,Private_Hugetlb,Swap,SwapPss,Locked,THPeligible,
  Mapping
Requires: procps.

Common recipes
- Largest mappings first: `pmap -x <pid> | sort -nrk 3 | head` (by RSS KB)
- Totals summary: `pmap <pid>` (last line shows total)

## 52. blktrace

- Compat: Linux; Root required; Needs kernel block trace support; Requires: blktrace.

- blktrace is a block layer IO tracing mechanism which provides detailed
  information about request queue operations up to user space. There are three
  major components: a kernel component, a utility to record the i/o trace
  information for the kernel to user space, and utilities to analyse and view
  the trace information.

```bash
# Trace block I/O on /dev/sda and parse
sudo blktrace -d /dev/sda -o - | blkparse -i -
```
Requires: blktrace.

outputs:
```
CPU0 (8,0):
 Reads Queued:         385,     1540KiB     Writes Queued:           0,        0KiB
 Read Dispatches:       75,     1544KiB     Write Dispatches:        4,       16KiB
 Reads Requeued:         0         Writes Requeued:         0
 Reads Completed:      681,    15168KiB     Writes Completed:       42,     1208KiB
 Read Merges:          315,     1260KiB     Write Merges:            0,        0KiB
 Read depth:            84             Write depth:            21
 IO unplugs:            63             Timer unplugs:           0
CPU1 (8,0):
 Reads Queued:         406,     1624KiB     Writes Queued:          13,      996KiB
 Read Dispatches:       71,     1620KiB     Write Dispatches:       10,      992KiB
 Reads Requeued:         1         Writes Requeued:         0
 Reads Completed:        0,        0KiB     Writes Completed:        0,        0KiB
 Read Merges:          336,     1344KiB     Write Merges:            2,      200KiB
 Read depth:            84             Write depth:            21
 IO unplugs:            68             Timer unplugs:           0
CPU2 (8,0):
 Reads Queued:        1531,     6152KiB     Writes Queued:          30,      120KiB
 Read Dispatches:      257,     6152KiB     Write Dispatches:        3,      108KiB
 Reads Requeued:         0         Writes Requeued:         0
 Reads Completed:        0,        0KiB     Writes Completed:        0,        0KiB
 Read Merges:         1277,     5108KiB     Write Merges:           24,       96KiB
 Read depth:            84             Write depth:            21
 IO unplugs:           255             Timer unplugs:           0
CPU3 (8,0):
 Reads Queued:        1266,     5852KiB     Writes Queued:          23,       92KiB
 Read Dispatches:      279,     5852KiB     Write Dispatches:       21,       92KiB
 Reads Requeued:         0         Writes Requeued:         0
 Reads Completed:        0,        0KiB     Writes Completed:        0,        0KiB
 Read Merges:          987,     3948KiB     Write Merges:            2,        8KiB
 Read depth:            84             Write depth:            21
 IO unplugs:           279             Timer unplugs:           1

Total (8,0):
 Reads Queued:        3588,    15168KiB     Writes Queued:          66,     1208KiB
 Read Dispatches:      682,    15168KiB     Write Dispatches:       38,     1208KiB
 Reads Requeued:         1         Writes Requeued:         0
 Reads Completed:      681,    15168KiB     Writes Completed:       42,     1208KiB
 Read Merges:         2915,    11660KiB     Write Merges:           28,      304KiB
 IO unplugs:           665             Timer unplugs:           1
```

## 53. btrace

- Compat: Linux; Wrapper script from blktrace; Root required.

- The btrace script provides a quick and easy way to do live tracing of block
  devices. It calls blktrace on the specified devices and pipes the output
  through blkparse for formatting. See blktrace (8) for more in-depth
  information about how blktrace works.

- `btrace /dev/sda`
Requires: blktrace.



## 54. tr

- Compat: Linux; Requires: coreutils.

Translate, squeeze, and/or delete characters from standard input, writing to standard output.

- `tr '\n' ','`: convert new lines to commas
- squeeze repeats: `tr -s ' ' < file` (collapse runs of spaces)
- delete chars: `tr -d '\r' < file` (remove CR)
- keep only printable: `tr -cd '[:print:]\n' < file`
- case convert: `tr '[:upper:]' '[:lower:]' < file`

## 55. cut

- Compat: Linux; Requires: coreutils.

- select CSV fields: `cut -d, -f1,3 file.csv`
- ranges: `cut -d: -f1-3 /etc/passwd`
- bytes/chars: `cut -b1-10 file`; `cut -c1-20 file`
- complement: `cut -d, -f1 --complement file.csv`
- with headers: pair with `head -1` to see column indexes
## 56. xargs

- Compat: Linux; Requires: findutils; GNU `-r` may vary on BusyBox.

Build and run argument lists; combine with `find` and null-terminated records for safety.

- safe null delim: `find . -type f -name '*.log' -print0 | xargs -0 rm -f`
- limit args per call: `xargs -n 1 -I{} sh -c 'echo {}'`
- parallelism: `xargs -P 4 -n 1 cmd` (run 4 at a time)
- interactive confirm: `xargs -p rm` (ask before each batch)
- do nothing on empty input: `xargs -r cmd` (GNU)

## Logs & Systemd

Cheat Card
- Unit status: `systemctl status <unit>`; failed: `systemctl list-units --failed`
- Hot errors: `journalctl -xeu <unit>`; follow: `journalctl -fu <unit>`
- Boot scoping: `journalctl -b` and `-b -1`; size: `journalctl --disk-usage`

Systemd basics
```bash
# Unit status and enablement
systemctl status <unit>
systemctl is-active <unit>
systemctl is-enabled <unit>

# Failed units overview
systemctl list-units --failed
journalctl -xe  # recent critical logs

# Restart and verify logs from this boot
systemctl restart <unit>
journalctl -u <unit> -b -n 50
```

Journal essentials
```bash
# Recent errors for a unit and live follow
journalctl -xeu <unit>
journalctl -fu <unit>

# Time window and priority
journalctl -u <unit> --since "1 hour ago" --until now
journalctl -p err..alert -b

# Previous boot
journalctl -b -1

# JSON output piped to jq (Requires: jq)
journalctl -u <unit> -o json | jq -r '.MESSAGE'
```

Journal management
```bash
# Disk usage and vacuum
journalctl --disk-usage
journalctl --vacuum-size=1G
journalctl --vacuum-time=7d

# Make logs persistent (requires root; edit journald.conf)
# /etc/systemd/journald.conf: set Storage=persistent
systemctl restart systemd-journald

# Tip: tune RateLimitIntervalSec/RateLimitBurst to manage log storms
```

Resolved (DNS)
```bash
# Overall resolver status
resolvectl status

# Query using systemd-resolved
resolvectl query example.com

# Flush caches
resolvectl flush-caches
```

## Security & Audit

Cheat Card
- SELinux mode: `getenforce`; recent denials: `ausearch -m AVC -ts recent`
- AppArmor status: `aa-status`; set complain/enforce on a profile
- Audit rule example: `auditctl -w /etc/ssh/sshd_config -p wa -k sshcfg`

SELinux
```bash
# Current mode and temporary permissive (diagnostic; requires root)
getenforce
setenforce 0  # Caution: reduces enforcement

# Contexts and recent denials
ls -Z
ps -eZ | head
ausearch -m AVC -ts recent
journalctl -t setroubleshoot

# Manage booleans (example: allow httpd network connect)
getsebool -a | grep httpd
setsebool -P httpd_can_network_connect on
# Requires: selinux-utils/policycoreutils; setroubleshoot (optional)
```

AppArmor
```bash
# Status and service
aa-status
systemctl status apparmor

# Toggle a profile mode
aa-complain /path/to/bin
aa-enforce /path/to/bin
# Requires: apparmor-utils
```

Auditd
```bash
# Service and rules
systemctl status auditd
auditctl -l

# Search recent denials / by PID
ausearch -m avc -ts recent
ausearch -p <pid> -ts recent

# Watch a file for writes/attr changes (key: sshcfg)
auditctl -w /etc/ssh/sshd_config -p wa -k sshcfg

# Summary report
aureport --summary -ts today
# Requires: auditd (auditd, auditctl, ausearch, aureport)
```

## Containers & Namespaces

Cheat Card
- Enter container namespace: `nsenter --target <pid> --mount --uts --ipc --net --pid -- bash`
- Docker triage: `docker ps`, `docker logs --tail=200 -f <id>`, `docker exec -it <id> sh`
- K8s triage: `kubectl get pods -A`, `kubectl describe pod <pod> -n <ns>`,
  `kubectl logs <pod> -n <ns> --previous`

nsenter (enter namespaces of a PID)
```bash
# Get target PID (e.g., container process)
pidof <proc>

# Enter multiple namespaces of a PID
nsenter --target <pid> --mount --uts --ipc --net --pid -- bash

# Inspect and chroot-like into the process rootfs
ls -l /proc/<pid>/root
nsenter --target <pid> --mount -- chroot /proc/<pid>/root bash
```

Docker (if present)
```bash
# List, exec, inspect PID, and tail logs
docker ps --format '{{.ID}} {{.Names}} {{.Status}}'
docker exec -it <id|name> bash  # or sh
docker inspect -f '{{.State.Pid}}' <id>
docker logs --tail=200 -f <id>
```

Kubernetes (if present)
```bash
# Pods and events
kubectl get pods -A -o wide
kubectl get events -A --sort-by=.lastTimestamp | tail

# Describe, logs, and exec
kubectl describe pod <pod> -n <ns>
kubectl logs <pod> -n <ns> --tail=200
kubectl logs <pod> -n <ns> --previous
kubectl exec -it <pod> -n <ns> -- bash
```

CRI/containerd (if present)
```bash
# List, inspect, and logs via crictl
crictl ps -a
crictl inspect <id>
crictl logs <id>
```

Notes
- Without runtime CLIs, use `nsenter` by PID from `ps`/`systemctl`.
- Requires: docker or podman for Docker-like commands; kubectl; crictl for containerd/CRI.

## Incident Playbooks

High CPU
```bash
# Top CPU processes and hot threads
ps -eo pid,ppid,user,%cpu,%mem,cmd --sort=-%cpu | head
top -H
ps -Lp <pid> -o pid,tid,pcpu,comm

# Per-process CPU over time; optional perf if available
pidstat -u 1 -p <pid>
perf top  # if installed
```

High IO wait / Disk latency
```bash
# Device saturation and per-process IO
iostat -xz 1   # watch await, %util, r/s, w/s
pidstat -d 1
iotop -oPa

# Device/FS inventory and kernel errors
lsblk -o NAME,TYPE,SIZE,ROTA,MOUNTPOINT,MODEL
dmesg -T | egrep -i 'error|reset|blk|nvme'

# Optional deep dive
blktrace -d /dev/sdX -o - | blkparse -i -
```

Memory leak / OOM
```bash
# Snapshot and top RSS processes
free -h
ps aux --sort=-rss | head

# Per-process mappings and over-time faults
pmap -x <pid> | sort -nrk 3 | head
pidstat -r 1 -p <pid>
smem -r  # if installed

# OOM evidence
dmesg -T | grep -i oom || journalctl -k -g OOM
```

Packet loss / High latency
```bash
# Path and end-to-end latency
ip route get <dest>
mtr -ezbw <dest>

# Interface health and TCP details
ip -s link show <iface>
ethtool -S <iface>
ss -i dst <dest>

# Targeted capture samples
tcpdump -ni <iface> host <dest> and icmp
tcpdump -ni <iface> tcp port 443 and 'tcp[tcpflags] & tcp-syn != 0'
```

DNS failures
```bash
# Resolve via systemd-resolved (or dig if available)
resolvectl query example.com
resolvectl status
dig @8.8.8.8 example.com A +time=2 +tries=1

# Reachability and captures
ss -u 'sport = :53 or dport = :53'
tcpdump -ni <iface> port 53

# Config checks
ls -l /etc/resolv.conf
resolvectl flush-caches
# Check firewall rules as appropriate
```

TLS handshake issues
```bash
# Inspect handshake/cert chain (TLS1.2 example)
openssl s_client -connect host:443 -servername host -tls1_2 -showcerts

# Check expiry/subject/issuer quickly
echo | openssl s_client -connect host:443 -servername host 2>/dev/null \
  | openssl x509 -noout -dates -subject -issuer

# App behavior (SNI, ALPN, protocols)
curl -v https://host/

# If proxy/MTLS: verify CA path and client certs; check time skew
timedatectl
```

Disk full / Inode exhaustion
```bash
# Space vs inodes
df -h
df -i

# Find biggest dirs on same filesystem
du -xhd1 /path | sort -h

# Deleted-but-open files
lsof +L1
journalctl --vacuum-size=1G  # cull journal size

# Many small files
find /path -xdev -type f | wc -l
```

Syscall slowness
```bash
# Trace syscalls and timings
strace -ttT -p <pid> -f -e trace=network,file,fsync,clock,nanosleep

# Optional CPU hotspot profiling
perf record -g -p <pid>; perf report
```

Container restart loops
```bash
# Docker restart loops
docker ps --filter 'status=restarting'
docker logs <id> --tail=200

# Kubernetes restart loops
kubectl get pods -A
kubectl describe pod <pod> -n <ns>
kubectl logs <pod> -n <ns> --previous

# Node/agent issues
journalctl -u kubelet
```

- modify priority of running process
