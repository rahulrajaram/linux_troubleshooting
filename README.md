# Linux Commands

## 1. ldd

## 2. grep

- search for one or more expressions: `grep -E 'hello|world' temp`
- search for one or more words: `grep -Ew 'hello|world' temp`
- search for suffix matches: `grep -E 'hello(world|lolo)' temp`
- search for suffixes matching regex: `grep -E 'hello[0-9]{3,}' temp`

## 3. sed

## 4. awk

## 5. ping

- `-4`: ping IPv4 only
- `-6`: ping IPv4 only
- `-A`: adapts to roundtrip time
- `-b`: allow pinging broadcast addresses
- `-I`: ping through an interface
- `-M`: set PMTU strategy
- `-s`: set packetsize (default is 56B)
- `-t`: set IP time-to-live

- `ping 224.0.0.1`: ping multicast address

Notes:
- Using average `rtt` values, you can determine whether there are huge variations causing jitter, especially in RT applications
- ping will report duplications, however, duplicate packets should never occur, and seem to be caused by inappropriate link-level retransmissions
- ping will report damaged packets, suggesting broken hardware in the n/w

## 6. ip

- `ip addr`: Show information for all addresses
- `ip addr show dev wlo1`: Display information only for device wlo1

- `ip link`: Show information for all interfaces
- `ip link show dev wlo1`: Display information only for device wlo1

- `ip -s`: Display interface statistics (packets dropped, received, sent, etc.)

- `ip route`: List all of the route entries in the kernel
- `ip route add`: List all of the route entries in the kernel
- `ip route replace`: List all of the route entries in the kernel

- `ip maddr`: Display multicast information for all devices
- `ip maddr show dev wlo1`

- `ip neigh show dev wlo1`: check for reachability of specific interfaces   

## 7. arp

- `arp`: show all ARP table entries
- `arp -d address`: delete ARP entry for address
- `arp -s address hw_addr`: set up new table entry

## 8. arping

- `arping -I wlo1 192.168.0.1`: send ARP requests to host
- `arping -D -I wlo1 192.168.0.15`: check for duplicate MAC address

## 9. ethtool

- `ethtool -S wlo1`: print n/w statistics

## 10. ss

- `ss -a`: show all sockets
- `ss -o`: show all sockets with timer information
- `ss -p`: show process using the socket
- `ss -t|-u|-4|-6`
- `ss -i`:
  - `ts`: show string "ts" if the timestamp option is set
  - `sack`: show string "sack" if the sack option is set
  - `ecn`: show string "ecn" if the explicit congestion notification option is set
  - `ecnseen`: show string "ecnseen" if the saw ecn flag is found in received packets
  - `fastopen`: show string "fastopen" if the fastopen option is set
  - `cong_alg`: the congestion algorithm name, the default congestion algorithm is "cubic"
  - `wscale:<snd_wscale>:<rcv_wscale>`: if window scale option is used, this field shows the send scale factor and receive scale factor
  - `rto:<icsk_rto>`: tcp re-transmission timeout value, the unit is millisecond
  - `backoff:<icsk_backoff>`: used for exponential backoff re-transmission, the actual re-transmission timeout value is icsk_rto << icsk_backoff
  - `rtt:<rtt>/<rttvar>`: rtt is the average round trip time, rttvar is the mean deviation of rtt, their units are millisecond
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

## 11. dmesg

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

- show status of modules in the Linux kernel

## 13. modprobe

- adds or removes modules from the Linux Kernel

## 14. dd (DO NOT SIMPLY RUN THESE)

- `dd if=/dev/zero of=/dev/sda bs=4k`: clean up HD 4k blocks at a time
- `dd if=/dev/sda | hexdump -C | grep [^00]`: check if drive is zeroed out
- `dd if=/dev/urandom of=myfile bs=6703104 count=1`: fill file with random chars
- `dd if=/dev/sda3 of=/dev/sdb3 bs=4096`: copy one partition onto another
- `dd if=/path/to/bootimage.img of=/dev/sdc`: create bootable USG drive
- `dd if=/home/$user/suspicious.doc | clamscan -`: check file for viruses
- `dd if=/home/$user/bigfile of=/dev/null && dd if=/dev/zero of=/home/$user/bigfile bs=1024 count=1000000`: benchmark HD for r/w speed
- `dd if=/dev/mem | strings | grep 'string_to_search'`: examine memory contents
- `dd if=/proc/kcore | hexdump -C | less`: view virtual memory
- `dd if=/dev/sda of=/dev/null bs=1024k count=1024`: determine sequential I/O speed for device
- `dd if=/dev/mem of=myRAM bs=1024`: copy RAM memory to file
- `dd if=/dev/zero of=swapfile bs=1MiB count=$((8*1024))`: set up swap space for mkswap

## 15. jq

- parse JSON string

## 16. diff

- compare file line by line

## 17. uname

- get all details about the computer

## 18. fsync

- sync in-memory data and metadata changes of a file to storage

## 19. mkswap

- `-c`: check if blocks are corrupted
- `-p`: set pagesize

## 20. fsck

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

## 21. mount

- `mount -a [-t type] [-O optlist]`: mount all FSs mentioned in fstab to be mounted
- `-o`: override the settings in fstab
- `mount --bind olddir newdir`: remount part of the hierarchy elsewhere
- `mount --move`: move mounted tree to another place

## 22. umount

- unmount from a mountpoint

## 23. chown

- `chown root:staff /u`: change owner and group

## 24. sysctl

- configure kernel parameters at runtime
- `sysctl -a | grep "tcp"`

## 25. iotop

- `iotop -o`: only show threads doing I/O
- `iotop -p <PID1>,<PID2>,...`: list of processes to monitor
- `iotop -a`: show accumulated IO rather than diff

## 26. netstat

- shows information similar to `ss`

## 27. top

- provides a dynamic real-time view of a running system
- can display system summary information as well as a list of processes or threads currently being managed by the Linux kernel
- descriptions of fields:
  - `%MEM` - simply RES divided by total physical memory
  - `CODE` - the 'pgms' portion of quadrant 3
  - `DATA` - the entire quadrant 1 portion of VIRT plus all explicit mmap file-backed pages of quadrant 3
  - `RES` - anything occupying physical memory which, beginning with Linux-4.5, is the sum of the following three fields:
    - `RSan` - quadrant 1 pages, which include any former quadrant 3 pages if modified
    - `RSfd` - quadrant 3 and quadrant 4 pages
    - `RSsh` - quadrant 2 pages
  - `RSlk` - subset of RES which cannot be swapped out (any quadrant)
  - `SHR` - subset of RES (excludes 1, includes all 2 & 4, some 3)
  - `SWAP` - potentially any quadrant except 4
  - `USED` - simply the sum of RES and SWAP
  - `VIRT` - everything in-use and/or reserved (all quadrants)
  - `us, user` - time running un-niced user processes
  - `sy, system` - time running kernel processes
  - `ni, nice` - time running niced user processes
  - `id, idle` - time spent in the kernel idle handler
  - `wa, IO-wait` - time waiting for I/O completion
  - `hi` - time spent servicing hardware interrupts
  - `si` - time spent servicing software interrupts
  - `st` - time stolen from this vm by the hypervisor

- `top -E m|g`: scale as mega|giga bytes
- `top -H`: thread-mode
- `top -i`: show idle processes
- `top -o RES|VIRT|SWAP`, etc: sort by attribute
- `top -O`: output fields: print all available sort-attributes
  - CGNAME CGROUPS CODE COMMAND %CPU DATA ENVIRON Flags GID GROUP LXC %MEM nDRT NI nMaj nMin nsIPC nsMNT nsNET nsPID nsUSER nsUTS nTH NU OOMa OOMs P PGRP PID PPID PR RES RSan RSfd RSlk RSsh RUID RUSER S SHR SID SUID SUPGIDS SUPGRPS SUSER SWAP TGID TIME TIME+ TPGID TTY UID USED USER VIRT vMj vMn WCHAN
- `top -p pid1,pid2,...`: monitor only these PIDs
- `top -1`: show per-CPU stats

## 28. vmstat

Useful to get so/si information

- Report virtual memory statistics
- `vmstat -a`: number active/inactive memory
- `vmstat --stats`: various statistics

## 29. strace

- trace system calls and signals

## 30. slabtop

- `slabtop`: display kernel slab cache information in real time

## 31. uptime

- information about how long the system has been up, and load averages

## 32. htop

- like top, but prettier

## 33. ps

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

## 34. mpstat

The mpstat command writes to standard output activities for each available processor, processor 0 being the first one. Global average activities among all processors are also reported.

- `CPU`: Processor number. The keyword all indicates that statistics are calculated as averages among all processors.
- `%usr`: Show the percentage of CPU utilization that occurred while executing at the user level (application).
- `%nice`: Show the percentage of CPU utilization that occurred while executing at the user level with nice priority.
- `%sys`: Show the percentage of CPU utilization that occurred while executing at the system level (kernel). Note that this does not include time spent servicing hardware and software interrupts.
- `%iowait`: Show the percentage of time that the CPU or CPUs were idle during which the system had an outstanding disk I/O request.
- `%irq`: Show the percentage of time spent by the CPU or CPUs to service hardware interrupts.
- `%soft`: Show the percentage of time spent by the CPU or CPUs to service software interrupts.
- `%steal`: Show the percentage of time spent in involuntary wait by the virtual CPU or CPUs while the hypervisor was servicing another virtual processor.
- `%guest`: Show the percentage of time spent by the CPU or CPUs to run a virtual processor.
- `%gnice`: Show the percentage of time spent by the CPU or CPUs to run a niced guest.

- `mpstat -I`: report interrupt stats
  - # of interrupts per CPU
  - # of times a particular interrupt occurred

## 35. free

- `used` - Used memory (calculated as total - free - buffers - cache)
- `free` - Unused memory (MemFree and SwapFree in /proc/meminfo)
- `shared` - Memory used (mostly) by tmpfs (Shmem in /proc/meminfo)
- `buffers` - Memory used by kernel buffers (Buffers in /proc/meminfo)
- `cache` - Memory used by the page cache and slabs (Cached and SReclaimable in /proc/meminfo)
- `buff/cache` - Sum of buffers and cache
- `available` - Estimation of how much memory is available for starting new applications, without swapping. Unlike the data provided by the cache or free fields, this field takes into account page cache and also that not all reclaimable memory slabs will be reclaimed due to items being in use (MemAvailable in /proc/meminfo, available on kernels 3.14, emulated on kernels 2.6.27+, otherwise the same as free)

- `free -l`: show low-high memory breakdown
- `free --wide`: show free memory stats

## 36. sar

- `sar -B`: report paging stats
  - `gpgin/s` - Total number of kilobytes the system paged in from disk per second.
  - `pgpgout/s` - Total number of kilobytes the system paged out to disk per second.
  - `fault/s` - Number of page faults (major + minor) made by the system per second. This is not a count of page faults that generate I/O, because some page faults can be resolved without I/O.
  - `majflt/s` - Number of major faults the system has made per second, those which have required loading a memory page from disk.
  - `pgfree/s` - Number of pages placed on the free list by the system per second.
  - `pgscank/s` - Number of pages scanned by the kswapd daemon per second.
  - `pgscand/s` - Number of pages scanned directly per second.
  - `pgsteal/s` - Number of pages the system has reclaimed from cache (pagecache and swapcache) per second to satisfy its memory demands.
  - `%vmeff` - Calculated as pgsteal / pgscan, this is a metric of the efficiency of page reclaim. If it is near 100% then almost every page coming off the tail of the inactive list is being reaped. If it gets too low (e.g. less than 30%) then the virtual memory is having some difficulty. This field is displayed as zero if no pages have been scanned during the interval of time.

- `sar -b`: Report I/O and transfer rate statistics.
  - `tps` - Total number of transfers per second that were issued to physical devices. A transfer is an I/O request to a physical device. Multiple logical requests can be combined into a single I/O request to the device. A transfer is of indeterminate size.
  - `rtps` - Total number of read requests per second issued to physical devices.
  - `wtps` - Total number of write requests per second issued to physical devices.
  - `bread/s` - Total amount of data read from the devices in blocks per second. Blocks are equivalent to sectors and therefore have a size of 512 bytes.
  - `bwrtn/s` - Total amount of data written to devices in blocks per second.

- `sar -d`: report activity for each block device
  - `tps` - Total number of transfers per second that were issued to physical devices. A transfer is an I/O request to a physical device. Multiple logical requests can be combined into a single I/O request to the device. A transfer is of indeterminate size.
  - `rkB/s` - Number of kilobytes read from the device per second.
  - `wkB/s` - Number of kilobytes written to the device per second.
  - `areq-sz` - The average size (in kilobytes) of the I/O requests that were issued to the device. Note: In previous versions, this field was known as avgrq-sz and was expressed in sectors.
  - `aqu-sz` - The average queue length of the requests that were issued to the device. Note: In previous versions, this field was known as avgqu-sz.
  - `await` - The average time (in milliseconds) for I/O requests issued to the device to be served. This includes the time spent by the requests in queue and the time spent servicing them.
  - `svctm` - The average service time (in milliseconds) for I/O requests that were issued to the device. Warning! Do not trust this field any more. This field will be removed in a future sysstat version.
  - `%util` - Percentage of elapsed time during which I/O requests were issued to the device (bandwidth utilization for the device). Device saturation occurs when this value is close to 100% for devices serving requests serially. But for devices serving requests in parallel, such as RAID arrays and modern SSDs, this number does not reflect their performance limits.

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
  - `drpm` - This field is calculated as the difference between current fan speed (rpm) and its low limit (fan_min).
  - `DEVICE` - Sensor device name.

  With the FREQ keyword, statistics about CPU clock frequency are reported. The following value is displayed:
  - `wghMHz` - Weighted average CPU clock frequency in MHz. Note that the cpufreq-stats driver must be compiled in the kernel for this option to work.

  With the IN keyword, statistics about voltage inputs are reported. The following values are displayed:
  - `inV` - Voltage input expressed in Volts.
  - `%in` - Relative input value. A value of 100% means that voltage input has reached its high limit (in_max) whereas a value of 0% means that it has reached its low limit (in_min).
  - `DEVICE` - Sensor device name. 
  
  With the USB keyword, the sar command takes a snapshot of all the USB devices currently plugged into the system. At the end of the report, sar will display a summary of all those USB devices. The following values are displayed:
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
  - `%ifutil` - Utilization percentage of the network interface. For half-duplex interfaces, utilization is calculated using the sum of rxkB/s and txkB/s as a percentage of the interface speed. For full-duplex, this is the greater of rxkB/S or txkB/s.

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
  - `imsg/s` - The total number of ICMP messages which the entity received per second [icmpInMsgs]. Note that this counter includes all those counted by ierr/s.
  - `omsg/s` - The total number of ICMP messages which this entity attempted to send per second [icmpOutMsgs]. Note that this counter includes all those counted by oerr/s.
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

- `sar -n EICMP`:
  - `ierr/s` - The number of ICMP messages per second which the entity received but determined as having ICMP-specific errors (bad ICMP checksums, bad length, etc.) [icmpInErrors].
  - `oerr/s` - The number of ICMP messages per second which this entity did not send due to problems discovered within ICMP such as a lack of buffers [icmpOutErrors].
  - `idstunr/s` - The number of ICMP Destination Unreachable messages received per second [icmpInDestUnreachs].
  - `odstunr/s` - The number of ICMP Destination Unreachable messages sent per second [icmpOutDestUnreachs].
  - `itmex/s` - The number of ICMP Time Exceeded messages received per second [icmpInTimeExcds].
  - `otmex/s` - The number of ICMP Time Exceeded messages sent per second [icmpOutTimeExcds].
  - `iparmpb/s` - The number of ICMP Parameter Problem messages received per second [icmpInParmProbs].
  - `oparmpb/s` - The number of ICMP Parameter Problem messages sent per second [icmpOutParmProbs].
  - `isrcq/s` - The number of ICMP Source Quench messages received per second [icmpInSrcQuenchs].
  - `osrcq/s` - The number of ICMP Source Quench messages sent per second [icmpOutSrcQuenchs].
  - `iredir/s` - The number of ICMP Redirect messages received per second [icmpInRedirects].
  - `oredir/s` - The number of ICMP Redirect messages sent per second [icmpOutRedirects].

- `sar -n EIP`:
  - `ihdrerr/s` - The number of input datagrams discarded per second due to errors in their IP headers, including bad checksums, version number mismatch, other format errors, time-to-live exceeded, errors discovered in processing their IP options, etc. [ipInHdrErrors]
  - `iadrerr/s` - The number of input datagrams discarded per second because the IP address in their IP header's destination field was not a valid address to be received at this entity. This count includes invalid addresses (e.g., 0.0.0.0) and addresses of unsupported Classes (e.g., Class E). For entities which are not IP routers and therefore do not forward datagrams, this counter includes datagrams discarded because the destination address was not a local address [ipInAddrErrors].
  - `iukwnpr/s` - The number of locally-addressed datagrams received successfully but discarded per second because of an unknown or unsupported protocol [ipInUnknownProtos].
  - `idisc/s` - The number of input IP datagrams per second for which no problems were encountered to prevent their continued processing, but which were discarded (e.g., for lack of buffer space) [ipInDiscards]. Note that this counter does not include any datagrams discarded while awaiting re-assembly.
  - `odisc/s` - The number of output IP datagrams per second for which no problem was encountered to prevent their transmission to their destination, but which were discarded (e.g., for lack of buffer space) [ipOutDiscards]. Note that this counter would include datagrams counted in fwddgm/s if any such packets met this (discretionary) discard criterion.
  - `onort/s` - The number of IP datagrams discarded per second because no route could be found to transmit them to their destination [ipOutNoRoutes]. Note that this counter includes any packets counted in fwddgm/s which meet this 'no-route' criterion. Note that this includes any datagrams which a host cannot route because all of its default routers are down.
  - `asmf/s` - The number of failures detected per second by the IP re-assembly algorithm (for whatever reason: timed out, errors, etc) [ipReasmFails]. Note that this is not necessarily a count of discarded IP fragments since some algorithms can lose track of the number of fragments by combining them as they are received.
  - `fragf/s` - The number of IP datagrams that have been discarded per second because they needed to be fragmented at this entity but could not be, e.g., because their Don't Fragment flag was set [ipFragFails].

- `sar -n IP6`:
  - `irec6/s` - The total number of input datagrams received from interfaces per second, including those received in error [ipv6IfStatsInReceives].
  - `fwddgm6/s` - The number of output datagrams per second which this entity received and forwarded to their final destinations [ipv6IfStatsOutForwDatagrams].
  - `idel6/s` - The total number of datagrams successfully delivered per second to IPv6 user-protocols (including ICMP) [ipv6IfStatsInDelivers].
  - `orq6/s` - The total number of IPv6 datagrams which local IPv6 user-protocols (including ICMP) supplied per second to IPv6 in requests for transmission [ipv6IfStatsOutRequests]. Note that this counter does not include any datagrams counted in fwddgm6/s.
  - `asmrq6/s` - The number of IPv6 fragments received per second which needed to be reassembled at this interface [ipv6IfStatsReasmReqds].
  - `asmok6/s` - The number of IPv6 datagrams successfully reassembled per second [ipv6IfStatsReasmOKs].
  - `imcpck6/s` - The number of multicast packets received per second by the interface [ipv6IfStatsInMcastPkts].
  - `omcpck6/s` - The number of multicast packets transmitted per second by the interface [ipv6IfStatsOutMcastPkts].
  - `fragok6/s` - The number of IPv6 datagrams that have been successfully fragmented at this output interface per second [ipv6IfStatsOutFragOKs].
  - `fragcr6/s` - The number of output datagram fragments that have been generated per second as a result of fragmentation at this output interface [ipv6IfStatsOutFragCreates].

- `sar -n EIP6`:
  - `ihdrer6/s` - The number of input datagrams discarded per second due to errors in their IPv6 headers, including version number mismatch, other format errors, hop count exceeded, errors discovered in processing their IPv6 options, etc. [ipv6IfStatsInHdrErrors]
  - `iadrer6/s` - The number of input datagrams discarded per second because the IPv6 address in their IPv6 header's destination field was not a valid address to be received at this entity. This count includes invalid addresses (e.g., ::0) and unsupported addresses (e.g., addresses with unallocated prefixes). For entities which are not IPv6 routers and therefore do not forward datagrams, this counter includes datagrams discarded because the destination address was not a local address [ipv6IfStatsInAddrErrors].
  - `iukwnp6/s` - The number of locally-addressed datagrams received successfully but discarded per second because of an unknown or unsupported protocol [ipv6IfStatsInUnknownProtos].
  - `i2big6/s` - The number of input datagrams that could not be forwarded per second because their size exceeded the link MTU of outgoing interface [ipv6IfStatsInTooBigErrors].
  - `idisc6/s` - The number of input IPv6 datagrams per second for which no problems were encountered to prevent their continued processing, but which were discarded (e.g., for lack of buffer space) [ipv6IfStatsInDiscards]. Note that this counter does not include any datagrams discarded while awaiting re-assembly.
  - `odisc6/s` - The number of output IPv6 datagrams per second for which no problem was encountered to prevent their transmission to their destination, but which were discarded (e.g., for lack of buffer space) [ipv6IfStatsOutDiscards]. Note that this counter would include datagrams counted in fwddgm6/s if any such packets met this (discretionary) discard criterion.
  - `inort6/s` - The number of input datagrams discarded per second because no route could be found to transmit them to their destination [ipv6IfStatsInNoRoutes].
  - `onort6/s` - The number of locally generated IP datagrams discarded per second because no route could be found to transmit them to their destination [unknown formal SNMP name].
  - `asmf6/s` - The number of failures detected per second by the IPv6 re-assembly algorithm (for whatever reason: timed out, errors, etc.) [ipv6IfStatsReasmFails]. Note that this is not necessarily a count of discarded IPv6 fragments since some algorithms can lose track of the number of fragments by combining them as they are received.
  - `fragf6/s` - The number of IPv6 datagrams that have been discarded per second because they needed to be fragmented at this output interface but could not be [ipv6IfStatsOutFragFails].
  - `itrpck6/s` - The number of input datagrams discarded per second because datagram frame didn't carry enough data [ipv6IfStatsInTruncatedPkts].

- `sar -n SOCK`:
  - `totsck` - Total number of sockets used by the system.
  - `tcpsck` - Number of TCP sockets currently in use.
  - `udpsck` - Number of UDP sockets currently in use.
  - `rawsck` - Number of RAW sockets currently in use.
  - `ip-frag` - Number of IP fragments currently in queue.
  - `tcp-tw` - Number of TCP sockets in TIME_WAIT state.

- `sar -n SOFT`:
  - `total/s` - The total number of network frames processed per second.
  - `dropd/s` - The total number of network frames dropped per second because there was no room on the processing queue.
  - `squeezd/s` - The number of times the softirq handler function terminated per second because its budget was consumed or the time limit was reached, but more work could have been done.
  - `rx_rps/s` - The number of times the CPU has been woken up per second to process packets via an inter-processor interrupt.
  - `flw_lim/s` - The number of times the flow limit has been reached per second. Flow limiting is an optional RPS feature that can be used to limit the number of packets queued to the backlog for each flow to a certain amount. This can help ensure that smaller flows are processed even though much larger flows are pushing packets in.

- `sar -n TCP`:
  - `active/s` - The number of times TCP connections have made a direct transition to the SYN-SENT state from the CLOSED state per second [tcpActiveOpens].
  - `passive/s` - The number of times TCP connections have made a direct transition to the SYN-RCVD state from the LISTEN state per second [tcpPassiveOpens].
  - `iseg/s` - The total number of segments received per second, including those received in error [tcpInSegs]. This count includes segments received on currently established connections.
  - `oseg/s` - The total number of segments sent per second, including those on current connections but excluding those containing only retransmitted octets [tcpOutSegs].

- `sar -n ETCP`:
  - `atmptf/s` - The number of times per second TCP connections have made a direct transition to the CLOSED state from either the SYN-SENT state or the SYN-RCVD state, plus the number of times per second TCP connections have made a direct transition to the LISTEN state from the SYN-RCVD state [tcpAttemptFails].
  - `estres/s` - The number of times per second TCP connections have made a direct transition to the CLOSED state from either the ESTABLISHED state or the CLOSE-WAIT state [tcpEstabResets].
  - `retrans/s` - The total number of segments retransmitted per second - that is, the number of TCP segments transmitted containing one or more previously transmitted octets [tcpRetransSegs].
  - `isegerr/s` - The total number of segments received in error (e.g., bad TCP checksums) per second [tcpInErrs].
  - `orsts/s` - The number of TCP segments sent per second containing the RST flag [tcpOutRsts].

- `sar -n UDP`:
  - `idgm/s` - The total number of UDP datagrams delivered per second to UDP users [udpInDatagrams].
  - `odgm/s` - The total number of UDP datagrams sent per second from this entity [udpOutDatagrams].
  - `noport/s` - The total number of received UDP datagrams per second for which there was no application at the destination port [udpNoPorts].
  - `idgmerr/s` - The number of received UDP datagrams per second that could not be delivered for reasons other than the lack of an application at the destination port [udpInErrors].

- `sar -n UDP6`:
  - `idgm6/s` - The total number of UDP datagrams delivered per second to UDP users [udpInDatagrams].
  - `odgm6/s` - The total number of UDP datagrams sent per second from this entity [udpOutDatagrams].
  - `noport6/s` - The total number of received UDP datagrams per second for which there was no application at the destination port [udpNoPorts].
  - `idgmer6/s` - The number of received UDP datagrams per second that could not be delivered for reasons other than the lack of an application at the destination port [udpInErrors].

- `sar -q`:
  - `runq-sz` - Run queue length (number of tasks waiting for run time).
  - `plist-sz` - Number of tasks in the task list.
  - `ldavg-1` - System load average for the last minute. The load average is calculated as the average number of runnable or running tasks (R state), and the number of tasks in uninterruptible sleep (D state) over the specified interval.
  - `ldavg-5` - System load average for the past 5 minutes.
  - `ldavg-15` - System load average for the past 15 minutes.
  - `blocked` - Number of tasks currently blocked, waiting for I/O to complete.

- `sar -r`:
  - `kbmemfree` - Amount of free memory available in kilobytes.
  - `kbavail` - Estimate of how much memory in kilobytes is available for starting new applications, without swapping. The estimate takes into account that the system needs some page cache to function well, and that not all reclaimable memory slabs will be reclaimable, due to items being in use. The impact of those factors will vary from system to system.
  - `kbmemused` - Amount of used memory in kilobytes (calculated as total installed memory - kbmemfree - kbbuffers - kbcached - kbslab).
  - `%memused` - Percentage of used memory.
  - `kbbuffers` - Amount of memory used as buffers by the kernel in kilobytes.
  - `kbcached` - Amount of memory used to cache data by the kernel in kilobytes.
  - `kbcommit` - Amount of memory in kilobytes needed for current workload. This is an estimate of how much RAM/swap is needed to guarantee that there never is out of memory.
  - `%commit` - Percentage of memory needed for current workload in relation to the total amount of memory (RAM+swap). This number may be greater than 100% because the kernel usually overcommits memory.
  - `kbactive` - Amount of active memory in kilobytes (memory that has been used more recently and usually not reclaimed unless absolutely necessary).
  - `kbinact` - Amount of inactive memory in kilobytes (memory which has been less recently used. It is more eligible to be reclaimed for other purposes).
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
  - `kbswpcad` - Amount of cached swap memory in kilobytes. This is memory that once was swapped out, is swapped back in but still also is in the swap area (if memory is needed it doesn't need to be swapped out again because it is already in the swap area. This saves I/O).
  - `%swpcad` - Percentage of cached swap memory in relation to the amount of used swap space.

- `sar -u`:
  - `%user` - Percentage of CPU utilization that occurred while executing at the user level (application). Note that this field includes time spent running virtual processors.
  - `%usr` - Percentage of CPU utilization that occurred while executing at the user level (application). Note that this field does NOT include time spent running virtual processors.
  - `%nice` - Percentage of CPU utilization that occurred while executing at the user level with nice priority.
  - `%system` - Percentage of CPU utilization that occurred while executing at the system level (kernel). Note that this field includes time spent servicing hardware and software interrupts.
  - `%sys` - Percentage of CPU utilization that occurred while executing at the system level (kernel). Note that this field does NOT include time spent servicing hardware or software interrupts.
  - `%iowait` - Percentage of time that the CPU or CPUs were idle during which the system had an outstanding disk I/O request.
  - `%steal` - Percentage of time spent in involuntary wait by the virtual CPU or CPUs while the hypervisor was servicing another virtual processor.
  - `%irq` - Percentage of time spent by the CPU or CPUs to service hardware interrupts.
  - `%soft` - Percentage of time spent by the CPU or CPUs to service software interrupts.
  - `%guest` - Percentage of time spent by the CPU or CPUs to run a virtual processor.
  - `%gnice` - Percentage of time spent by the CPU or CPUs to run a niced guest.
  - `%idle` - Percentage of time that the CPU or CPUs were idle and the system did not have an outstanding disk I/O request.

- `sar -v`:
  - `dentunusd` - Number of unused cache entries in the directory cache.
  - `file-nr` - Number of file handles used by the system.
  - `inode-nr` - Number of inode handlers used by the system.
  - `pty-nr` - Number of pseudo-terminals used by the system.

- `sar -W`: Report swapping statistics. The following values are displayed:
  - `pswpin/s` - Total number of swap pages the system brought in per second.
  - `pswpout/s` - Total number of swap pages the system brought out per second.

- `sar -w`: Report task creation and system switching activity.
  - `proc/s` - Total number of tasks created per second.
  - `cswch/s` - Total number of context switches per second.

- `sar -y`: Report TTY devices activity. The following values are displayed:
  - `rcvin/s` - Number of receive interrupts per second for current serial line. Serial line number is given in the TTY column.
  - `xmtin/s` - Number of transmit interrupts per second for current serial line.
  - `framerr/s` - Number of frame errors per second for current serial line.
  - `prtyerr/s` - Number of parity errors per second for current serial line.
  - `brk/s` - Number of breaks per second for current serial line.
  - `ovrun/s` - Number of overrun errors per second for current serial line.

## 37. tcpdump

- `-B buffer_size`: Set the operating system capture buffer size to buffer_size, in units of KiB (1024 bytes).
- `-i interface`: listen on a specific interface
- `-I`: turn on monitor mode. before doing this:
  ```
  sudo ifconfig wlan0 down
  sudo iwconfig wlan0 mode Monitor
  sudo ifconfig wlan0 up
  ```
- `--no-promiscuous-mode`
- `-Q direction in|out|inout`
- `--absolute-tcp-sequence-numbers`
- `-w`: write raw packets to file
- expression

Examples:
- To print all packets arriving at or departing from sundown:
  ```
  tcpdump host sundown
  ```

- To print traffic between helios and either hot or ace:
  ```
  tcpdump host helios and \( hot or ace \)
  ```

- To print all IP packets between ace and any host except helios:
  ```
  tcpdump ip host ace and not helios
  ```

- To print all ftp traffic through internet gateway snup: (note that the expression is quoted to prevent the shell from (mis-)interpreting the parentheses):
  ```
  tcpdump 'gateway snup and (port ftp or ftp-data)'
  ```

- To print traffic neither sourced from nor destined for local hosts (if you gateway to one other net, this stuff should never make it onto your local net).
  ```
  tcpdump ip and not net localnet
  ```

- To print the start and end packets (the SYN and FIN packets) of each TCP conversation that involves a non-local host.
  ```
  tcpdump 'tcp[tcpflags] & (tcp-syn|tcp-fin) != 0 and not src and dst net localnet'
  ```

- To print all IPv4 HTTP packets to and from port 80, i.e. print only packets that contain data, not, for example, SYN and FIN packets and ACK-only packets. (IPv6 is left as an exercise for the reader.)
  ```
  tcpdump 'tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)'
  ```

- To print IP packets longer than 576 bytes sent through gateway snup:
  ```
  tcpdump 'gateway snup and ip[2:2] > 576'
  ```

- To print IP broadcast or multicast packets that were not sent via Ethernet broadcast or multicast:
  ```
  tcpdump 'ether[0] & 1 = 0 and ip[16] >= 224'
  ```

- To print all ICMP packets that are not echo requests/replies (i.e., not ping packets):
  ```
  tcpdump 'icmp[icmptype] != icmp-echo and icmp[icmptype] != icmp-echoreply'
  ```

## 38. nicstat

- nicstat prints out network statistics for all network cards (NICs), including packets, kilobytes per second, average packet sizes and more.
- `nicstat -t`: show CP stats
- `nicstat`: show n/w interface stats

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
  - `%Util` - Percentage utilization of the interface. For full-duplex interfaces, this is the greater of rKB/s or wKB/s as a percentage of the interface speed. For half-duplex interfaces, rKB/s and wKB/s are summed.
  - `%rUtil, %wUtil` - Percentage utilization for bytes read and written, respectively.
  - `Sat` - Saturation. This the number of errors/second seen for the interface - an indicator the interface may be approaching saturation. This statistic is combined from a number of kernel statistics. It is recommended to use the '-x' option to see more individual statistics (those mentioned below) when attempting to diagnose a network issue.
  - `IErr` - Packets received that could not be processed because they contained errors
  - `OErr` - Packets that were not successfully transmitted because of errors
  - `Coll` - Ethernet collisions during transmit.
  - `NoCP` - No-can-puts. This is when an incoming packet can not be put to the process reading the socket. This suggests the local process is unable to process incoming packets in a timely manner.
  - `Defer` - Defer Transmits. Packets without collisions where first transmit attempt was delayed because the medium was busy.
  - `Reset` - tcpEstabResets. The number of times TCP connections have made a direct transition to the CLOSED state from either the ESTABLISHED state or the CLOSE-WAIT state.
  - `AttF` - tcpAttemptFails - The number of times that TCP connections have made a direct transition to the CLOSED state from either the SYN-SENT state or the SYN-RCVD state, plus the number of times TCP connections have made a direct transition to the LISTEN state from the SYN-RCVD state.
  - `%ReTX` - Percentage of TCP segments retransmitted - that is, the number of TCP segments transmitted containing one or more previously transmitted octets.
  - `InConn` - tcpPassiveOpens - The number of times that TCP connections have made a direct transition to the SYN-RCVD state from the LISTEN state.
  - `OutCon` - tcpActiveOpens - The number of times that TCP connections have made a direct transition to the SYN-SENT state from the CLOSED state.
  - `Drops` - tcpHalfOpenDrop + tcpListenDrop + tcpListenDropQ0. tcpListenDrop and tcpListenDropQ0 - Number of connections dropped from the completed connection queue and incomplete connection queue, respectively. tcpHalfOpenDrops - Number of connections dropped after the initial SYN packet was received.

## 39. pidstat

- monitor individual tasks currently being managed

- `pidstat -d`:
  - `UID` - The real user identification number of the task being monitored.
  - `USER` - The name of the real user owning the task being monitored.
  - `PID` - The identification number of the task being monitored.
  - `kB_rd/s` - Number of kilobytes the task has caused to be read from disk per second.
  - `kB_wr/s` - Number of kilobytes the task has caused, or shall cause to be written to disk per second.
  - `kB_ccwr/s` - Number of kilobytes whose writing to disk has been cancelled by the task. This may occur when the task truncates some dirty page-cache. In this case, some IO which another task has been accounted for will not be happening.
  - `iodelay` - Block I/O delay of the task being monitored, measured in clock ticks. This metric includes the delays spent waiting for sync block I/O completion and for swapin block I/O completion.

- `pidstat -R`: Report realtime priority and scheduling policy information. The following values may be displayed:
  - `UID` - The real user identification number of the task being monitored.
  - `USER` - The name of the real user owning the task being monitored.
  - `PID` - The identification number of the task being monitored.
  - `prio` - The realtime priority of the task being monitored.
  - `policy` - The scheduling policy of the task being monitored.
  - `Command` - The command name of the task.

- `pidstat -r`: Report page faults and memory utilization.

  When reporting statistics for individual tasks, the following values may be displayed:
  - `UID` - The real user identification number of the task being monitored.
  - `USER` - The name of the real user owning the task being monitored.
  - `PID` - The identification number of the task being monitored.
  - `minflt/s` - Total number of minor faults the task has made per second, those which have not required loading a memory page from disk.
  - `majflt/s` - Total number of major faults the task has made per second, those which have required loading a memory page from disk.
  - `VSZ` - Virtual Size: The virtual memory usage of entire task in kilobytes.
  - `RSS` - Resident Set Size: The non-swapped physical memory used by the task in kilobytes.
  - `%MEM` - The tasks's currently used share of available physical memory.
  - `Command` - The command name of the task.

  When reporting global statistics for tasks and all their children, the following values may be displayed:
  - `UID` - The real user identification number of the task which is being monitored together with its children.
  - `USER` - The name of the real user owning the task which is being monitored together with its children.
  - `PID` - The identification number of the task which is being monitored together with its children.
  - `minflt-nr` - Total number of minor faults made by the task and all its children, and collected during the interval of time.
  - `majflt-nr` - Total number of major faults made by the task and all its children, and collected during the interval of time.
  - `Command` - The command name of the task which is being monitored together with its children.

- `pidstat -s`: Report stack utilization. The following values may be displayed:
  - `UID` - The real user identification number of the task being monitored.
  - `USER` - The name of the real user owning the task being monitored.
  - `PID` - The identification number of the task being monitored.
  - `StkSize` - The amount of memory in kilobytes reserved for the task as stack, but not necessarily used.
  - `StkRef` - The amount of memory in kilobytes used as stack, referenced by the task.
  - `Command` - The command name of the task.

- `pidstat -t`: Also display statistics for threads associated with selected tasks. List process and threads

- `pidstat -u`: Report CPU utilization.

  When reporting statistics for individual tasks, the following values may be displayed:
  - `UID` - The real user identification number of the task being monitored.
  - `USER` - The name of the real user owning the task being monitored.
  - `PID` - The identification number of the task being monitored.
  - `%usr` - Percentage of CPU used by the task while executing at the user level (application), with or without nice priority. Note that this field does NOT include time spent running a virtual processor.
  - `%system` - Percentage of CPU used by the task while executing at the system level (kernel).
  - `%guest` - Percentage of CPU spent by the task in virtual machine (running a virtual processor).
  - `%wait` - Percentage of CPU spent by the task while waiting to run.
  - `%CPU` - Total percentage of CPU time used by the task. In an SMP environment, the task's CPU usage will be divided by the total number of CPU's if option -I has been entered on the command line.
  - `CPU` - Processor number to which the task is attached.

  When reporting global statistics for tasks and all their children, the following values may be displayed:
  - `UID` - The real user identification number of the task which is being monitored together with its children.
  - `USER` - The name of the real user owning the task which is being monitored together with its children.
  - `PID` - The identification number of the task which is being monitored together with its children.
  - `usr-ms` - Total number of milliseconds spent by the task and all its children while executing at the user level (application), with or without nice priority, and collected during the interval of time. Note that this field does NOT include time spent running a virtual processor.
  - `system-ms` - Total number of milliseconds spent by the task and all its children while executing at the system level (kernel), and collected during the interval of time.
  - `guest-ms` - Total number of milliseconds spent by the task and all its children in virtual machine (running a virtual processor).

## 40. swapon

- swapon, swapoff - enable/disable devices and files for paging and swapping

## 41. lsof

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
kill -9 $(lsof -t -i) # Kill all programs w/network activity
```

## 42. pgrep/pkill

## 43. tiptop

- The tiptop program provides a dynamic real-time view of the tasks running in the system. tiptop is very similar to top (1), but the information displayed comes from hardware counters.
- `tiptop -H`: show threads

  - CPU_CYCLES
  - INSTRUCTIONS
  - CACHE_MISSES
  - BRANCH_MISSES
  - %CPU
  - CPU_TOT
  - PROC_ID
  - Cycles (millions)
  - Instructions (millions)
  - Executed instructions per cycle
  - Cache miss per instruction
  - Branch misprediction per 100 instructions

## 44. sensors

- sensors is used to show the current readings of all sensor chips.
- `sensors`: shows current, high and critical temps.

## 45. traceroute

- `traceroute -I`: use ICMP echo for probes
- `traceroute -T`: use TCP SYN for probes

## 46. df

- This manual page documents the GNU version of df. df displays the amount of disk space available on the file system containing each file name argument. If no file name is given, the space available on all currently mounted file systems is shown. Disk space is shown in 1K blocks by default, unless the environment variable POSIXLY_CORRECT is set, in which case 512-byte blocks are used.

- `df`: show use/available FS space
- `df -i`: show used/unused inodes
- `df --sync`: sync with disk before showing data

## 47. pmap

- `pmap 29740 -X`: show Address,Perm,Offset,Device,Inode,Size,Rss,Pss,Referenced,Anonymous,LazyFree,ShmemPmdMapped,Shared_Hugetlb,Private_Hugetlb,Swap,SwapPss,Locked,THPeligible,Mapping

## 48. blktrace

- blktrace is a block layer IO tracing mechanism which provides detailed information about request queue operations up to user space. There are three major components: a kernel component, a utility to record the i/o trace information for the kernel to user space, and utilities to analyse and view the trace information.

- `sudo blktrace -d /dev/sda -o - | blkparse -i -`

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

## 49. btrace

- The btrace script provides a quick and easy way to do live tracing of block devices. It calls blktrace on the specified devices and pipes the output through blkparse for formatting. See blktrace (8) for more in-depth information about how blktrace works.

- `btrace /dev/sda`

## 50. iwconfig

- `iwconfig wlo1`: show WLAN config:

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

## 51. arp

## 52. nslookup

query Internet name servers interactively

- `nslookup <domain>`

## 53. host

host is a simple utility for performing DNS lookups. It is normally used to convert names to IP addresses and vice versa.

- `host <domain>`

## 54. tr

Translate, squeeze, and/or delete characters from standard input, writing to standard output.

- `tr '\n' ','`: convert new lines to commas

## 55. cut

## 56. xargs

- tcptrace takes a tcpdump file specified on the command line (or from standard input) and produces a summarization of the connections.

## 57. getconf

- getconf - Query system configuration variables

## 58. brctl

- brctl is used to set up, maintain, and inspect the ethernet bridge configuration in the linux kernel.

## 59. badblocks

- badblocks is used to search for bad blocks on a device (usually a disk partition). device is the special file corresponding to the device (e.g /dev/hdc1).

## 60. e2fsck

- check a Linux ext2/ext3/ext4 file system

## 61. arpspoof

- arpspoof redirects packets from a target host (or all hosts) on the LAN intended for another host on the LAN by forging ARP replies. This is an extremely effective way of sniffing traffic on a switch.

## 62. rev

- `rev <file>`: reverses characters in file line by line

## 63. sendmail

## 64. ar

- The GNU ar program creates, modifies, and extracts from archives. An archive is a single file holding a collection of other files in a structure that makes it possible to retrieve the original individual files (called members of the archive).

## 65. readelf

- This program performs a similar function to objdump but it goes into more detail and it exists independently of the BFD library, so if there is a bug in BFD then readelf will not be affected.

## 66. objdump

- disassemble executable

## 67. nm

- GNU nm lists the symbols from object files objfile.... If no object files are listed as arguments, nm assumes the file a.out.

## 68. who

- show who is logged in

## 69. crontab

- cron syntax: (min) (hour) (day/month) (month) (day/week)
  - https://crontab.guru/

## 70. telnet

## 71. last

- last, lastb - show a listing of last logged in users

## 72. pidof

- find PID of process

## 73. mktemp

- Create a temporary file or directory, safely, and print its name.

## 74. ionice

- set or get process I/O scheduling class and priority

As of this writing, a process can be in one of three scheduling classes:

- **Idle** - A program running with idle I/O priority will only get disk time when no other program has asked for disk I/O for a defined grace period. The impact of an idle I/O process on normal system activity should be zero. This scheduling class does not take a priority argument. Presently, this scheduling class is permitted for an ordinary user (since kernel 2.6.25).

- **Best-effort** - This is the effective scheduling class for any process that has not asked for a specific I/O priority. This class takes a priority argument from 0-7, with a lower number being higher priority. Programs running at the same best-effort priority are served in a round-robin fashion.

  Note that before kernel 2.6.26 a process that has not asked for an I/O priority formally uses "none" as scheduling class, but the I/O scheduler will treat such processes as if it were in the best-effort class. The priority within the best-effort class will be dynamically derived from the CPU nice level of the process: io_priority = (cpu_nice + 20) / 5.

  For kernels after 2.6.26 with the CFQ I/O scheduler, a process that has not asked for an I/O priority inherits its CPU scheduling class. The I/O priority is derived from the CPU nice level of the process (same as before kernel 2.6.26).

- **Realtime** - The RT scheduling class is given first access to the disk, regardless of what else is going on in the system. Thus the RT class needs to be used with some care, as it can starve other processes. As with the best-effort class, 8 priority levels are defined denoting how big a time slice a given process will receive on each scheduling window. This scheduling class is not permitted for an ordinary (i.e., non-root) user.

Examples:
- `ionice -c 3 -p 89`: Sets process with PID 89 as an idle I/O process.
- `ionice -c 2 -n 0 bash`: Runs 'bash' as a best-effort program with highest priority.
- `ionice -p 89 91`: Prints the class and priority of the processes with PID 89 and 91.

## 75. /proc/locks

## 76. nice

- set a nice value for program

## 77. renice

- modify priority of running process

## 78. hdparm

- `hdparm -I /dev/sda`: display settings from drive
- `hdparm -Tt /dev/sda`: read benchmark
- `dd if=/dev/zero of=/tmp/output conv=fdatasync bs=4M count=100; rm -f /tmp/output`: write benchmark

## 79. perf
