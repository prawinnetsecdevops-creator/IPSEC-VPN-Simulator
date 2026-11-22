import { Check, CornerDownLeft, Play, RotateCcw, Terminal, Trash2, X } from 'lucide-react';
import { useEffect, useRef, useState, type KeyboardEvent } from 'react';
import { intToIp, parseCidr } from '../lib/net';
import type { SimResult, Trace } from '../lib/simulate';
import type { Site, SiteKey } from '../lib/types';
import { cn } from '../utils/cn';
import { EmptyState, PrimaryButton, Segmented, SiteBadge } from './ui';

interface TerminalLine {
  text: string;
  tone?: 'ok' | 'bad' | 'dim' | 'warn' | 'info';
}

interface CommandEntry {
  id: string;
  prompt: string;
  command: string;
  lines: TerminalLine[];
}

function getDefaultPingLines(t: Trace): TerminalLine[] {
  const lines: TerminalLine[] = [
    { text: `PING ${t.dst} (${t.dst}) 56(84) bytes of data.`, tone: 'dim' },
  ];
  if (t.success) {
    const ms = [24.1, 22.8, 23.4, 22.9, 23.1];
    ms.forEach((m, i) =>
      lines.push({ text: `64 bytes from ${t.dst}: icmp_seq=${i + 1} ttl=62 time=${m} ms` })
    );
    lines.push(
      { text: '' },
      { text: `--- ${t.dst} ping statistics ---`, tone: 'dim' },
      { text: '5 packets transmitted, 5 received, 0% packet loss, time 4006ms', tone: 'ok' },
      { text: 'rtt min/avg/max/mdev = 22.8/23.3/24.1/0.5 ms', tone: 'dim' }
    );
  } else {
    // If failCode indicates overlap or drop at gateway
    if (t.failCode === 'OVERLAP') {
      lines.push(
        { text: `From ${t.src} icmp_seq=1 Destination Host Unreachable`, tone: 'bad' },
        { text: `From ${t.src} icmp_seq=2 Destination Host Unreachable`, tone: 'bad' },
        { text: `From ${t.src} icmp_seq=3 Destination Host Unreachable`, tone: 'bad' },
        { text: `From ${t.src} icmp_seq=4 Destination Host Unreachable`, tone: 'bad' },
        { text: `From ${t.src} icmp_seq=5 Destination Host Unreachable`, tone: 'bad' },
        { text: '' },
        { text: `--- ${t.dst} ping statistics ---`, tone: 'dim' },
        { text: '5 packets transmitted, 0 received, +5 errors, 100% packet loss, time 4087ms', tone: 'bad' }
      );
    } else {
      lines.push(
        { text: '' },
        { text: `--- ${t.dst} ping statistics ---`, tone: 'dim' },
        { text: '5 packets transmitted, 0 received, 100% packet loss, time 4087ms', tone: 'bad' }
      );
    }
  }
  return lines;
}

function reading(t: Trace, src: Site, dst: Site): string {
  const s = t.counters[src.key];
  const d = t.counters[dst.key];
  if (t.success) return 'Encapsulation and decapsulation counters rise together on both gateways. That is what a healthy tunnel looks like.';
  if (s.encaps === 0) return `${src.name} never encrypts anything. The fault sits before its crypto engine: the SA itself, security policy, routing or NAT on ${src.name}.`;
  if (d.decaps === 0) return `${src.name} encrypts, ${dst.name} never decrypts. The packets are lost between the gateways, so look at ESP filtering and NAT traversal.`;
  if (d.encaps === 0) return `${dst.name} decrypts the requests but never encrypts a reply. The fault is on the return path of ${dst.name}: security policy, routing or NAT.`;
  return `Replies leave ${dst.name} encrypted but never arrive at ${src.name}.`;
}

function runInteractiveCommand(
  rawCmd: string,
  t: Trace,
  src: Site,
  dst: Site,
): TerminalLine[] {
  const trimmed = rawCmd.trim();
  if (!trimmed) return [];

  const parts = trimmed.split(/\s+/);
  const bin = parts[0].toLowerCase();
  const args = parts.slice(1);

  const c = parseCidr(src.lan);
  const localGw = c ? intToIp(c.net + 1) : '10.10.0.1';
  const localMask = c ? c.mask : '255.255.255.0';
  const localCidrBits = c ? c.bits : 24;

  switch (bin) {
    case 'ping': {
      // parse options e.g. ping -c 5 <ip>
      let count = 5;
      let target = t.dst;
      for (let i = 0; i < args.length; i++) {
        if (args[i] === '-c' && args[i + 1]) {
          count = Math.min(10, Math.max(1, parseInt(args[i + 1], 10) || 5));
          i++;
        } else if (!args[i].startsWith('-')) {
          target = args[i];
        }
      }

      if (!target) {
        return [{ text: 'ping: usage error: Destination address required', tone: 'bad' }];
      }

      // 1) Ping local loopback or local host IP
      if (target === '127.0.0.1' || target === 'localhost' || target === t.src) {
        const res: TerminalLine[] = [
          { text: `PING ${target} (${target}) 56(84) bytes of data.`, tone: 'dim' },
        ];
        for (let seq = 1; seq <= count; seq++) {
          res.push({ text: `64 bytes from ${target}: icmp_seq=${seq} ttl=64 time=0.04 ms` });
        }
        res.push(
          { text: '' },
          { text: `--- ${target} ping statistics ---`, tone: 'dim' },
          { text: `${count} packets transmitted, ${count} received, 0% packet loss, time ${count * 100}ms`, tone: 'ok' },
          { text: 'rtt min/avg/max/mdev = 0.038/0.042/0.051/0.005 ms', tone: 'dim' }
        );
        return res;
      }

      // 2) Ping local default gateway
      if (target === localGw) {
        const res: TerminalLine[] = [
          { text: `PING ${target} (${target}) 56(84) bytes of data.`, tone: 'dim' },
        ];
        for (let seq = 1; seq <= count; seq++) {
          res.push({ text: `64 bytes from ${target}: icmp_seq=${seq} ttl=64 time=0.4 ms` });
        }
        res.push(
          { text: '' },
          { text: `--- ${target} ping statistics ---`, tone: 'dim' },
          { text: `${count} packets transmitted, ${count} received, 0% packet loss, time ${count * 1000}ms`, tone: 'ok' },
          { text: 'rtt min/avg/max/mdev = 0.38/0.42/0.49/0.04 ms', tone: 'dim' }
        );
        return res;
      }

      // 3) Ping remote protected LAN target or default dst
      const res: TerminalLine[] = [
        { text: `PING ${target} (${target}) 56(84) bytes of data.`, tone: 'dim' },
      ];

      if (t.success) {
        const baseTimes = [24.1, 22.8, 23.4, 22.9, 23.1, 24.5, 23.2, 22.7, 23.8, 23.0];
        for (let seq = 1; seq <= count; seq++) {
          const ms = baseTimes[(seq - 1) % baseTimes.length];
          res.push({ text: `64 bytes from ${target}: icmp_seq=${seq} ttl=62 time=${ms} ms` });
        }
        res.push(
          { text: '' },
          { text: `--- ${target} ping statistics ---`, tone: 'dim' },
          { text: `${count} packets transmitted, ${count} received, 0% packet loss, time ${count * 1002}ms`, tone: 'ok' },
          { text: 'rtt min/avg/max/mdev = 22.7/23.3/24.5/0.6 ms', tone: 'dim' }
        );
      } else {
        if (t.failCode === 'OVERLAP') {
          for (let seq = 1; seq <= count; seq++) {
            res.push({ text: `From ${t.src} icmp_seq=${seq} Destination Host Unreachable`, tone: 'bad' });
          }
          res.push(
            { text: '' },
            { text: `--- ${target} ping statistics ---`, tone: 'dim' },
            { text: `${count} packets transmitted, 0 received, +${count} errors, 100% packet loss, time ${count * 1010}ms`, tone: 'bad' }
          );
        } else {
          for (let seq = 1; seq <= Math.min(3, count); seq++) {
            res.push({ text: `Request timeout for icmp_seq ${seq}`, tone: 'bad' });
          }
          res.push(
            { text: '' },
            { text: `--- ${target} ping statistics ---`, tone: 'dim' },
            { text: `${count} packets transmitted, 0 received, 100% packet loss, time ${count * 1010}ms`, tone: 'bad' }
          );
        }
      }
      return res;
    }

    case 'traceroute':
    case 'tracepath': {
      const target = args[0] || t.dst;
      const res: TerminalLine[] = [
        { text: `traceroute to ${target} (${target}), 30 hops max, 60 byte packets`, tone: 'dim' },
        { text: ` 1  ${localGw} (${localGw})  0.412 ms  0.388 ms  0.395 ms` },
      ];

      if (t.success) {
        res.push(
          { text: ` 2  * * * (IPsec ESP tunnel mode 0x${t.from === 'A' ? 'tunnel' : 'vpn'}${t.srcPostNat ? ` · SNAT: ${t.srcPostNat}` : ''})` },
          { text: ` 3  ${target}${t.dstPostNat && target === t.dst ? ` [DNAT: ${t.dstPostNat}]` : ''} (${target})  23.142 ms  22.890 ms  23.011 ms`, tone: 'ok' }
        );
      } else {
        if (t.failCode?.startsWith('ROUTE') || t.failCode?.startsWith('POLICY')) {
          res.push(
            { text: ` 2  ${localGw} (${localGw})  !H (Host Unreachable)`, tone: 'bad' },
            { text: ' 3  * * *' }
          );
        } else {
          res.push(
            { text: ' 2  * * *' },
            { text: ' 3  * * *' },
            { text: ' 4  * * *' }
          );
        }
      }
      return res;
    }

    case 'ip': {
      const sub = args[0]?.toLowerCase();
      if (sub === 'route' || sub === 'r') {
        return [
          { text: `default via ${localGw} dev eth0 proto dhcp src ${t.src} metric 100` },
          { text: `${src.lan} dev eth0 proto kernel scope link src ${t.src} metric 100` },
        ];
      }
      if (sub === 'addr' || sub === 'a') {
        return [
          { text: '1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000' },
          { text: '    inet 127.0.0.1/8 scope host lo' },
          { text: `2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000` },
          { text: `    inet ${t.src}/${localCidrBits} brd ${localGw.replace(/\.\d+$/, '.255')} scope global dynamic eth0` },
        ];
      }
      if (sub === 'neigh' || sub === 'n') {
        if (t.failCode === 'OVERLAP') {
          return [
            { text: `${localGw} dev eth0 lladdr 52:54:00:1a:2b:3c REACHABLE` },
            { text: `${t.dst} dev eth0  FAILED (incomplete - host ARPing on local link)`, tone: 'bad' },
          ];
        }
        return [
          { text: `${localGw} dev eth0 lladdr 52:54:00:1a:2b:3c REACHABLE` },
        ];
      }
      return [
        { text: 'Usage: ip [route | addr | neigh]', tone: 'dim' },
      ];
    }

    case 'route': {
      return [
        { text: 'Kernel IP routing table' },
        { text: 'Destination     Gateway         Genmask         Flags Metric Ref    Use Iface' },
        { text: `0.0.0.0         ${localGw.padEnd(16)}0.0.0.0         UG    100    0        0 eth0` },
        { text: `${src.lan.padEnd(16)}0.0.0.0         ${localMask.padEnd(16)}U     100    0        0 eth0` },
      ];
    }

    case 'ifconfig': {
      return [
        { text: `eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500` },
        { text: `        inet ${t.src}  netmask ${localMask}  broadcast ${localGw.replace(/\.\d+$/, '.255')}` },
        { text: `        ether 52:54:00:8c:9d:01  txqueuelen 1000  (Ethernet)` },
        { text: `        RX packets 1245  bytes 98124 (98.1 KB)` },
        { text: `        TX packets 890   bytes 72102 (72.1 KB)` },
      ];
    }

    case 'arp': {
      if (t.failCode === 'OVERLAP') {
        return [
          { text: 'Address                  HWtype  HWaddress           Flags Mask            Iface' },
          { text: `${localGw.padEnd(25)}ether   52:54:00:1a:2b:3c   C                     eth0` },
          { text: `${t.dst.padEnd(25)}(incomplete)                                   eth0`, tone: 'bad' },
        ];
      }
      return [
        { text: 'Address                  HWtype  HWaddress           Flags Mask            Iface' },
        { text: `${localGw.padEnd(25)}ether   52:54:00:1a:2b:3c   C                     eth0` },
      ];
    }

    case 'curl': {
      const target = args.find((a) => !a.startsWith('-'))?.replace(/^https?:\/\//, '').split('/')[0] || t.dst;
      if (t.success) {
        return [
          { text: `HTTP/1.1 200 OK`, tone: 'ok' },
          { text: `Server: nginx/1.24.0 (${dst.name} App Server)` },
          { text: `Date: ${new Date().toUTCString()}` },
          { text: `Content-Type: text/html; charset=UTF-8` },
          { text: `Content-Length: 312` },
          { text: `Connection: keep-alive` },
          { text: '' },
          { text: `<!DOCTYPE html><html><body><h1>Welcome to ${dst.name} Internal Portal</h1><p>Connected via Site-to-Site VPN</p></body></html>`, tone: 'info' },
        ];
      }
      return [
        { text: `curl: (28) Failed to connect to ${target} port 80: Connection timed out`, tone: 'bad' },
      ];
    }

    case 'nc':
    case 'netcat': {
      const host = args.find((a) => !a.startsWith('-') && !/^\d+$/.test(a)) || t.dst;
      const port = args.find((a) => /^\d+$/.test(a)) || '80';
      if (t.success) {
        return [
          { text: `Connection to ${host} ${port} port [tcp/http] succeeded!`, tone: 'ok' },
        ];
      }
      return [
        { text: `nc: connect to ${host} port ${port} (tcp) failed: Connection timed out`, tone: 'bad' },
      ];
    }

    case 'telnet': {
      let host = '';
      let port = '23';

      if (args.length === 0) {
        return [
          { text: 'Usage: telnet <host> [port]', tone: 'dim' },
          { text: `Example: telnet ${t.dst} 80`, tone: 'info' },
        ];
      }

      // Support "telnet host port" and "telnet host:port"
      if (args[0].includes(':')) {
        const [h, p] = args[0].split(':');
        host = h;
        if (p && /^\d+$/.test(p)) port = p;
      } else {
        host = args[0];
        if (args[1] && /^\d+$/.test(args[1])) {
          port = args[1];
        }
      }

      if (!host) {
        return [{ text: 'telnet: Host address required', tone: 'bad' }];
      }

      // Local loopback or self IP
      if (host === '127.0.0.1' || host === 'localhost' || host === t.src) {
        return [
          { text: `Trying ${host}...`, tone: 'dim' },
          { text: `Connected to ${host}.`, tone: 'ok' },
          { text: "Escape character is '^]'." },
          { text: 'Connection closed by foreign host.' },
        ];
      }

      // Remote host over IPsec VPN tunnel
      if (t.success) {
        const lines: TerminalLine[] = [
          { text: `Trying ${host}...`, tone: 'dim' },
          { text: `Connected to ${host} (port ${port}).`, tone: 'ok' },
          { text: "Escape character is '^]'." },
        ];

        if (port === '22') {
          lines.push({ text: `SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2 (${dst.name} Gateway/Server)` });
        } else if (port === '80' || port === '8080') {
          lines.push({ text: `HTTP/1.1 200 OK` });
          lines.push({ text: `Server: nginx/1.24.0 (${dst.name})` });
        } else if (port === '443' || port === '8443') {
          lines.push({ text: `Connected to TLS service on ${host}:${port}` });
        } else if (port === '23') {
          lines.push({ text: `${dst.name} Linux (Debian 12) login: ` });
        } else {
          lines.push({ text: `Connected to TCP port ${port} on ${dst.name} peer network.` });
        }

        return lines;
      }

      // Path failure handling
      if (t.failCode === 'OVERLAP') {
        return [
          { text: `Trying ${host}...`, tone: 'dim' },
          { text: 'telnet: Unable to connect to remote host: No route to host', tone: 'bad' },
        ];
      }

      if (t.failCode?.startsWith('ROUTE')) {
        return [
          { text: `Trying ${host}...`, tone: 'dim' },
          { text: 'telnet: Unable to connect to remote host: Network is unreachable', tone: 'bad' },
        ];
      }

      return [
        { text: `Trying ${host}...`, tone: 'dim' },
        { text: `telnet: Unable to connect to remote host: Connection timed out`, tone: 'bad' },
      ];
    }

    case 'uname': {
      return [{ text: 'Linux client-host 6.1.0-21-amd64 #1 SMP PREEMPT_DYNAMIC Debian x86_64 GNU/Linux' }];
    }

    case 'whoami': {
      return [{ text: 'user' }];
    }

    case 'hostname': {
      return [{ text: `client-${src.name.toLowerCase().replace(/[^a-z0-9]/g, '-')}` }];
    }

    case 'help': {
      return [
        { text: 'IPSEC VPN Simulator Host Diagnostics CLI - Available commands:', tone: 'info' },
        { text: '  ping [-c N] <ip>      Send ICMP echo requests to remote host or gateway' },
        { text: '  telnet <ip> [port]    Test TCP port connection (e.g. telnet <dst> 80)' },
        { text: '  traceroute <ip>       Trace packet route hops through the VPN tunnel' },
        { text: '  curl <ip>[:port]      Test TCP/HTTP connection to remote server' },
        { text: '  nc -zv <ip> <port>    Check TCP port connectivity' },
        { text: '  ip route              Display host routing table' },
        { text: '  ip addr               Show local IP addresses and netmask' },
        { text: '  arp -n                Show local ARP table / neighbor cache' },
        { text: '  clear                 Clear terminal output' },
        { text: '  reset                 Restore default ping output' },
      ];
    }

    default:
      return [
        { text: `bash: ${bin}: command not found. Type 'help' for available diagnostic commands.`, tone: 'bad' },
      ];
  }
}

export function TrafficTab({
  a, b, sim, status, onRun,
}: { a: Site; b: Site; sim: SimResult; status: 'idle' | 'running' | 'done'; onRun: () => void }) {
  const [from, setFrom] = useState<SiteKey>('A');

  if (status !== 'done')
    return (
      <EmptyState
        title={status === 'running' ? 'Negotiation in progress' : 'No tunnel to test yet'}
        text={status === 'running' ? 'The traffic test is available once the exchange finishes.' : 'Bring the tunnel up, then send pings between the two LANs and follow each packet hop by hop.'}
        action={
          status === 'idle' ? (
            <PrimaryButton onClick={onRun}>
              <Play className="h-4 w-4" aria-hidden /> Bring tunnel up
            </PrimaryButton>
          ) : undefined
        }
      />
    );

  const t = sim.traffic[from];
  const src = from === 'A' ? a : b;
  const dst = from === 'A' ? b : a;
  const site = (k?: SiteKey) => (k ? (k === 'A' ? a : b) : undefined);

  // Interactive CLI state
  const [inputVal, setInputVal] = useState('');
  const [commandHistory, setCommandHistory] = useState<string[]>([]);
  const [historyIndex, setHistoryIndex] = useState<number>(-1);
  const cliScrollRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  // Initialize terminal entries with default ping
  const [entries, setEntries] = useState<CommandEntry[]>(() => [
    {
      id: 'default-ping',
      prompt: `user@${t.src}:~$ `,
      command: `ping -c 5 ${t.dst}`,
      lines: getDefaultPingLines(t),
    },
  ]);

  // When direction switches, re-initialize terminal with the default ping for that direction
  useEffect(() => {
    setEntries([
      {
        id: `default-ping-${from}-${Date.now()}`,
        prompt: `user@${t.src}:~$ `,
        command: `ping -c 5 ${t.dst}`,
        lines: getDefaultPingLines(t),
      },
    ]);
    setInputVal('');
    setCommandHistory([]);
    setHistoryIndex(-1);
  }, [from, t]);

  // Auto-scroll terminal on change
  useEffect(() => {
    if (cliScrollRef.current) {
      cliScrollRef.current.scrollTop = cliScrollRef.current.scrollHeight;
    }
  }, [entries]);

  const executeCommand = (cmdText: string) => {
    const trimmed = cmdText.trim();
    if (!trimmed) return;

    if (trimmed.toLowerCase() === 'clear') {
      setEntries([]);
      setInputVal('');
      return;
    }

    if (trimmed.toLowerCase() === 'reset') {
      setEntries([
        {
          id: `reset-ping-${Date.now()}`,
          prompt: `user@${t.src}:~$ `,
          command: `ping -c 5 ${t.dst}`,
          lines: getDefaultPingLines(t),
        },
      ]);
      setInputVal('');
      return;
    }

    const outputLines = runInteractiveCommand(trimmed, t, src, dst);
    const newEntry: CommandEntry = {
      id: `${Date.now()}-${Math.random()}`,
      prompt: `user@${t.src}:~$ `,
      command: trimmed,
      lines: outputLines,
    };

    setEntries((prev) => [...prev, newEntry]);
    setCommandHistory((prev) => [...prev, trimmed]);
    setHistoryIndex(-1);
    setInputVal('');
  };

  const handleKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      executeCommand(inputVal);
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      if (commandHistory.length === 0) return;
      const nextIndex = historyIndex === -1 ? commandHistory.length - 1 : Math.max(0, historyIndex - 1);
      setHistoryIndex(nextIndex);
      setInputVal(commandHistory[nextIndex]);
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      if (historyIndex === -1) return;
      const nextIndex = historyIndex + 1;
      if (nextIndex >= commandHistory.length) {
        setHistoryIndex(-1);
        setInputVal('');
      } else {
        setHistoryIndex(nextIndex);
        setInputVal(commandHistory[nextIndex]);
      }
    }
  };

  const quickCommands = [
    { label: `ping ${t.dst}`, cmd: `ping -c 5 ${t.dst}` },
    { label: `telnet ${t.dst} 80`, cmd: `telnet ${t.dst} 80` },
    { label: `traceroute ${t.dst}`, cmd: `traceroute ${t.dst}` },
    { label: `curl http://${t.dst}`, cmd: `curl http://${t.dst}` },
    { label: 'ip route', cmd: 'ip route' },
    { label: 'ip addr', cmd: 'ip addr' },
    { label: 'arp -n', cmd: 'arp -n' },
    { label: 'help', cmd: 'help' },
  ];

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center gap-3">
        <Segmented
          label="Ping direction"
          value={from}
          onChange={setFrom}
          className="w-full sm:w-auto sm:min-w-[340px]"
          options={[
            { value: 'A', label: `${a.name} → ${b.name}` },
            { value: 'B', label: `${b.name} → ${a.name}` },
          ]}
        />
        <span className="font-mono text-[12px] text-mute">
          {t.src} → {t.dst} · interactive host terminal
        </span>
      </div>

      <div className="grid gap-5 lg:grid-cols-[minmax(0,1.15fr)_minmax(0,1fr)]">
        <section aria-label="Packet path">
          <h3 className="mb-2 text-[12px] font-semibold uppercase tracking-[0.08em] text-mute">Packet path</h3>
          <ol className="relative space-y-0">
            {t.hops.map((h, i) => {
              const s = site(h.site);
              return (
                <li key={i} className="relative flex gap-3 pb-3 last:pb-0">
                  {i < t.hops.length - 1 && <span className="absolute left-[9px] top-5 h-full w-px bg-line" aria-hidden />}
                  <span className={cn('relative z-10 mt-0.5 grid h-[19px] w-[19px] shrink-0 place-items-center rounded-full', h.ok ? 'bg-ok/15 text-ok' : 'bg-bad text-ink')}>
                    {h.ok ? <Check className="h-3 w-3" strokeWidth={3} aria-hidden /> : <X className="h-3 w-3" strokeWidth={3} aria-hidden />}
                    <span className="sr-only">{h.ok ? 'passed' : 'dropped'}</span>
                  </span>
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-1.5">
                      {s ? <SiteBadge site={s.key} className="h-4 w-4 text-[10px]" /> : null}
                      <span className="text-[12px] text-mute">{s ? s.name : 'Internet'}</span>
                      <span className={cn('text-[13px] font-medium', h.ok ? 'text-fg' : 'text-bad')}>{h.where}</span>
                    </div>
                    <p className={cn('mt-0.5 max-w-[62ch] text-[12.5px] leading-snug', h.ok ? 'text-mute' : 'text-fg/90')}>{h.text}</p>
                  </div>
                </li>
              );
            })}
          </ol>
        </section>

        <div className="min-w-0 space-y-4">
          {/* Interactive Terminal CLI */}
          <section
            aria-label="Interactive Host CLI"
            className="flex flex-col overflow-hidden rounded-lg border border-line bg-term shadow-md"
            onClick={() => inputRef.current?.focus()}
          >
            {/* Terminal Header */}
            <div className="flex items-center justify-between border-b border-line px-3 py-2 font-mono text-[11px] text-mute">
              <div className="flex flex-wrap items-center gap-2">
                <span className="inline-block h-2 w-2 rounded-full bg-ok shadow-[0_0_6px_rgba(69,214,160,0.8)]" />
                <span className="font-semibold text-fg/90">host on {src.name} LAN</span>
                <span className="text-dim">({t.src})</span>
                {t.srcPostNat && (
                  <span className="rounded bg-ok/15 px-1.5 py-0.5 font-mono text-[10px] font-semibold text-ok">
                    SNAT: {t.srcPostNat}
                  </span>
                )}
                {t.dstPostNat && t.dstPostNat !== t.dst && (
                  <span className="rounded bg-ok/15 px-1.5 py-0.5 font-mono text-[10px] font-semibold text-ok">
                    DNAT: {t.dstPostNat}
                  </span>
                )}
              </div>
              <div className="flex items-center gap-1.5">
                <button
                  type="button"
                  onClick={(e) => {
                    e.stopPropagation();
                    executeCommand('reset');
                  }}
                  title="Reset to default ping"
                  className="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] text-mute transition-colors hover:bg-raised hover:text-fg"
                >
                  <RotateCcw className="h-3 w-3" />
                  <span>Reset</span>
                </button>
                <button
                  type="button"
                  onClick={(e) => {
                    e.stopPropagation();
                    executeCommand('clear');
                  }}
                  title="Clear terminal screen"
                  className="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] text-mute transition-colors hover:bg-raised hover:text-fg"
                >
                  <Trash2 className="h-3 w-3" />
                  <span>Clear</span>
                </button>
              </div>
            </div>

            {/* Terminal Output Body */}
            <div
              ref={cliScrollRef}
              className="thin-scroll max-h-[380px] min-h-[220px] overflow-y-auto px-3 py-2.5 font-mono text-[11.5px] leading-[1.55] [overflow-wrap:anywhere]"
            >
              {entries.map((entry) => (
                <div key={entry.id} className="mb-2">
                  <div className="flex items-baseline gap-1">
                    <span className="shrink-0 select-none font-semibold text-ok whitespace-pre">{entry.prompt}</span>
                    <span className="text-fg font-medium break-all">{entry.command}</span>
                  </div>
                  <div className="mt-0.5">
                    {entry.lines.map((l, i) => (
                      <div
                        key={i}
                        className={cn(
                          l.tone === 'ok'
                            ? 'text-ok font-medium'
                            : l.tone === 'bad'
                              ? 'text-bad font-medium'
                              : l.tone === 'warn'
                                ? 'text-warn'
                                : l.tone === 'info'
                                  ? 'text-a'
                                  : l.tone === 'dim'
                                    ? 'text-dim'
                                    : 'text-fg/85'
                        )}
                      >
                        {l.text || '\u00a0'}
                      </div>
                    ))}
                  </div>
                </div>
              ))}

              {/* Active Prompt Line with Interactive Input */}
              <div className="flex items-center pt-1">
                <span className="shrink-0 select-none font-semibold text-ok whitespace-pre">
                  user@{t.src}:~$&nbsp;
                </span>
                <input
                  ref={inputRef}
                  type="text"
                  value={inputVal}
                  onChange={(e) => setInputVal(e.target.value)}
                  onKeyDown={handleKeyDown}
                  placeholder="type command (e.g. ping, telnet, traceroute, curl, help)..."
                  className="min-w-0 flex-1 border-0 bg-transparent p-0 font-mono text-[11.5px] text-fg outline-none placeholder:text-dim/60 focus:ring-0"
                  autoCapitalize="none"
                  autoComplete="off"
                  spellCheck={false}
                />
                <button
                  type="button"
                  onClick={(e) => {
                    e.stopPropagation();
                    executeCommand(inputVal || `ping -c 5 ${t.dst}`);
                  }}
                  className="ml-1 text-dim hover:text-fg"
                  title="Run command (Enter)"
                >
                  <CornerDownLeft className="h-3.5 w-3.5" />
                </button>
              </div>
            </div>

            {/* Quick Command Suggestions Toolbar */}
            <div className="flex flex-wrap items-center gap-1.5 border-t border-line bg-well/40 px-2.5 py-1.5 font-mono text-[10.5px]">
              <span className="flex items-center gap-1 text-[10px] text-dim uppercase tracking-wider">
                <Terminal className="h-3 w-3" /> Quick:
              </span>
              {quickCommands.map((q) => (
                <button
                  key={q.cmd}
                  type="button"
                  onClick={(e) => {
                    e.stopPropagation();
                    executeCommand(q.cmd);
                  }}
                  className="rounded border border-line bg-raised/70 px-1.5 py-0.5 text-mute transition-colors hover:border-line-strong hover:bg-raised hover:text-fg active:translate-y-px"
                >
                  {q.label}
                </button>
              ))}
            </div>
          </section>

          <section aria-label="IPsec counters">
            <h3 className="mb-2 text-[12px] font-semibold uppercase tracking-[0.08em] text-mute">IPsec SA counters after the test</h3>
            <div className="overflow-hidden rounded-lg border border-line">
              <table className="w-full text-left font-mono text-[12.5px]">
                <thead>
                  <tr className="border-b border-line bg-raised/50 text-[11px] uppercase tracking-[0.06em] text-mute">
                    <th className="px-3 py-1.5 font-medium">Gateway</th>
                    <th className="px-3 py-1.5 text-right font-medium">Encaps</th>
                    <th className="px-3 py-1.5 text-right font-medium">Decaps</th>
                  </tr>
                </thead>
                <tbody>
                  {([src, dst] as Site[]).map((s) => (
                    <tr key={s.key} className="border-b border-line/60 last:border-0">
                      <td className="px-3 py-2">
                        <span className="flex items-center gap-1.5 font-sans text-[13px]">
                          <SiteBadge site={s.key} className="h-4 w-4 text-[10px]" /> {s.name}
                        </span>
                      </td>
                      <td className={cn('px-3 py-2 text-right tabular-nums', t.counters[s.key].encaps ? 'text-fg' : 'text-bad')}>{t.counters[s.key].encaps}</td>
                      <td className={cn('px-3 py-2 text-right tabular-nums', t.counters[s.key].decaps ? 'text-fg' : 'text-bad')}>{t.counters[s.key].decaps}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <p className="mt-2 text-[12.5px] leading-snug text-mute">{reading(t, src, dst)}</p>
          </section>
        </div>
      </div>
    </div>
  );
}
