#!/usr/bin/env bun
// ============================================================
//  COMBINED CHECKER  (Bun / Node, Windows + Linux)
//  probe : TCP 443 握手 (代替 ping, 本地/GitHub Actions 通用)
//  input : all-ip.txt  (IPv4/IPv6 混排, 一行一个, # 开头跳过)
//  stage1: TCP 443 探活, 失败重试 retry 次, 记录握手延迟
//  stage2: 探活通过则用 curl --resolve 指定解析 HOST 并 GET
//  output: ipv4.txt / ipv6.txt  (通过且HTTP 200, 非根随机版)
//          log.txt              (全部IP逐条记录)
//  环境变量: DO_PING=0 跳过探活直接 HTTP
//  运行  : bun check.js [列表文件]   (node 也可以)
// ============================================================

const { execFile } = require('child_process');
const net = require('net');
const fs = require('fs');

// ---------------- 配置区 ----------------
const config = {
  ipList: process.argv[2] || 'all-ip.txt',
  ipv4File: 'ipv4.txt',   // 非根随机版 IPv4
  ipv6File: 'ipv6.txt',   // 非根随机版 IPv6
  logFile: 'log.txt',
  host: 'www.acofork.com',
  url: 'https://www.acofork.com/',
  retry: 5,           // TCP 探活失败重试次数
  tcpPort: 443,
  tcpTimeout: 2000,   // 单次握手超时(毫秒)
  connectTimeout: 5,  // HTTP 连接超时(秒)
  maxTime: 15,        // HTTP 整体超时(秒)
  concurrency: 30,    // 并行度 (10=保守, 30=均衡, 50=激进)
  ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
  doProbe: 'DO_PING' in process.env ? Number(process.env.DO_PING) : 1, // 0 = 跳过探活直接 HTTP
};
// --------------------------------------

const isWin = process.platform === 'win32';
const devNull = isWin ? 'NUL' : '/dev/null';

function run(cmd, args, timeoutMs) {
  return new Promise((resolve) => {
    execFile(cmd, args, {
      timeout: timeoutMs,
      windowsHide: true,
      maxBuffer: 1024 * 1024,
    }, (err, stdout, stderr) => {
      resolve({
        ok: !err,
        code: err ? err.code : 0,
        stdout: stdout || '',
        stderr: stderr || '',
      });
    });
  });
}

function isV6(ip) { return ip.includes(':'); }

function randInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

// v4: 末段为 0(根IP) 时, 随机为 1-255
function randomizeV4(ip) {
  const p = String(ip).split('.');
  if (p.length !== 4) return ip;
  if (p[3] === '0') p[3] = String(randInt(1, 255));
  return p.join('.');
}

// v6: 以 "::" 结尾(根IP) 时, 随机补一个 1-65535 的末尾 hextet
function randomizeV6(ip) {
  const s = String(ip).trim();
  if (s.endsWith('::')) {
    return s.slice(0, -2) + '::' + randInt(1, 0xffff).toString(16);
  }
  const parts = s.split(':');
  if (parts[parts.length - 1] === '0') {
    parts[parts.length - 1] = randInt(1, 0xffff).toString(16);
    return parts.join(':');
  }
  return s;
}

// TCP 探活 + 延迟(三次握手耗时, 毫秒)
function tcpPing(ip, fam, timeoutMs) {
  return new Promise((resolve) => {
    const t0 = Date.now();
    let done = false;
    const sock = net.connect({ host: ip, port: config.tcpPort, family: fam === 6 ? 6 : 4 });
    const finish = (ok, lat) => {
      if (done) return;
      done = true;
      sock.destroy();
      resolve({ ok, lat });
    };
    sock.setTimeout(timeoutMs, () => finish(false, null));
    sock.on('connect', () => finish(true, Math.round(Date.now() - t0)));
    sock.on('error', () => finish(false, null));
  });
}

async function probeWithRetry(ip, fam) {
  if (!config.doProbe) return { ok: true, lat: 'skip' };
  for (let i = 0; i < 1 + config.retry; i++) {
    const r = await tcpPing(ip, fam, config.tcpTimeout);
    if (r.ok) return { ok: true, lat: r.lat };
  }
  return { ok: false, lat: null };
}

async function httpProbe(ip, fam) {
  const resolveArg = fam === 6
    ? `${config.host}:443:[${ip}]`
    : `${config.host}:443:${ip}`;
  const args = [
    '--noproxy', '*',
    '-k', '-s', '-L', '--max-redirs', '5', '--compressed',
    '-A', config.ua,
    '-o', devNull,
    '-w', '%{http_code}|%{remote_ip}|%{url_effective}',
    '--connect-timeout', String(config.connectTimeout),
    '--max-time', String(config.maxTime),
    '--resolve', resolveArg,
    config.url,
  ];
  const r = await run('curl', args, (config.maxTime + 10) * 1000);
  const out = String(r.stdout || '').trim() || '000||';
  const p = out.split('|');
  return { code: p[0] || '000', remote: p[1] || '', finalUrl: p[2] || '' };
}

// ---------------- 单个 IP 检测 ----------------
async function testIp(ip, idx, total) {
  const fam = isV6(ip) ? 6 : 4;
  const ver = fam === 6 ? 'v6' : 'v4';
  const pr = await probeWithRetry(ip, fam);

  if (!pr.ok) {
    console.log(`[${idx + 1}/${total}] [tcp FAIL] ${ip} ${ver}`);
    return { idx, ip, fam, res: 'pfail', line: `${ip}  ver=${ver}  tcp=FAIL  latency=-  http=skip` };
  }

  const skipped = pr.lat === 'skip';
  const latStr = pr.lat === null ? '-' : (skipped ? 'skip' : pr.lat + 'ms');
  const tcpStr = skipped ? 'skip' : 'OK';
  const h = await httpProbe(ip, fam);
  const line = `${ip}  ver=${ver}  tcp=${tcpStr}  latency=${latStr}  http=${h.code}  remote=${h.remote}  finalURL=${h.finalUrl}`;

  if (h.code === '200') {
    console.log(`[${idx + 1}/${total}] [http 200] ${ip} ${ver}`);
    return { idx, ip, fam, res: 'ok', line };
  }
  console.log(`[${idx + 1}/${total}] [http ${h.code}] ${ip} ${ver}`);
  return { idx, ip, fam, res: 'bad', line };
}

// ---------------- 主流程 ----------------
(async () => {
  if (!fs.existsSync(config.ipList)) {
    console.error(`[ERR] not found: ${config.ipList}`);
    process.exit(1);
  }
  {
    const c = await run('curl', ['--version'], 5000);
    if (!c.ok && c.code === 'ENOENT') {
      console.error('[ERR] curl not found in PATH');
      process.exit(1);
    }
  }

  const raw = fs.readFileSync(config.ipList, 'utf8');
  const ips = raw.split(/\r?\n/)
    .map(s => s.trim().split(/\s+/)[0])
    .filter(s => s !== '' && !s.startsWith('#'));
  const total = ips.length;

  fs.writeFileSync(config.ipv4File, '');
  fs.writeFileSync(config.ipv6File, '');
  fs.writeFileSync(config.logFile, '');

  console.log(`start: ${total} IPs, concurrency=${config.concurrency}, probe=tcp/${config.tcpPort}`);

  // ---- 工作池: N 个 worker 同时拉任务 ----
  const results = new Array(total);
  let cursor = 0;
  const workers = Math.max(1, Math.min(config.concurrency, total));

  await Promise.all(Array.from({ length: workers }, async () => {
    while (true) {
      const i = cursor++;
      if (i >= total) break;
      results[i] = await testIp(ips[i], i, total);
    }
  }));

  // ---- 按输入顺序落盘 (通过的写入非根随机版) ----
  let tcpFail = 0, http200 = 0, httpBad = 0, ok4 = 0, ok6 = 0;
  for (const r of results) {
    fs.appendFileSync(config.logFile, r.line + '\n');
    if (r.res === 'pfail') {
      tcpFail++;
    } else if (r.res === 'ok') {
      http200++;
      if (r.fam === 6) {
        fs.appendFileSync(config.ipv6File, randomizeV6(r.ip) + '\n');
        ok6++;
      } else {
        fs.appendFileSync(config.ipv4File, randomizeV4(r.ip) + '\n');
        ok4++;
      }
    } else {
      httpBad++;
    }
  }

  console.log('');
  console.log('==================================================');
  console.log(`DONE: total=${total}  tcp_fail=${tcpFail}`);
  console.log(`       http200=${http200} (v4=${ok4}, v6=${ok6})  other=${httpBad}`);
  console.log(`ipv4 : ${config.ipv4File}   (非根随机版)`);
  console.log(`ipv6 : ${config.ipv6File}   (非根随机版)`);
  console.log(`log  : ${config.logFile}`);
  console.log('==================================================');
})();
