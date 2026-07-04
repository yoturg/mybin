#!/usr/bin/env node
// 顺序解压目录下所有 zip / 7z / rar / tar.*（按文件头魔数识别，不依赖后缀名）；成功后删除压缩包。
// 根目录固定为调用时的当前工作目录；密码由命令行传入；多个密码时对每个压缩包依次尝试直至成功。
//
// 用法：
//   extract_all_archives.js [-d|--deep] [密码 ...]
//   extract_all_archives.js [选项] -- [密码 ...]
//   -d, --deep   递归扫描子目录（默认只扫当前目录）
//
// 分卷：按同目录常见命名归组（如 .partN.rar、.r00、.7z.001、.zip + .z01），每组只解压主卷一次，成功后删除整组。

'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

// ── 用法帮助 ──────────────────────────────────────────────────
function usage() {
  console.log(`顺序解压目录下 zip / 7z / rar / tar.*（按文件头识别，不依赖后缀名）；成功后删除压缩包。
根目录固定为当前工作目录；密码由参数传入；多个密码时对每个压缩包按顺序逐一尝试直至成功。

用法：
  extract_all_archives.js [-d|--deep] [密码 ...]
  extract_all_archives.js [-d|--deep] -- [密码 ...]
  extract_all_archives.js -h | --help

  -d, --deep   递归扫描子目录（默认只扫当前目录顶层文件）
  「--」之后的参数全部视为密码。

示例：
  extract_all_archives.js                    # 当前目录顶层，无密码
  extract_all_archives.js -d                 # 递归扫描，无密码
  extract_all_archives.js pass1              # 当前目录顶层，一个密码
  extract_all_archives.js -d pass1 pass2     # 递归扫描，依次尝试两个密码
  extract_all_archives.js -- 'pa ss' word    # 含空格密码用引号`);
}

// ── 参数解析 ──────────────────────────────────────────────────
const args = process.argv.slice(2);
const passwords = [];
let deep = false;

for (let i = 0; i < args.length; i++) {
  const a = args[i];
  if (a === '-d' || a === '--deep') {
    deep = true;
  } else if (a === '-h' || a === '--help') {
    usage();
    process.exit(0);
  } else if (a === '--') {
    for (i++; i < args.length; i++) passwords.push(args[i]);
    break;
  } else {
    passwords.push(a);
  }
}

const root = process.cwd();

// 检查 7z 是否可用
const check7z = spawnSync('7z', ['i'], { encoding: 'utf8' });
if (check7z.error || (check7z.status !== 0 && check7z.status !== 1 && check7z.stdout === '')) {
  const which = spawnSync('which', ['7z'], { encoding: 'utf8' });
  if (which.status !== 0) {
    console.error('错误：未找到 7z 命令。请先安装：brew install p7zip');
    process.exit(1);
  }
}

if (passwords.length > 0) {
  console.log(`将依次尝试 ${passwords.length} 个密码（每个压缩包在成功前会按顺序尝试）。`);
} else {
  console.log('未提供密码（仅适用于无密码或 7z 可直接打开的压缩包）。');
}

// ── 工具函数 ──────────────────────────────────────────────────
function fmtDuration(ms) {
  const s = Math.floor(ms / 1000);
  if (s >= 3600) return `${Math.floor(s / 3600)}h${Math.floor((s % 3600) / 60)}m${s % 60}s`;
  if (s >= 60) return `${Math.floor(s / 60)}m${s % 60}s`;
  return `${s}s`;
}

// ── 魔数识别（与 7z 支持格式一致） ───────────────────────────
// 读 512 字节（一个 tar block）：
//   前 8 字节覆盖 zip/7z/rar/gzip/bzip2/xz/zstd；
//   offset 257 是 POSIX/GNU tar 的 "ustar" 魔数；
//   无魔数的旧式 V7 tar 则通过校验和（checksum）鉴别。
function isArchiveMagic(filePath) {
  let fd;
  try {
    fd = fs.openSync(filePath, 'r');
    const buf = Buffer.alloc(512);
    const n = fs.readSync(fd, buf, 0, 512, 0);
    if (n < 4) return false;
    const hex = buf.slice(0, Math.min(n, 8)).toString('hex');
    if (hex.startsWith('504b0304') || hex.startsWith('504b0506') || hex.startsWith('504b0708')) return true; // ZIP
    if (hex.startsWith('377abcaf271c')) return true; // 7z
    if (hex.startsWith('526172211a07')) return true; // RAR4 / RAR5
    if (hex.startsWith('1f8b')) return true;         // gzip  → .tar.gz / .tgz
    if (hex.startsWith('425a68')) return true;        // bzip2 → .tar.bz2 / .tbz2
    if (hex.startsWith('fd377a585a00')) return true;  // xz    → .tar.xz / .txz
    if (hex.startsWith('28b52ffd')) return true;      // zstd  → .tar.zst / .tzst
    // POSIX / GNU tar：offset 257 处有 "ustar" 字符串
    if (n >= 262 && buf.slice(257, 262).toString('latin1') === 'ustar') return true;
    // V7 旧式 tar（无任何魔数）：通过 header checksum 验证
    // tar header 共 512 字节，校验和字段在 offset 148-155（8 字节 octal ASCII）
    // 计算规则：所有字节之和，校验和字段本身按 0x20（空格）参与计算
    if (n >= 512) {
      let sum = 0;
      for (let i = 0; i < 512; i++) {
        sum += (i >= 148 && i < 156) ? 0x20 : buf[i];
      }
      const storedStr = buf.slice(148, 156).toString('latin1').replace(/[\0 ]/g, '');
      if (storedStr.length > 0 && /^[0-7]+$/.test(storedStr) && parseInt(storedStr, 8) === sum) return true;
    }
    return false;
  } catch (_) {
    return false;
  } finally {
    if (fd !== undefined) try { fs.closeSync(fd); } catch (_) { /* ignore */ }
  }
}

// ── 分卷识别 ──────────────────────────────────────────────────
function isAllDigits(s) {
  return /^[0-9]+$/.test(s);
}

function pickLowestNumericSuffix(files) {
  let best = null;
  let bestN = Infinity;
  for (const f of files) {
    const bn = path.basename(f);
    const dotIdx = bn.lastIndexOf('.');
    if (dotIdx < 0) continue;
    const suf = bn.slice(dotIdx + 1);
    if (isAllDigits(suf)) {
      const n = parseInt(suf, 10);
      if (n < bestN) { best = f; bestN = n; }
    }
  }
  return best;
}

function pickLowestRarPart(files) {
  let best = null;
  let bestN = Infinity;
  for (const f of files) {
    const m = path.basename(f).match(/^(.+)\.part([0-9]+)\.rar$/i);
    if (m) {
      const n = parseInt(m[2], 10);
      if (n < bestN) { best = f; bestN = n; }
    }
  }
  return best;
}

function readdirSafe(dir) {
  try { return fs.readdirSync(dir); } catch (_) { return []; }
}

// 获取主卷路径（供 7z x 使用）
function volumePrimaryPath(archive) {
  const dir = path.dirname(archive);
  const base = path.basename(archive);

  // 7z 分卷：name.7z.001
  if (/\.7z\.[0-9]+$/i.test(base)) {
    const stem = base.replace(/\.[0-9]+$/, ''); // name.7z
    const peers = readdirSafe(dir)
      .filter(f => f.startsWith(stem + '.') && isAllDigits(f.slice(stem.length + 1)))
      .map(f => path.join(dir, f));
    return pickLowestNumericSuffix(peers) || archive;
  }

  // ZIP 分卷：name.zip.001
  if (/\.zip\.[0-9]+$/i.test(base)) {
    const stem = base.replace(/\.[0-9]+$/, ''); // name.zip
    const peers = readdirSafe(dir)
      .filter(f => f.startsWith(stem + '.') && isAllDigits(f.slice(stem.length + 1)))
      .map(f => path.join(dir, f));
    return pickLowestNumericSuffix(peers) || archive;
  }

  // RAR：name.part01.rar
  if (/\.part[0-9]+\.rar$/i.test(base)) {
    const stemBase = base.replace(/\.part[0-9]+\.rar$/i, '');
    const peers = readdirSafe(dir)
      .filter(f => /\.part[0-9]+\.rar$/i.test(f) && f.toLowerCase().startsWith(stemBase.toLowerCase() + '.part'))
      .map(f => path.join(dir, f));
    return pickLowestRarPart(peers) || archive;
  }

  // RAR 经典：name.rar + name.r00 …
  if (/\.r[0-9]{2}$/i.test(base) || /\.rar$/i.test(base)) {
    const stem = base.replace(/\.(rar|r[0-9]{2})$/i, '');
    const rarFile = path.join(dir, stem + '.rar');
    if (fs.existsSync(rarFile)) return rarFile;
    const rparts = readdirSafe(dir)
      .filter(f => /\.r[0-9]{2}$/i.test(f) && f.toLowerCase().startsWith(stem.toLowerCase() + '.r'))
      .sort();
    return rparts.length > 0 ? path.join(dir, rparts[0]) : archive;
  }

  // ZIP + WinZip 分卷：name.zip + name.z01 …
  if (/\.(zip|cbz)$/i.test(base)) {
    const stem = base.replace(/\.[^.]+$/, '');
    const hasZ01 = readdirSafe(dir).some(
      f => /\.z[0-9]{2}$/i.test(f) && f.toLowerCase().startsWith(stem.toLowerCase() + '.z'),
    );
    return hasZ01 ? path.join(dir, base) : archive;
  }

  return archive;
}

// 获取分卷组全部文件（解压成功后一并删除）
function volumeGroupFiles(primary) {
  const dir = path.dirname(primary);
  const base = path.basename(primary);

  // 7z 分卷
  if (/\.7z\.[0-9]+$/i.test(base)) {
    const stem = base.replace(/\.[0-9]+$/, '');
    return readdirSafe(dir)
      .filter(f => f.startsWith(stem + '.') && isAllDigits(f.slice(stem.length + 1)))
      .map(f => path.join(dir, f));
  }

  // ZIP 分卷：name.zip.001
  if (/\.zip\.[0-9]+$/i.test(base)) {
    const stem = base.replace(/\.[0-9]+$/, '');
    return readdirSafe(dir)
      .filter(f => f.startsWith(stem + '.') && isAllDigits(f.slice(stem.length + 1)))
      .map(f => path.join(dir, f));
  }

  // RAR：name.part01.rar
  if (/\.part[0-9]+\.rar$/i.test(base)) {
    const stemBase = base.replace(/\.part[0-9]+\.rar$/i, '');
    return readdirSafe(dir)
      .filter(f => /\.part[0-9]+\.rar$/i.test(f) && f.toLowerCase().startsWith(stemBase.toLowerCase() + '.part'))
      .map(f => path.join(dir, f));
  }

  // RAR 经典
  if (/\.r[0-9]{2}$/i.test(base) || /\.rar$/i.test(base)) {
    const stem = base.replace(/\.(rar|r[0-9]{2})$/i, '');
    const result = [];
    const rarFile = path.join(dir, stem + '.rar');
    if (fs.existsSync(rarFile)) result.push(rarFile);
    readdirSafe(dir)
      .filter(f => /\.r[0-9]{2}$/i.test(f) && f.toLowerCase().startsWith(stem.toLowerCase() + '.r'))
      .forEach(f => result.push(path.join(dir, f)));
    return result.length > 0 ? result : [primary];
  }

  // ZIP + WinZip 分卷
  if (/\.(zip|cbz)$/i.test(base)) {
    const stem = base.replace(/\.[^.]+$/, '');
    const result = [path.join(dir, base)];
    readdirSafe(dir)
      .filter(f => /\.z[0-9]{2}$/i.test(f) && f.toLowerCase().startsWith(stem.toLowerCase() + '.z'))
      .forEach(f => result.push(path.join(dir, f)));
    return result;
  }

  return [primary];
}

// ── 文件扫描 ─────────────────────────────────────────────────
// deep=false：只列当前目录的直接文件（不进子目录）
// deep=true ：递归遍历所有子目录
function walkSync(dir, recursive, results = []) {
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch (_) {
    return results;
  }
  for (const e of entries) {
    const full = path.join(dir, e.name);
    if (e.isDirectory()) {
      if (recursive) walkSync(full, true, results);
    } else if (e.isFile()) {
      results.push(full);
    }
  }
  return results;
}

// ── 阶段 1：扫描 ──────────────────────────────────────────────
console.log(`── 阶段 1/2：扫描目录（按文件头识别压缩包，${deep ? '递归' : '仅顶层'}）──`);
console.log(`根目录：${root}`);

const scanStart = Date.now();
const isTTY = process.stdout.isTTY;
let scanned = 0;
const archives = [];

const allFiles = walkSync(root, deep)
  .filter(f => { try { return fs.statSync(f).size > 11; } catch (_) { return false; } })
  .sort();

for (const f of allFiles) {
  scanned++;
  if (isTTY) {
    process.stdout.write(`\r  正在扫描 #${scanned}: ${f}\x1b[K`);
  } else {
    console.log(`  正在扫描 #${scanned}: ${f}`);
  }
  if (scanned % 3000 === 0) {
    if (isTTY) process.stdout.write('\n');
    console.log(`  … 已检查 ${scanned} 个文件，已识别 ${archives.length} 个压缩包，扫描已用时 ${fmtDuration(Date.now() - scanStart)}；当前：${f}`);
  }
  if (isArchiveMagic(f)) archives.push(f);
}

if (isTTY) process.stdout.write('\n');
console.log(`扫描结束：共检查 ${scanned} 个文件，识别 ${archives.length} 个压缩包，用时 ${fmtDuration(Date.now() - scanStart)}。`);

// 分卷组去重：每组只保留主卷
const primarySet = new Set(archives.map(a => volumePrimaryPath(a)));
const deduped = [...primarySet].sort();

const total = deduped.length;
if (total === 0) {
  console.log(`在「${root}」下未发现文件头为 ZIP / 7z / RAR / tar.* 的压缩包（不看后缀名）。`);
  process.exit(0);
}

// ── 阶段 2：解压 ──────────────────────────────────────────────
function run7zExtract(archive, outDir) {
  if (passwords.length === 0) {
    const r = spawnSync('7z', ['x', '-y', `-o${outDir}/`, '--', archive], { stdio: 'inherit' });
    return r.status === 0;
  }
  for (let i = 0; i < passwords.length; i++) {
    if (passwords.length > 1) console.log(`  尝试第 ${i + 1}/${passwords.length} 个密码…`);
    const r = spawnSync('7z', ['x', '-y', `-p${passwords[i]}`, `-o${outDir}/`, '--', archive], { stdio: 'inherit' });
    if (r.status === 0) return true;
  }
  console.error(`  已尝试全部 ${passwords.length} 个密码，解压仍失败。`);
  return false;
}

// ── pyzipper 可用性检查（懒加载，只检测一次）──────────────────
let _pyzipperOk = null;
function checkPyzipper() {
  if (_pyzipperOk !== null) return _pyzipperOk;
  const r = spawnSync('python3', ['-c', 'import pyzipper'], { encoding: 'utf8' });
  _pyzipperOk = (r.status === 0);
  return _pyzipperOk;
}

// ── GBK zip 检测 ──────────────────────────────────────────────
// 读 central directory：若所有条目 EFS flag(bit 11)均未置位，
// 且至少一个文件名含 GBK 高字节（>=0x81），则判定为 GBK zip。
function isGbkZip(filePath) {
  let fd;
  try {
    fd = fs.openSync(filePath, 'r');
    const { size } = fs.fstatSync(fd);

    // 1. 在末尾 65558 字节内搜索 EOCD 签名 PK\x05\x06
    const searchSize = Math.min(65558, size);
    const tail = Buffer.alloc(searchSize);
    fs.readSync(fd, tail, 0, searchSize, size - searchSize);

    let cdOffset = -1;
    for (let i = searchSize - 22; i >= 0; i--) {
      if (tail[i] !== 0x50 || tail[i+1] !== 0x4b || tail[i+2] !== 0x05 || tail[i+3] !== 0x06) continue;
      const raw = tail.readUInt32LE(i + 16);
      if (raw !== 0xFFFFFFFF) {
        cdOffset = raw;
      } else {
        // Zip64：找 EOCD Locator（PK\x06\x07），从中取 Zip64 EOCD 偏移
        for (let j = i - 20; j >= 0; j--) {
          if (tail[j] === 0x50 && tail[j+1] === 0x4b && tail[j+2] === 0x06 && tail[j+3] === 0x07) {
            const eocd64At = Number(tail.readBigUInt64LE(j + 8));
            const eocd64 = Buffer.alloc(56);
            fs.readSync(fd, eocd64, 0, 56, eocd64At);
            cdOffset = Number(eocd64.readBigUInt64LE(48));
            break;
          }
        }
      }
      break;
    }
    if (cdOffset < 0) return false;

    // 2. 读 central directory（最多 64 KB，可覆盖数百条目的文件名）
    const cdSize = Math.min(65536, size - cdOffset);
    const cd = Buffer.alloc(cdSize);
    const cdRead = fs.readSync(fd, cd, 0, cdSize, cdOffset);

    // 3. 逐条扫描
    let pos = 0;
    while (pos + 46 <= cdRead) {
      if (cd[pos] !== 0x50 || cd[pos+1] !== 0x4b || cd[pos+2] !== 0x01 || cd[pos+3] !== 0x02) break;
      const flag   = cd.readUInt16LE(pos + 8);
      const fnLen  = cd.readUInt16LE(pos + 28);
      const extLen = cd.readUInt16LE(pos + 30);
      const cmtLen = cd.readUInt16LE(pos + 32);
      if (flag & 0x800) return false;                   // EFS=1 → UTF-8，非 GBK
      const fn = cd.slice(pos + 46, pos + 46 + fnLen);
      for (let b = 0; b < fn.length; b++) {
        if (fn[b] >= 0x81) return true;                 // 发现 GBK 高字节
      }
      pos += 46 + fnLen + extLen + cmtLen;
    }
    return false;
  } catch (_) {
    return false;
  } finally {
    if (fd !== undefined) try { fs.closeSync(fd); } catch (_) {}
  }
}

// ── pyzipper 解压（GBK 文件名 + GBK 密码）────────────────────
// 将 Python 脚本写入临时文件执行，避免内联字符串转义问题。
function runPyZipperExtract(archive, outDir) {
  const tmpScript = path.join(os.tmpdir(), `gbkzip_${process.pid}.py`);
  const pyScript = `\
import sys, os, pyzipper, shutil

zip_path = sys.argv[1]
out_dir  = sys.argv[2]
raw_pwds = sys.argv[3:]
pwds     = [p.encode('gbk') for p in raw_pwds] if raw_pwds else [None]

def fix_name(s):
    try:
        return s.encode('cp437').decode('gbk')
    except Exception:
        return s

def do_extract(pwd):
    os.makedirs(out_dir, exist_ok=True)
    root = os.path.abspath(out_dir) + os.sep
    with pyzipper.AESZipFile(zip_path, 'r') as zf:
        if pwd is not None:
            zf.setpassword(pwd)
        for info in zf.infolist():
            name = fix_name(info.filename)
            dest = os.path.normpath(os.path.join(out_dir, name.lstrip('/').replace('\\\\', '/')))
            # 防路径穿越
            if not (dest + os.sep).startswith(root) and dest + os.sep != root:
                continue
            if name.endswith('/'):
                os.makedirs(dest, exist_ok=True)
            else:
                par = os.path.dirname(dest)
                if par:
                    os.makedirs(par, exist_ok=True)
                with zf.open(info) as src, open(dest, 'wb') as dst:
                    shutil.copyfileobj(src, dst, 1 << 20)
                print('  提取: ' + name, flush=True)

last_err = None
for i, pwd in enumerate(pwds):
    try:
        if len(pwds) > 1:
            print('  尝试第 %d/%d 个密码（GBK 编码）…' % (i + 1, len(pwds)), flush=True)
        do_extract(pwd)
        sys.exit(0)
    except Exception as e:
        last_err = str(e)

print('pyzipper 失败：' + str(last_err), file=sys.stderr, flush=True)
sys.exit(1)
`;
  try {
    fs.writeFileSync(tmpScript, pyScript, 'utf8');
    const r = spawnSync('python3', [tmpScript, archive, outDir, ...passwords], { stdio: 'inherit' });
    return r.status === 0;
  } finally {
    try { fs.unlinkSync(tmpScript); } catch (_) {}
  }
}

// ── 解压路由：GBK zip → pyzipper；其他 → 7z ──────────────────
function extractArchive(archive, outDir) {
  // 只对 zip 格式做 GBK 检测（magic: PK\x03\x04）
  const isZip = (() => {
    try {
      const buf = Buffer.alloc(4);
      const fd = fs.openSync(archive, 'r');
      fs.readSync(fd, buf, 0, 4, 0);
      fs.closeSync(fd);
      const h = buf.toString('hex');
      return h.startsWith('504b0304') || h.startsWith('504b0506') || h.startsWith('504b0708');
    } catch (_) { return false; }
  })();

  if (isZip && isGbkZip(archive)) {
    if (checkPyzipper()) {
      console.log('  [GBK zip] 检测到 GBK 编码，使用 pyzipper 解压…');
      if (runPyZipperExtract(archive, outDir)) return true;
      console.log('  [GBK zip] pyzipper 解压失败，回退 7z（文件名可能乱码）…');
    } else {
      console.log('  [GBK zip] 检测到 GBK 编码，但未安装 pyzipper（请运行：pip3 install pyzipper），回退 7z（文件名可能乱码）。');
    }
  }
  return run7zExtract(archive, outDir);
}

console.log('');
console.log('── 阶段 2/2：解压（顺序执行，不并行）──');
console.log(`共 ${total} 个压缩包（分卷已合并为每组 1 次），解压到各文件所在目录；成功后删除该组全部分卷。`);
console.log('');

const extractStart = Date.now();
let ok = 0;
let fail = 0;

for (let idx = 0; idx < deduped.length; idx++) {
  const archive = deduped[idx];
  const dir = path.dirname(archive);
  const name = path.basename(archive);
  const pct = Math.floor((idx + 1) * 100 / total);

  let etaStr = '';
  if (idx > 0) {
    const elapsed = Date.now() - extractStart;
    const avg = elapsed / idx;
    const eta = avg * (total - idx);
    etaStr = `；已用时 ${fmtDuration(elapsed)}；按当前均速预计剩余约 ${fmtDuration(eta)}`;
  }

  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log(`进度：[${idx + 1} / ${total}]  约 ${pct}%${etaStr}`);
  console.log(`文件：${archive}`);
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');

  const tItem = Date.now();
  if (extractArchive(archive, dir)) {
    const groupFiles = volumeGroupFiles(archive);
    const deleted = [];
    for (const vf of groupFiles) {
      if (!vf) continue;
      try { fs.unlinkSync(vf); deleted.push(path.basename(vf)); } catch (_) { /* ignore */ }
    }
    ok++;
    const itemTime = fmtDuration(Date.now() - tItem);
    if (deleted.length > 1) {
      console.log(`>>> 成功（本包 ${itemTime}）— 已删除分卷共 ${deleted.length} 个：${deleted.join(' ')}`);
    } else {
      console.log(`>>> 成功（本包 ${itemTime}）— 已删除：${name}`);
    }
  } else {
    fail++;
    console.error(`>>> 失败（本包 ${fmtDuration(Date.now() - tItem)}）— 未删除：${name}`);
  }
  console.log('');
}

const extractEnd = Date.now();
console.log('全部处理结束。');
console.log(`汇总：成功 ${ok}，失败 ${fail}，解压阶段总用时 ${fmtDuration(extractEnd - extractStart)}；含扫描共 ${fmtDuration(extractEnd - scanStart)}）。`);
