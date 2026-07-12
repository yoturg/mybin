#!/usr/bin/env node
// 顺序解压目录下所有 zip / 7z / rar / tar.* / wim / Bandizip SFX（按文件头魔数识别，不依赖后缀名）；成功后删除压缩包。
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
  console.log(`顺序解压目录下 zip / 7z / rar / tar.* / wim / Bandizip SFX（按文件头识别，不依赖后缀名）；成功后删除压缩包。
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

// ── Bandizip SFX 识别 ─────────────────────────────────────────
// 文件头为 PE（MZ），内嵌 ZIP 数据；stub 内通常含 "BANDIZIPSFX" 标记。
// 同目录多个纯数字命名（001、002…）时 7z 会误判为分卷，解压时需加 -tzip。
const BANDIZIP_SFX_MARK = Buffer.from('BANDIZIPSFX');

function isBandizipSfx(filePath) {
  let fd;
  try {
    fd = fs.openSync(filePath, 'r');
    const head = Buffer.alloc(2);
    if (fs.readSync(fd, head, 0, 2, 0) < 2) return false;
    if (head[0] !== 0x4d || head[1] !== 0x5a) return false; // MZ
    const scanSize = Math.min(400 * 1024, fs.fstatSync(fd).size);
    const scan = Buffer.alloc(scanSize);
    fs.readSync(fd, scan, 0, scanSize, 0);
    return scan.includes(BANDIZIP_SFX_MARK);
  } catch (_) {
    return false;
  } finally {
    if (fd !== undefined) try { fs.closeSync(fd); } catch (_) { /* ignore */ }
  }
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
    if (hex.startsWith('4d5a')) return isBandizipSfx(filePath); // Bandizip SFX（PE stub + 内嵌 zip）
    if (hex.startsWith('4d5357494d')) return true; // WIM (MSWIM)
    if (hex.startsWith('57494d53')) return true;  // Split WIM 分卷 (WIMS)
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

  // Split WIM：name.wim + name2.swm + name3.swm …
  if (/\.swm$/i.test(base)) {
    const m = base.match(/^(.+?)(\d+)\.swm$/i);
    if (m) {
      const wimFile = path.join(dir, `${m[1]}.wim`);
      if (fs.existsSync(wimFile)) return wimFile;
    }
  }

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

  // Split WIM：name.wim + name2.swm + name3.swm …
  if (/\.wim$/i.test(base)) {
    const stem = base.replace(/\.wim$/i, '');
    const result = [path.join(dir, base)];
    const swmRe = new RegExp(`^${stem.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(\\d+)\\.swm$`, 'i');
    readdirSafe(dir)
      .filter(f => {
        const m = f.match(swmRe);
        return m && parseInt(m[1], 10) >= 2;
      })
      .forEach(f => result.push(path.join(dir, f)));
    return result;
  }

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
  console.log(`在「${root}」下未发现文件头为 ZIP / 7z / RAR / tar.* / WIM / Bandizip SFX 的压缩包（不看后缀名）。`);
  process.exit(0);
}

// ── 阶段 2：解压 ──────────────────────────────────────────────
function run7zExtract(archive, outDir, opts = {}) {
  const typeArgs = opts.type ? [`-t${opts.type}`] : [];
  if (passwords.length === 0) {
    const r = spawnSync('7z', ['x', '-y', ...typeArgs, `-o${outDir}/`, '--', archive], { stdio: 'inherit' });
    return r.status === 0;
  }
  for (let i = 0; i < passwords.length; i++) {
    if (passwords.length > 1) console.log(`  尝试第 ${i + 1}/${passwords.length} 个密码…`);
    const r = spawnSync('7z', ['x', '-y', ...typeArgs, `-p${passwords[i]}`, `-o${outDir}/`, '--', archive], { stdio: 'inherit' });
    if (r.status === 0) return true;
  }
  console.error(`  已尝试全部 ${passwords.length} 个密码，解压仍失败。`);
  return false;
}

// ── unrar 可用性检查（懒加载，只检测一次）────────────────────
let _unrarOk = null;
function checkUnrar() {
  if (_unrarOk !== null) return _unrarOk;
  const r = spawnSync('unrar', [], { encoding: 'utf8' });
  // unrar 无参数时输出帮助并以非 0 退出，但不会 error（找不到命令才 error）
  _unrarOk = !r.error;
  return _unrarOk;
}

// ── unrar 解压（支持 RAR4 / RAR5 所有压缩算法）───────────────
function runUnrarExtract(archive, outDir) {
  // unrar x -y -o+ [-pPASSWORD] archive outdir/
  if (passwords.length === 0) {
    const r = spawnSync('unrar', ['x', '-y', '-o+', archive, outDir + '/'], { stdio: 'inherit' });
    return r.status === 0;
  }
  for (let i = 0; i < passwords.length; i++) {
    if (passwords.length > 1) console.log(`  尝试第 ${i + 1}/${passwords.length} 个密码…`);
    const r = spawnSync('unrar', ['x', '-y', '-o+', `-p${passwords[i]}`, archive, outDir + '/'], { stdio: 'inherit' });
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

// ── gzip fname 读取 ───────────────────────────────────────────
// 解析 gzip 文件头（RFC 1952），返回 fname 字段的原始字节（Buffer）；
// 若无 fname 字段或解析失败则返回 null。
function readGzipFname(filePath) {
  let fd;
  try {
    fd = fs.openSync(filePath, 'r');
    const hdr = Buffer.alloc(10);
    if (fs.readSync(fd, hdr, 0, 10, 0) < 10) return null;
    if (hdr[0] !== 0x1f || hdr[1] !== 0x8b) return null; // 不是 gzip
    const flg = hdr[3];
    let pos = 10;

    if (flg & 0x04) { // FEXTRA
      const xlenBuf = Buffer.alloc(2);
      if (fs.readSync(fd, xlenBuf, 0, 2, pos) < 2) return null;
      pos += 2 + xlenBuf.readUInt16LE(0);
    }

    if (!(flg & 0x08)) return null; // 无 FNAME 字段

    // 读 null-terminated fname（最多 512 字节）
    const nameBuf = Buffer.alloc(512);
    const n = fs.readSync(fd, nameBuf, 0, 512, pos);
    const nullIdx = nameBuf.indexOf(0x00, 0);
    if (nullIdx < 0 || nullIdx > n) return nameBuf.slice(0, n);
    return nameBuf.slice(0, nullIdx);
  } catch (_) {
    return null;
  } finally {
    if (fd !== undefined) try { fs.closeSync(fd); } catch (_) {}
  }
}

// 检测 gzip fname 是否含 GBK 高字节（>= 0x81）
function isGbkGzip(filePath) {
  const fname = readGzipFname(filePath);
  if (!fname || fname.length === 0) return false;
  for (let i = 0; i < fname.length; i++) {
    if (fname[i] >= 0x81) return true;
  }
  return false;
}

// ── Python gzip 解压（GBK 文件名修正）────────────────────────
function runPythonGzipExtract(archive, outDir) {
  const tmpScript = path.join(os.tmpdir(), `gbkgzip_${process.pid}.py`);
  const pyScript = `\
import sys, os, gzip, shutil

gz_path = sys.argv[1]
out_dir  = sys.argv[2]

# 解析 gzip 头取 fname 字节
fname_bytes = b''
with open(gz_path, 'rb') as f:
    if f.read(2) != b'\\x1f\\x8b':
        print('不是 gzip 文件', file=sys.stderr)
        sys.exit(1)
    f.read(1)          # CM
    flg = f.read(1)[0] # FLG
    f.read(6)          # MTIME + XFL + OS
    if flg & 0x04:     # FEXTRA
        xlen = int.from_bytes(f.read(2), 'little')
        f.read(xlen)
    if flg & 0x08:     # FNAME
        while True:
            b = f.read(1)
            if not b or b == b'\\x00':
                break
            fname_bytes += b

if fname_bytes:
    try:
        outname = fname_bytes.decode('gbk')
    except Exception:
        outname = fname_bytes.decode('latin1', errors='replace')
else:
    base = os.path.basename(gz_path)
    outname = base[:-3] if base.lower().endswith('.gz') else base

os.makedirs(out_dir, exist_ok=True)
dest = os.path.join(out_dir, outname)
with gzip.open(gz_path, 'rb') as src, open(dest, 'wb') as dst:
    shutil.copyfileobj(src, dst, 1 << 20)
print('  提取: ' + outname, flush=True)
`;
  try {
    fs.writeFileSync(tmpScript, pyScript, 'utf8');
    const r = spawnSync('python3', [tmpScript, archive, outDir], { stdio: 'inherit' });
    return r.status === 0;
  } finally {
    try { fs.unlinkSync(tmpScript); } catch (_) {}
  }
}

// ── tar GBK 检测 ──────────────────────────────────────────────
// 遍历 tar 条目的文件名字段（最多检查 30 个条目），
// 若发现 GBK 高字节（>= 0x81）则返回 true。
function isGbkTar(filePath) {
  let fd;
  try {
    fd = fs.openSync(filePath, 'r');
    const block = Buffer.alloc(512);
    let pos = 0;
    for (let checked = 0; checked < 30; checked++) {
      if (fs.readSync(fd, block, 0, 512, pos) < 512) break;
      pos += 512;

      // 全零块 = 归档结束
      let allZero = true;
      for (let i = 0; i < 8; i++) { if (block[i] !== 0) { allZero = false; break; } }
      if (allZero) break;

      // 文件名字段：bytes 0-99（null 终止）
      const nullIdx = block.indexOf(0x00, 0);
      const nameLen = nullIdx < 0 ? 100 : Math.min(nullIdx, 100);
      for (let i = 0; i < nameLen; i++) {
        if (block[i] >= 0x81) return true;
      }

      // 跳过数据块（size 在 bytes 124-135，八进制 ASCII）
      const sizeStr = block.slice(124, 136).toString('latin1').replace(/[\0 ]/g, '');
      const fileSize = sizeStr.length > 0 ? parseInt(sizeStr, 8) : 0;
      if (!isNaN(fileSize) && fileSize > 0) {
        pos += Math.ceil(fileSize / 512) * 512;
      }
    }
    return false;
  } catch (_) {
    return false;
  } finally {
    if (fd !== undefined) try { fs.closeSync(fd); } catch (_) {}
  }
}

// ── Python tar 解压（GBK 文件名修正）────────────────────────
function runPythonTarExtract(archive, outDir) {
  const tmpScript = path.join(os.tmpdir(), `gbktar_${process.pid}.py`);
  const pyScript = `\
import sys, os, tarfile, shutil

tar_path = sys.argv[1]
out_dir  = sys.argv[2]
os.makedirs(out_dir, exist_ok=True)
root = os.path.abspath(out_dir) + os.sep

with tarfile.open(tar_path, 'r', encoding='gbk', errors='surrogateescape') as tf:
    for member in tf.getmembers():
        name = member.name.replace('\\\\\\\\', '/')
        dest = os.path.normpath(os.path.join(out_dir, name.lstrip('/')))
        if not (dest + os.sep).startswith(root) and dest + os.sep != root:
            continue
        if member.isdir():
            os.makedirs(dest, exist_ok=True)
        elif member.isfile():
            par = os.path.dirname(dest)
            if par:
                os.makedirs(par, exist_ok=True)
            with tf.extractfile(member) as src, open(dest, 'wb') as dst:
                shutil.copyfileobj(src, dst, 1 << 20)
            print('  提取: ' + member.name, flush=True)
`;
  try {
    fs.writeFileSync(tmpScript, pyScript, 'utf8');
    const r = spawnSync('python3', [tmpScript, archive, outDir], { stdio: 'inherit' });
    return r.status === 0;
  } finally {
    try { fs.unlinkSync(tmpScript); } catch (_) {}
  }
}

// ── 解压路由：GBK zip → pyzipper；GBK gzip → python gzip；GBK tar → python tar；其他 → 7z ──
function extractArchive(archive, outDir) {
  // 读文件头 512 字节，兼顾 tar 格式（需要 512 字节才能做 ustar / V7 校验）
  let magic512 = Buffer.alloc(0);
  try {
    const buf = Buffer.alloc(512);
    const fd = fs.openSync(archive, 'r');
    const n = fs.readSync(fd, buf, 0, 512, 0);
    fs.closeSync(fd);
    magic512 = buf.slice(0, n);
  } catch (_) {}

  const magic4 = magic512.slice(0, 4).toString('hex');
  const isZip  = magic4.startsWith('504b0304') || magic4.startsWith('504b0506') || magic4.startsWith('504b0708');
  const isGzip = magic4.startsWith('1f8b');
  const isRar  = magic4.startsWith('5261');   // RAR4: 526172211a0700  RAR5: 526172211a070100
  // RAR4: magic 第 7 字节（index 6）= 0x00；RAR5: = 0x01
  const isRar4 = isRar && magic512.length >= 7 && magic512[6] === 0x00;

  // 判断是否为 plain tar（ustar 或 V7 校验和）
  const isTar = (() => {
    if (magic512.length >= 262 && magic512.slice(257, 262).toString('latin1') === 'ustar') return true;
    if (magic512.length >= 512) {
      let sum = 0;
      for (let i = 0; i < 512; i++) sum += (i >= 148 && i < 156) ? 0x20 : magic512[i];
      const storedStr = magic512.slice(148, 156).toString('latin1').replace(/[\0 ]/g, '');
      if (storedStr.length > 0 && /^[0-7]+$/.test(storedStr) && parseInt(storedStr, 8) === sum) return true;
    }
    return false;
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

  if (isGzip && isGbkGzip(archive)) {
    console.log('  [GBK gzip] 检测到 gzip fname 字段含 GBK 编码，使用 python3 修正文件名…');
    if (runPythonGzipExtract(archive, outDir)) return true;
    console.log('  [GBK gzip] python3 解压失败，回退 7z（文件名可能乱码）…');
  }

  if (isTar && isGbkTar(archive)) {
    console.log('  [GBK tar] 检测到 tar 文件名含 GBK 编码，使用 python3 修正文件名…');
    if (runPythonTarExtract(archive, outDir)) return true;
    console.log('  [GBK tar] python3 解压失败，回退 7z（文件名可能乱码）…');
  }

  if (isRar && checkUnrar()) {
    const label = isRar4 ? 'RAR4' : 'RAR5';
    console.log(`  [${label}] 使用 unrar 解压…`);
    if (runUnrarExtract(archive, outDir)) return true;
    console.log(`  [${label}] unrar 失败，回退 7z…`);
  }

  if (isBandizipSfx(archive)) {
    console.log('  [Bandizip SFX] 使用 7z -tzip 解压（避免同目录多个 SFX 被误判为分卷）…');
    return run7zExtract(archive, outDir, { type: 'zip' });
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
