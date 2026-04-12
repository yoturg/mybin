#!/usr/bin/env bash
# 顺序解压目录下所有 zip / 7z / rar（按文件头魔数识别，不依赖后缀名）；成功后删除压缩包。
# 密码由命令行传入；无密码参数时不使用密码；多个密码时对每个压缩包依次尝试直至成功。
#
# 用法：
#   extract_all_archives.sh [选项] [根目录] [密码 ...]
#   extract_all_archives.sh [选项] -- [密码 ...]
#   -d, --directory DIR   解压扫描根目录（默认：当前工作目录）
#   若第一个非选项参数是已存在的目录，则作为根目录，其后参数均为密码。
#   若第一个非选项参数不是目录，则所有非选项参数均视为密码，根目录为当前目录。
#   「--」之后的参数全部视为密码。
#
# 分卷：按同目录常见命名归组（如 .partN.rar、.r00、.7z.001、.zip + .z01），每组只解压主卷一次，成功后删除整组。
# 说明：带自解压壳的压缩包（文件头不是 PK/7z/Rar!）不会被识别；嵌套压缩包需再次运行脚本。
# 扫描阶段：在终端里会单行刷新显示当前文件；若 stdout 被重定向，则每个文件各打一行（文件极多时日志会很大）。

set -uo pipefail

usage() {
  cat <<'EOF'
顺序解压目录下 zip / 7z / rar（按文件头识别，不依赖后缀名）；成功后删除压缩包。
密码由参数传入：无密码参数则不解密；多个密码时对每个压缩包按顺序逐一尝试直至成功。

用法：
  extract_all_archives.sh [-d DIR|--directory DIR] [根目录] [密码 ...]
  extract_all_archives.sh [选项] -- [密码 ...]
  extract_all_archives.sh -h | --help

  -d, --directory DIR   扫描与解压的根目录（默认：当前工作目录）
  若未使用 -d，且第一个非选项参数是「已存在的目录」，则作为根目录，其后参数均为密码。
  否则所有非选项参数均视为密码，根目录为当前目录。
  「--」之后的参数全部视为密码（根目录请用 -d 指定）。

示例：
  extract_all_archives.sh                          # 当前目录，无密码
  extract_all_archives.sh -d ~/Downloads           # 指定目录，无密码
  extract_all_archives.sh ~/Downloads pass1        # 目录 + 一个密码
  extract_all_archives.sh pass1 pass2              # 当前目录，依次尝试两个密码
  extract_all_archives.sh -d . -- 'pa ss' word     # 含空格密码用引号
EOF
}

declare -a PASSWORDS=()
ROOT=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    -d|--directory)
      if [[ $# -lt 2 ]]; then
        echo "错误：$1 需要目录参数。" >&2
        exit 1
      fi
      ROOT=$2
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --)
      shift
      while [[ $# -gt 0 ]]; do
        PASSWORDS+=("$1")
        shift
      done
      break
      ;;
    *)
      if [[ -z "$ROOT" && -d "$1" ]]; then
        ROOT=$1
        shift
      else
        PASSWORDS+=("$1")
        shift
      fi
      ;;
  esac
done

[[ -n "$ROOT" ]] || ROOT="."

if ! command -v 7z >/dev/null 2>&1; then
  echo "错误：未找到 7z 命令。请先安装：brew install p7zip" >&2
  exit 1
fi

if [[ ! -d "$ROOT" ]]; then
  echo "错误：根目录不存在或不是目录：$ROOT" >&2
  exit 1
fi

ROOT=$(cd "$ROOT" && pwd)

if ((${#PASSWORDS[@]} > 0)); then
  echo "将依次尝试 ${#PASSWORDS[@]} 个密码（每个压缩包在成功前会按顺序尝试）。"
else
  echo "未提供密码（仅适用于无密码或 7z 可直接打开的压缩包）。"
fi

# 读取文件头若干字节的十六进制（小写、无空格），兼容 macOS 自带 od
file_head_hex() {
  LC_ALL=C od -An -tx1 -N8 "$1" 2>/dev/null | tr -d ' \n\t' | tr '[:upper:]' '[:lower:]'
}

# 将秒数格式化为易读字符串（兼容 Bash 整数运算）
fmt_duration() {
  local s=$1
  if (( s >= 3600 )); then
    printf '%dh%dm%ds' $((s / 3600)) $(((s % 3600) / 60)) $((s % 60))
  elif (( s >= 60 )); then
    printf '%dm%ds' $((s / 60)) $((s % 60))
  else
    printf '%ds' "$s"
  fi
}

# 是否为 7z / zip / rar 的常见魔数（与 7z 能解的格式一致）
is_archive_magic() {
  local f=$1
  local hex
  hex=$(file_head_hex "$f")
  # 至少需要 4 字节（8 个十六进制字符）才能判断 zip
  [[ ${#hex} -ge 8 ]] || return 1
  case "$hex" in
    504b0304*|504b0506*|504b0708*) return 0 ;; # ZIP（含无后缀、.cbz 等）
    377abcaf271c*) return 0 ;;               # 7z
    526172211a07*) return 0 ;;               # RAR4 / RAR5（含 .cbr）
    *) return 1 ;;
  esac
}

# ---------- 分卷压缩包：识别「同组」文件、主卷路径、解压成功后整组删除 ----------
# 主卷：应传给 7z x 的那一个；同目录下常见命名（WinRAR / 7-Zip / WinZip）尽量覆盖。
# 说明：非常规命名或非首卷无魔数的分卷，仍可能只识别到部分文件；主卷逻辑与删除列表一致。

# 若 $1 为全数字则 echo 1，否则 0
_is_all_digits() {
  [[ "$1" =~ ^[0-9]+$ ]] && echo 1 || echo 0
}

# 从若干路径里选出「应作为 7z 输入」的主卷（按分卷序号）；无则 echo 第一参数
_pick_lowest_numeric_suffix_among() {
  local best="" bestn=""
  local f bn suf stem
  for f in "$@"; do
    [[ -f "$f" ]] || continue
    bn=$(basename "$f")
    stem="${bn%.*}"
    suf="${bn#"$stem".}"
    if [[ $(_is_all_digits "$suf") -eq 1 ]]; then
      if [[ -z "$best" ]] || (( 10#$suf < 10#$bestn )); then
        best=$f
        bestn=$suf
      fi
    fi
  done
  if [[ -n "$best" ]]; then
    echo "$best"
  else
    echo "$1"
  fi
}

# 从路径列表中选出 part 编号最小的 .partNN.rar（nocase）；无则 echo 空
_pick_lowest_rar_part_among() {
  local best="" bestn=999999999
  local f bn
  shopt -s nocasematch
  for f in "$@"; do
    [[ -f "$f" ]] || continue
    bn=$(basename "$f")
    if [[ "$bn" =~ ^(.+)\.part([0-9]+)\.rar$ ]]; then
      local n="${BASH_REMATCH[2]}"
      if (( 10#$n < bestn )); then
        best=$f
        bestn=$((10#$n))
      fi
    fi
  done
  shopt -u nocasematch
  echo "$best"
}

# 输出：主卷绝对路径（供 7z x 使用）。参数：已识别的压缩包绝对路径之一。
volume_primary_path() {
  local archive=$1
  local dir base stem peers f bn suf
  dir=$(cd "$(dirname "$archive")" && pwd)
  base=$(basename "$archive")

  shopt -s nullglob nocasematch

  # 7z 分卷：name.7z.001
  if [[ "$base" =~ \.7z\.[0-9]+$ ]]; then
    stem="${base%.*}"
    peers=("$dir/$stem".*)
    shopt -u nullglob nocasematch
    if ((${#peers[@]} == 0)); then
      echo "$archive"
      return
    fi
    _pick_lowest_numeric_suffix_among "${peers[@]}"
    return
  fi

  # ZIP 分卷：name.zip.001（后缀为纯数字）
  if [[ "$base" =~ \.zip\.[0-9]+$ ]]; then
    stem="${base%.*}"
    peers=("$dir/$stem".*)
    shopt -u nullglob nocasematch
    if ((${#peers[@]} == 0)); then
      echo "$archive"
      return
    fi
    _pick_lowest_numeric_suffix_among "${peers[@]}"
    return
  fi

  # RAR：name.part01.rar / name.part1.rar
  if [[ "$base" =~ \.part[0-9]+\.rar$ ]]; then
    stem="${base%.part*}.part"
    peers=("$dir/${stem}"*.rar)
    local p
    p=$(_pick_lowest_rar_part_among "${peers[@]}")
    shopt -u nullglob nocasematch
    if [[ -n "$p" ]]; then
      echo "$p"
    else
      echo "$archive"
    fi
    return
  fi

  # RAR 经典：name.rar + name.r00 …（扩展名恰好三个字符且为 .r + 两位数字）
  if [[ "$base" =~ \.r[0-9][0-9]$ ]] || [[ "$base" =~ \.rar$ ]]; then
    stem="${base%.rar}"
    if [[ "$base" =~ \.r[0-9][0-9]$ ]]; then
      stem="${base%.???}"
    fi
    peers=()
    [[ -f "$dir/$stem.rar" ]] && peers+=("$dir/$stem.rar")
    for f in "$dir/$stem".r[0-9][0-9]; do
      [[ -f "$f" ]] && peers+=("$f")
    done
    shopt -u nullglob nocasematch
    if [[ -f "$dir/$stem.rar" ]]; then
      echo "$dir/$stem.rar"
    elif ((${#peers[@]} > 0)); then
      echo "${peers[0]}"
    else
      echo "$archive"
    fi
    return
  fi

  # ZIP + WinZip 分卷：name.zip + name.z01 …
  if [[ "$base" =~ \.zip$ ]] || [[ "$base" =~ \.cbz$ ]]; then
    stem="${base%.*}"
    peers=("$dir/$base")
    for f in "$dir/$stem".z[0-9][0-9]; do
      peers+=("$f")
    done
    shopt -u nullglob nocasematch
    # 存在 z01 等则认为分卷，主卷为 zip/cbz；否则即单文件
    for f in "$dir/$stem".z[0-9][0-9]; do
      if [[ -f "$f" ]]; then
        echo "$dir/$base"
        return
      fi
    done
    echo "$archive"
    return
  fi

  shopt -u nullglob nocasematch
  echo "$archive"
}

# 输出：与主卷同组、应一并删除的绝对路径（每行一个，含主卷）。参数：主卷路径。
volume_group_files() {
  local primary=$1
  local dir base stem peers f bn suf
  dir=$(cd "$(dirname "$primary")" && pwd)
  base=$(basename "$primary")

  shopt -s nullglob nocasematch

  if [[ "$base" =~ \.7z\.[0-9]+$ ]]; then
    stem="${base%.*}"
    for f in "$dir/$stem".*; do
      bn=$(basename "$f")
      suf="${bn#"${stem}".}"
      [[ -f "$f" ]] && [[ $(_is_all_digits "$suf") -eq 1 ]] && echo "$f"
    done
    shopt -u nullglob nocasematch
    return
  fi

  if [[ "$base" =~ \.zip\.[0-9]+$ ]]; then
    stem="${base%.*}"
    for f in "$dir/$stem".*; do
      bn=$(basename "$f")
      suf="${bn#"${stem}".}"
      [[ -f "$f" ]] && [[ $(_is_all_digits "$suf") -eq 1 ]] && echo "$f"
    done
    shopt -u nullglob nocasematch
    return
  fi

  if [[ "$base" =~ \.part[0-9]+\.rar$ ]]; then
    stem="${base%.part*}.part"
    for f in "$dir/${stem}"*.rar; do
      bn=$(basename "$f")
      [[ -f "$f" ]] && [[ "$bn" =~ \.part[0-9]+\.rar$ ]] && echo "$f"
    done
    shopt -u nullglob nocasematch
    return
  fi

  if [[ "$base" =~ \.r[0-9][0-9]$ ]] || [[ "$base" =~ \.rar$ ]]; then
    stem="${base%.rar}"
    if [[ "$base" =~ \.r[0-9][0-9]$ ]]; then
      stem="${base%.???}"
    fi
    [[ -f "$dir/$stem.rar" ]] && echo "$dir/$stem.rar"
    for f in "$dir/$stem".r[0-9][0-9]; do
      [[ -f "$f" ]] && echo "$f"
    done
    shopt -u nullglob nocasematch
    return
  fi

  if [[ "$base" =~ \.zip$ ]] || [[ "$base" =~ \.cbz$ ]]; then
    stem="${base%.*}"
    echo "$dir/$base"
    for f in "$dir/$stem".z[0-9][0-9]; do
      [[ -f "$f" ]] && echo "$f"
    done
    shopt -u nullglob nocasematch
    return
  fi

  shopt -u nullglob nocasematch
  echo "$primary"
}

# 将扫描到的路径去重为「每个分卷组只保留主卷」；stdout 每行一个路径
unique_primary_archives() {
  local a p
  local -a prim
  for a in "$@"; do
    p=$(volume_primary_path "$a")
    prim+=("$p")
  done
  if ((${#prim[@]} == 0)); then
    return
  fi
  printf '%s\n' "${prim[@]}" | LC_ALL=C sort -u
}

# 启动时一次性收集路径，避免解压过程中新生成的文件被重复处理（兼容 macOS Bash 3.2）
echo "── 阶段 1/2：扫描目录（按文件头识别压缩包）──"
echo "根目录：$ROOT"
scan_start=$(date +%s)
scanned=0
archives=()
while IFS= read -r -d '' f; do
  scanned=$((scanned + 1))
  # 显示当前正在检查的文件：终端用 \r 单行刷新；重定向等非终端时每个文件单独一行
  if [[ -t 1 ]]; then
    printf '\r  正在扫描 #%d: %s\033[K' "$scanned" "$f"
  else
    echo "  正在扫描 #${scanned}: $f"
  fi
  if (( scanned % 3000 == 0 )); then
    [[ -t 1 ]] && echo ""
    now=$(date +%s)
    elapsed=$((now - scan_start))
    echo "  … 已检查 ${scanned} 个文件，已识别 ${#archives[@]} 个压缩包，扫描已用时 $(fmt_duration "$elapsed")；当前：$f"
  fi
  is_archive_magic "$f" || continue
  archives+=("$f")
done < <(find "$ROOT" -type f -size +11c -print0 2>/dev/null)

[[ -t 1 ]] && echo ""
scan_end=$(date +%s)
scan_secs=$((scan_end - scan_start))
echo "扫描结束：共检查 ${scanned} 个文件，识别 ${#archives[@]} 个压缩包，用时 $(fmt_duration "$scan_secs")。"

# 按路径排序（支持异常文件名）
sorted=()
if (( ${#archives[@]} > 0 )); then
  echo "正在对识别结果排序…"
  while IFS= read -r -d '' s; do
    sorted+=("$s")
  done < <(printf '%s\0' "${archives[@]}" | LC_ALL=C sort -z)
  archives=("${sorted[@]}")
fi

# 分卷组：多个被识别的文件可能属于同一组，只保留主卷解压一次，成功后整组删除
if (( ${#archives[@]} > 0 )); then
  deduped=()
  while IFS= read -r line; do
    [[ -n "$line" ]] && deduped+=("$line")
  done < <(unique_primary_archives "${archives[@]}")
  archives=("${deduped[@]}")
fi

total=${#archives[@]}
if (( total == 0 )); then
  echo "在「$ROOT」下未发现文件头为 ZIP / 7z / RAR 的压缩包（不看后缀名）。"
  exit 0
fi

# 使用全局 PASSWORDS：无密码则 7z 不传 -p；否则对每个压缩包按顺序尝试各密码直至成功
run_7z_extract() {
  local archive=$1
  local outdir=$2
  local idx pw
  if ((${#PASSWORDS[@]} == 0)); then
    7z x -y "-o${outdir}/" -- "$archive"
    return
  fi
  idx=0
  for pw in "${PASSWORDS[@]}"; do
    idx=$((idx + 1))
    if ((${#PASSWORDS[@]} > 1)); then
      echo "  尝试第 ${idx}/${#PASSWORDS[@]} 个密码…"
    fi
    if 7z x -y "-p${pw}" "-o${outdir}/" -- "$archive"; then
      return 0
    fi
  done
  echo "  已尝试全部 ${#PASSWORDS[@]} 个密码，解压仍失败。" >&2
  return 1
}

echo ""
echo "── 阶段 2/2：解压（顺序执行，不并行）──"
echo "共 $total 个压缩包（分卷已合并为每组 1 次），解压到各文件所在目录；成功后删除该组全部分卷。"
echo ""

extract_start=$(date +%s)
ok=0
fail=0
idx=0
for archive in "${archives[@]}"; do
  idx=$((idx + 1))
  dir=$(dirname "$archive")
  name=$(basename "$archive")
  pct=$((idx * 100 / total))
  if (( idx > 1 )); then
    now=$(date +%s)
    elapsed=$((now - extract_start))
    done_n=$((idx - 1))
    avg=$((elapsed / done_n))
    left=$((total - idx + 1))
    eta=$((avg * left))
    eta_str="；已用时 $(fmt_duration "$elapsed")；按当前均速预计剩余约 $(fmt_duration "$eta")"
  else
    eta_str=""
  fi

  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "进度：[$idx / $total]  约 ${pct}%${eta_str}"
  echo "文件：$archive"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

  t_item=$(date +%s)
  # -o 与路径之间不能有空格；解压到压缩包所在目录
  if run_7z_extract "$archive" "$dir"; then
    deleted=()
    while IFS= read -r vf; do
      [[ -z "$vf" ]] && continue
      rm -f -- "$vf"
      deleted+=("$(basename "$vf")")
    done < <(volume_group_files "$archive")
    ok=$((ok + 1))
    item_secs=$(($(date +%s) - t_item))
    if ((${#deleted[@]} > 1)); then
      echo ">>> 成功（本包 $(fmt_duration "$item_secs")）— 已删除分卷共 ${#deleted[@]} 个：${deleted[*]}"
    else
      echo ">>> 成功（本包 $(fmt_duration "$item_secs")）— 已删除：$name"
    fi
  else
    fail=$((fail + 1))
    item_secs=$(($(date +%s) - t_item))
    echo ">>> 失败（本包 $(fmt_duration "$item_secs")）— 未删除：$name" >&2
  fi
  echo ""
done

extract_end=$(date +%s)
extract_secs=$((extract_end - extract_start))
echo "全部处理结束。"
echo "汇总：成功 ${ok}，失败 ${fail}，解压阶段总用时 $(fmt_duration "$extract_secs")；含扫描共 $(fmt_duration "$((extract_end - scan_start))")）。"
