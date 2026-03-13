#!/usr/bin/env zsh

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RC_DIR="$SCRIPT_DIR/rc"

RC_FILES=(.zshrc .vimrc .my_env)

for file in "${RC_FILES[@]}"; do
    src="$RC_DIR/$file"
    dst="$HOME/$file"

    if [[ ! -f "$src" ]]; then
        echo "⚠ 源文件不存在，跳过: $src"
        continue
    fi

    if [[ -L "$dst" ]]; then
        current_target="$(readlink "$dst")"
        if [[ "$current_target" == "$src" ]]; then
            echo "✓ 已是正确软链接，跳过: $dst"
            continue
        else
            echo "↺ 替换已有软链接: $dst -> $src (原指向: $current_target)"
            ln -sf "$src" "$dst"
        fi
    elif [[ -f "$dst" ]]; then
        backup="${dst}.bak.$(date +%Y%m%d%H%M%S)"
        echo "↷ 备份已有文件: $dst -> $backup"
        mv "$dst" "$backup"
        ln -s "$src" "$dst"
        echo "✓ 已创建软链接: $dst -> $src"
    else
        ln -s "$src" "$dst"
        echo "✓ 已创建软链接: $dst -> $src"
    fi
done
