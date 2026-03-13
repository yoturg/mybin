
set tabstop=2
set softtabstop=2
set shiftwidth=2
set expandtab
set nu

imap{ {}<ESC>i<CR><ESC>O


let g:indentLine_char='|'
let g:indentLine_color_term=239

nmap <C-n> :NERDTreeToggle<CR>

call plug#begin('~/.vim/plugged')

Plug 'mattn/emmet-vim'
Plug 'ayu-theme/ayu-vim'    
Plug 'vim-airline/vim-airline'
Plug 'Yggdroot/indentLine'
Plug 'Raimondi/delimitMate'
Plug 'alvan/vim-closetag'
Plug 'preservim/nerdtree'
Plug 'junegunn/limelight.vim'
Plug 'junegunn/goyo.vim'  
Plug 'mxw/vim-jsx'
Plug 'ap/vim-css-color'
Plug 'tpope/vim-surround'
Plug 'isRuslan/vim-es6'
Plug 'guileen/vim-node'

" stylus的vim配色 
"Plug 'wavded/vim-stylus'

call plug#end()

set termguicolors
let ayucolor='dark'
colorscheme ayu

" 进入goyo模式后自动触发limelight，退出则关闭
autocmd! User GoyoEnter Limelight
autocmd! User GoyoLeave Limelight!
