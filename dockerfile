# 使用 Ubuntu 作為基礎鏡像，方便安裝各種工具
FROM ubuntu:22.04

# 避免安裝過程中的交互式提示
ENV DEBIAN_FRONTEND=noninteractive

# 1. 更新並安裝系統依賴
# git, curl: 下載工具
# build-essential, libssl-dev, pkg-config: 編譯 Foundry 所需
# vim, nano: 容器內編輯代碼用 (可選)
RUN apt-get update && apt-get install -y     curl     git     build-essential     libssl-dev     pkg-config     vim     nano     && rm -rf /var/lib/apt/lists/*

# 2. 安裝 Node.js (為了兼容一些 npm 依賴或腳本)
RUN curl -fsSL https://deb.nodesource.com/setup_18.x | bash -     && apt-get install -y nodejs

# 3. 安裝 Foundry (Forge, Cast, Anvil)
SHELL ["/bin/bash", "-c"]
RUN curl -L https://foundry.paradigm.xyz | bash

# 將 Foundry 加入環境變數
ENV PATH="/root/.foundry/bin:/home/j/.npm-global/bin:/run/user/1000/fnm_multishells/4839_1765154743407/bin:/home/j/.local/share/fnm:/home/j/.pyenv/shims:/home/j/.pyenv/bin:/home/j/.local/bin:/usr/local/go/bin:/home/j/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/usr/lib/wsl/lib:/mnt/c/Program Files/WindowsApps/MicrosoftCorporationII.WindowsSubsystemForLinux_2.6.2.0_x64__8wekyb3d8bbwe:/mnt/c/Program Files (x86)/Common Files/Oracle/Java/java8path:/mnt/c/Program Files (x86)/Common Files/Oracle/Java/javapath:/mnt/c/Program Files (x86)/VMware/VMware Workstation/bin/:/mnt/c/Windows/system32:/mnt/c/Windows:/mnt/c/Windows/System32/Wbem:/mnt/c/Windows/System32/WindowsPowerShell/v1.0/:/mnt/c/Windows/System32/OpenSSH/:/mnt/d/Program Files/dotnet/:/mnt/d/Program Files/Git/cmd:/mnt/c/Program Files/LLVM/bin:/mnt/c/Program Files/Docker/Docker/resources/bin:/mnt/c/Users/j/.cargo/bin:/mnt/c/Users/j/AppData/Local/Programs/Python/Python311/Scripts/:/mnt/c/Users/j/AppData/Local/Programs/Python/Python311/:/mnt/c/Users/j/AppData/Local/Microsoft/WindowsApps:/mnt/c/Program Files/LLVM/bin:/mnt/d/rusty-kaspa/protoc-21.10-win64/bin:/mnt/d/tools/platform-tools:/mnt/c/Users/j/AppData/Local/Programs/Microsoft VS Code/bin:/mnt/c/Users/j/AppData/Local/Programs/Antigravity/bin:/home/j/.foundry/bin:/home/j/.fzf/bin"

# 執行 foundryup 安裝最新版本
RUN foundryup

# 4. 設置工作目錄
WORKDIR /app

# 5. 預設命令：保持容器運行，方便進入操作
CMD ["tail", "-f", "/dev/null"]
