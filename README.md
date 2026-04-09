# wsl1-patch-align
This Python script is to fix ELF p_align for Windows Subsystem for Linux 1 (WSL 1) compatibility.  

No dependency.

The target issue is recorded in [microsoft/WSL#8219](https://github.com/microsoft/WSL/issues/8219), [microsoft/WSL#8151](https://github.com/microsoft/WSL/issues/8151), [microsoft/WSL#12369](https://github.com/microsoft/WSL/issues/12359).  

## Run
```bash
python3 fix.py [filepath_or_command]
```
e.g., `python3 fix.py node` or `python3 fix.py copilot`  
You might need to run this with `sudo`, for example, `sudo python3 fix.py node` 

```text
Command-Line Interface (CLI)

usage: fix.py [-h] [-f | -c] [-r] [-b BACKUP] [-o] target

Fix ELF p_align for WSL 1 compatibility.

positional arguments:
  target                The file path to the binary or command name to fix

options:
  -h, --help            show this help message and exit
  -f, --file            Explicitly treat input as a file path
  -c, --command         Explicitly treat input as a command name
  -r, --restore         Restore the file from the backup
  -b BACKUP, --backup BACKUP
                        Customized backup path
  -o, --overwrite       Overwrite existing backup
```

## Download
Pick curl or wget
```bash
curl -fsSL --proto '=https' --tlsv1.3 https://raw.githubusercontent.com/qingpeng9802/wsl1-patch-align/refs/heads/main/fix.py
```
```bash
wget -qO- --https-only --secure-protocol=TLSv1_3 https://raw.githubusercontent.com/qingpeng9802/wsl1-patch-align/refs/heads/main/fix.py
```

## One-liner (Download and Run)
Pick curl or wget
```bash
python3 <(curl -fsSL --proto '=https' --tlsv1.3 https://raw.githubusercontent.com/qingpeng9802/wsl1-patch-align/refs/heads/main/fix.py) -- [filepath_or_command]
```
```bash
python3 <(wget -qO- --https-only --secure-protocol=TLSv1_3 https://raw.githubusercontent.com/qingpeng9802/wsl1-patch-align/refs/heads/main/fix.py) -- [filepath_or_command]
```

## Target issue
This issue mainly affect `node`, `gzip` and `@github/copilot`, and the errors are reported in the way as 
```log
/usr/bin/node: 1: Syntax error: ")" unexpected
/usr/bin/nodejs: cannot execute binary file: Exec format error
sh: 1: gzip: Exec format error
node_modules/@github/copilot-linux-x64/copilot: 1: Syntax error: ")" unexpected
```

The root cause is the too strict `p_align` assumption in WSL 1 as described in [microsoft/WSL#8219-Comment1](https://github.com/microsoft/WSL/issues/8219#issuecomment-1094123281) and the initial solution is to modify the `p_align` in ELF as described in [microsoft/WSL#8219-Comment2](https://github.com/microsoft/WSL/issues/8219#issuecomment-1133936081).  
