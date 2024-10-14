# CTF Framework

[toc]

CTF Framework, Save you time and exploit quickly

## Start
pwn docker
```
python3 start_docker.py 20.04
```

### r809pwn
```bash
git clone https://github.com/r888800009/CTF-tool
cd CTF-tool
pdm install
```

```python
import r809pwn.lib
```

## gdb toolbox
toolbox should run after `apogiatzis/gdb-peda-pwndbg-gef` installed

```bash
python3 ./instal_gdb_toolbox.py
```

current toolbox include
- [r888800009/gdb_toolbox](https://github.com/r888800009/gdb_toolbox)
- [0n3t04ll/OneGadgetTest](https://github.com/0n3t04ll/OneGadgetTest) [fork](https://github.com/r888800009/OneGadgetTest)

fork is backup if original repo is deleted

there are some useful tools, but not include in this repo,
- symbolic execution
  - [SQLab/symgdb](https://github.com/SQLab/symgdb) 
    - only support python2
  - [andreafioraldi/angrgdb](https://github.com/andreafioraldi/angrgdb/tree/master)
    - crash on new version angr, because of `angr` api change
- misc
  - [io12/pwninit: pwninit - automate starting binary exploit challenges](https://github.com/io12/pwninit)
    - it may be useful for finding unstrip binary, maybe
  
## Dependencies

- docker
- pwntools

## Web

### SQL encoder

```
>>> r809web.mysql.concat('asd')
'concat(0x61,0x73,0x64)'
```

### Hash Tool chains (TODO)

```python
import r809web.hash_tools
```

#### Hash Extractor (TODO)

use

```python
hash_extractor(['sensitive.html', 'sensitive.txt'])
```

a tool extract all passable hash value from html or text file,  after that can be cracked by rainbow table

- `md5`: `[0-9a-f]{32}`

ref:

- [Cheat Sheet For Password Crackers](https://gist.github.com/crunchprank/61a0ca3f6087b49fabb2)
- [A cheat-sheet for password crackers](https://www.unix-ninja.com/p/A_cheat-sheet_for_password_crackers)

#### Rainbow table searcher (TODO)

a tool search hash on rainbow table online or local database

use

```python
rainbow_table(['21232f297a57a5a743894a0e4a801fc3', 'ee11cbb19052e40b07aac0ca060c23ee'])
```

Output

```python
['admin', 'user']
```

or

```python
'could not find a hash in the databases'
```

## PWN

- `test_pwn_heap_rwx.cpp` 用來檢查 mappings
  - heap 能否執行和 kernel 版本有關聯
  - 如果採用 docker 需要注意 host kernel
- [Old Ubuntu Releases](http://old-releases.ubuntu.com/releases/)
- `./libc-extractor.sh 20.04`

### todo

- [ ] format string leak analyser
  - [ ] find Leak return address and %?$p location
  - [ ][格式化字串攻擊 (Format String Attack) | r809&#39;s Notes](https://r888800009.github.io/software/security/binary/format-string-attack/#%E5%A6%82%E4%BD%95%E5%BF%AB%E9%80%9F%E6%89%BE%E5%88%B0-p-%E5%9C%A8%E8%A8%98%E6%86%B6%E9%AB%94%E4%B8%8A%E9%9D%A2%E7%9A%84%E4%BD%8D%E7%BD%AE)
- [ ] `exploit.py` template
- [ ] Predefined hook function for angr an triton

## Fuzzer
- [r888800009/afl-darwin-dockerfile](https://github.com/r888800009/afl-darwin-dockerfile)

## Sensitive Path

Todo

- Auto-gen payload reading

```
/proc/pid/*
```

## Docker

- `pwn_docker/`
  - `./setup_docker.sh 20.04`

Build docker

```bash
cd pwn_docker/
docker build . -t ctf_ubuntu1804 --target ctf

# only devtools
docker build . -t ubuntu1804 --target basic
docker build . -t ubuntu_latest --target basic --build-arg VERSION=latest

# ubuntu 20.04
docker build . -t ctf_ubuntu2004 --target ctf --build-arg VERSION=20.04

# latest
docker build . -t ctf_ubuntu_latest --target ctf --build-arg VERSION=latest
```

Run docker

```bash
docker run --rm -it ctf_ubuntu1804 /bin/bash
docker run --rm -it -v $(pwd):/work ctf_ubuntu_latest bash
```

check ubuntu version

```bash
docker run --rm -it ctf_ubuntu1804 cat /etc/os-release
docker run --rm -it ctf_ubuntu2004 cat /etc/os-release
docker run --rm -it ctf_ubuntu_latest cat /etc/os-release
```

Maybe need `--cap-add=SYS_PTRACE `
