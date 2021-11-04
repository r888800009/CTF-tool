# CTF-tool
[toc]

## Start

```
./exploiting
```

## Dependencies

- iPython (Optional)
- docker
- pwntools

## Web

### SQL encoder

```
>>> sql.mysql.concat('asd')
'concat(0x61,0x73,0x64)'
```

## PWN
- `test_pwn_heap_rwx.cpp` 用來檢查 mappings
  - heap 能否執行和 kernel 版本有關聯
  - 如果採用 docker 需要注意 host kernel
- [Old Ubuntu Releases](http://old-releases.ubuntu.com/releases/)

### todo

- [ ] format string leak analyser
  - [ ] find Leak return address and %?$p location
  - [ ] [格式化字串攻擊 (Format String Attack) | r809's Notes](https://r888800009.github.io/software/security/binary/format-string-attack/#%E5%A6%82%E4%BD%95%E5%BF%AB%E9%80%9F%E6%89%BE%E5%88%B0-p-%E5%9C%A8%E8%A8%98%E6%86%B6%E9%AB%94%E4%B8%8A%E9%9D%A2%E7%9A%84%E4%BD%8D%E7%BD%AE)
- [ ] `exploit.py` template
- [ ] Predefined hook function for angr an triton

## Sensitive Path

Todo

- Auto-gen payload reading

```
/proc/pid/*
```

## Docker

- `pwn_docker/`

```bash
cd pwn_docker/
docker build . -t ctf_ubuntu1804 --target ctf
docker run --rm -it ctf_ubuntu1804 /bin/bash

# only devtools
docker build . -t ubuntu1804 --target basic
docker build . -t ubuntu_latest --target basic --build-arg VERSION=latest

# ubuntu 20.04
docker build . -t ctf_ubuntu2004 --target ctf --build-arg VERSION=20.04

# latest
docker build . -t ctf_ubuntu_latest --target ctf --build-arg VERSION=latest

```

check ubuntu version
```bash
docker run --rm -it ctf_ubuntu1804 cat /etc/os-releas
docker run --rm -it ctf_ubuntu1804 cat /etc/os-releasee
docker run --rm -it ctf_ubuntu_latest cat /etc/os-release
```
