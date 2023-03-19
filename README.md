WIP

Библиотека для работы с Cryptopro CSP в Rust.

Установка зависимостей:
```bash
apt install g++ lsb-base alien lsb-core
cd cpcsp
./install.sh
alien -kci lsb-cprocsp-devel-4.0.0-4.noarch.rpm cprocsp-pki-2.0.0-amd64-cades.rpm
cd /opt/cprocsp/lib/amd64/
ln -s libcades.so.2 libcades.so
ldd libcades.so
```
