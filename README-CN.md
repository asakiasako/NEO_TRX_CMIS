# TRX CMIS

TRX CMIS 用于控制和操作基于 CMIS 协议的一系列 Transceiver，包括: QSFP-DD， OSFP。

## 基本使用方法

``` python
from trx_cmis import TRX_MAP
trx = TRX_MAP['QSFP-DD'](ip='xxx.xxx.xxx.xxx')
# CMIS 规定的标准操作，参考 /cmis/README_CN.md
trx[0xFF] = 0x11
trx[0x7F].to_signed()
trx[0x03][7:4]
# ...
# 通过 dut 的属性访问 EVB 对象和 components 对象
trx.adc.get(key)
trx.dac.set(key, val)
trx.evb.set_fan_speed(val)
```
