# Allwinner A20's eMMC to USB firmware dumper

Should work for other u-boot running devices, but has only been tested on Allwinner A20.

The retry logic is generally unnecessary if one uses an appropriate pendrive that does not
trigger USB bus errors such as the dreaded ones below:

```
(...)
Sending: mmc read 0x42000000 0x18F00 0x100
Sending: usb write 0x42000000 0x18F00 0x100
Sending: mmc read 0x42000000 0x19000 0x100
Sending: usb write 0x42000000 0x19000 0x100
(stops)
^C

(...)
usb write: device 0 block # 102400, count 256 ... EHCI timed out on TD - token=0xd0008c80
```
