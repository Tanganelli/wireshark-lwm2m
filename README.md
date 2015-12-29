# wireshark-lwm2m
Lua script to dissect the TLV encoding used by LWM2M.

## Requirements

- Wireshark with Lua support: 
    - start Wireshark and click on Help in the menubar and then on About Wireshark
    - search for something similar to :

> Compiled (64-bit) with Qt 5.3.2, with libpcap, without POSIX capabilities, with
>libz 1.2.3, with GLib 2.36.0, with SMI 0.4.8, without c-ares, without ADNS, with
>**Lua 5.2**, with GnuTLS 2.12.19, with Gcrypt 1.5.0, with MIT Kerberos, with GeoIP,
>without PortAudio, with AirPcap.

## Install
Locate the Personal Plugins directories. To do this, start Wireshark and click on **Help** in the menubar and then on **About Wireshark**. This should bring up the About Wireshark dialog. From there, navigate to the **Folders** tab. Locate folders **Personal Plugins** and note its paths.
> on Linux and MacOS: ~/.wireshark/plugins (if plugins doesn't exist, create it)

Put the **lwm2m.lua** file inside the **Personal Plugins** folder.

Restart Wireshark.

## Known issues

- Wireshark will try to decode as TLV all CoAP packets, if the payload is not in the TLV encoding an error will be displayed in the wireshark dissector tree, however the CoAP dissector will still work as usual.
