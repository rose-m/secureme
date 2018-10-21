# secureme

*secureme* aims to be a little utility running in the background and detecting simple but common attacks used especially in public WiFis.

Some of the modules makes use of the great [Scapy](https://scapy.net/) library.

> *Note: This is HEAVY WIP*


## Detection Modules

The currently implemented detection modules cover:

- *ARP spoofing*: Alerts when unexpected ARP Replies are detected.
- *MITM Proxy*: Tries to detect an HTTPS mitigating MITM proxy by doing certificate pinning on `https://www.google.com`
- *Deauth Attacks*: **NOT WORKING** - requires monitor mode to detect unexpected WiFi deauth packets

## Next Steps

My goal is to implement a basic app on top of those modules (my target: macOS) that offers a nice seamless integration and usability - like running in the menubar and giving notifications on alert events. How to do that? - No idea, yet.