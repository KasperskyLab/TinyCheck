# TinyCheck

![Architecture](/assets/network-home.png)

### Description

TinyCheck allows you to easily capture network communications from a smartphone or any device which can be associated to a Wi-Fi access point in order to quickly analyze them. This can be used to check if any suspect or malicious communication is outgoing from a smartphone, by using heuristics or specific Indicators of Compromise (IoCs).

The idea of TinyCheck emerged in a meeting about stalkerware with a [French women's shelter](https://www.centre-hubertine-auclert.fr). During this meeting we talked about how to easily detect [stalkerware](https://stopstalkerware.org/) without installing very technical apps nor doing forensic analysis on the victim's smartphone. The initial concept was to develop a tiny kiosk device based on Raspberry Pi which can be used by non-tech people to test their smartphones against malicious communications issued by stalkerware or any spyware.

Of course, TinyCheck can also be used to spot any malicious communications from cybercrime to state-sponsored implants. It allows the end-user to push their own extended Indicators of Compromise via a backend in order to detect some ghosts over the wire.

<p align="center"><strong>If you need more documentation on how to install it, use it and the internals, don't hesitate to take a look at the <a href="https://github.com/KasperskyLab/TinyCheck/wiki">TinyCheck Wiki</a>.</strong></p>

<p align="center">If you have any question about the project, want to contribute or just send your feedback, <br />don't hesitate to contact us at tinycheck[@]kaspersky[.]com.</p>

### Use cases

TinyCheck can be used in several ways by individuals and entities:

- Over a network - TinyCheck is installed on a network and can be accessed from a workstation via a browser.
- In kiosk mode - TinyCheck can be used as a kiosk to allow visitors to test their own devices.
- Fully standalone - By using a powerbank, two Wi-Fi interfaces or a 4G dongle and a small touch screen [like in this video](https://twitter.com/felixaime/status/1331535790392946689), you can tap any device anywhere.

### Installation

Please check the few steps in the [Wiki's Installation Page](https://github.com/KasperskyLab/TinyCheck/wiki/TinyCheck-installation). 

### Meet the frontend

The frontend - which can be accessed from `http://tinycheck.local` is a kind of tunnel which help the user throughout the process of network capture and reporting. It allows the user to setup a Wi-Fi connection to an existing Wi-Fi network, create an ephemeral Wi-Fi network, capture the communications and show a report to the user... in less than one minute, 5 clicks and without any technical knowledge. 

![Frontend](/assets/frontend.png)

### Meet the backend

Once installed, you can connect yourself to the TinyCheck backend by browsing the URL `https://tinycheck.local` and accepting the SSL self-signed certificate. 

![Backend](/assets/backend.png)

The backend allows you to edit the configuration of TinyCheck, add extended IOCs and whitelisted elements in order to prevent false positives. Several IOCs are already provided such as few suricata rules, FreeDNS, Name servers, CIDRs known to host malicious servers and so on.

### Special thanks

**Guys who provided some IOCs**
- [Cian Heasley](https://twitter.com/nscrutables) for his android stalkerwares IOC repo, available here: https://github.com/diskurse/android-stalkerware
- [Te-k](https://twitter.com/tenacioustek) for his stalkerwares awesome IOCs repo, available here: https://github.com/Te-k/stalkerware-indicators
- [Emilien](https://twitter.com/__Emilien__) for his Stratum rules, available here: https://github.com/kwouffe/cryptonote-hunt
- [Costin Raiu](https://twitter.com/craiu) for his geo-tracker domains, available here: https://github.com/craiu/mobiletrackers/blob/master/list.txt

**Code review**
- Dan Demeter [@_xdanx](https://twitter.com/_xdanx)
- Maxime Granier
- Florian Pires [@Florian_Pires](https://twitter.com/Florian_Pires)
- Ivan Kwiatkowski [@JusticeRage](https://twitter.com/JusticeRage)

**Others**
- GReAT colleagues.
- Tatyana, Kristina, Christina and Arnaud from Kaspersky (Support and IOCs)
- Zeek and Suricata awesome maintainers.
- virtual-keyboard.js.org & loading.io guys.
- Yan Zhu for his awesome Spectre CSS lib (https://picturepan2.github.io/spectre/)
