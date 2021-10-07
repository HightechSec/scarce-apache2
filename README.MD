
# ScaRCE Framework - CVE-2021-41773 Hunter
[![License](https://img.shields.io/badge/license-MIT-red.svg?style=flat)](https://github.com/HightechSec/scarce-apache2/blob/master/LICENSE.md)
![Build](https://img.shields.io/badge/Supported_OS-Linux-yellow.svg?style=flat)
![Build](https://img.shields.io/badge/Supported_WSL-Windows-blue.svg?style=flat)
![GitHub code size in bytes](https://img.shields.io/github/languages/code-size/HightechSec/scarce-apache2)
![GitHub repo size](https://img.shields.io/github/repo-size/HightechSec/scarce-apache2)
![GitHub last commit](https://img.shields.io/github/last-commit/HightechSec/scarce-apache2)
![GitHub stars](https://img.shields.io/github/stars/HightechSec/scarce-apache2)
![GitHub pull requests](https://img.shields.io/github/issues-pr/HightechSec/scarce-apache2)
![GitHub forks](https://img.shields.io/github/forks/HightechSec/scarce-apache2)
![GitHub issues](https://img.shields.io/github/issues/HightechSec/scarce-apache2)
![GitHub watchers](https://img.shields.io/github/watchers/HightechSec/scarce-apache2)

This tool can scan websites with CVE-2021-41773 Vulnerability that are affecting Apache2 Webserver, ScaRCE can run too for executing Remote Command Injections at the webservers that found from the scanning method (Only if the **MOD_CGI** is Enabled at the targeted webserver). This tool works with the provided Single target or Mass Target from a file list. Only use this tool for `Bug Hunting`/ `Pentesting Purposes`.

<img src="https://raw.githubusercontent.com/HightechSec/scarce-apache2/main/img/1-scarceapache.png" width="30%"></img> <img src="https://raw.githubusercontent.com/HightechSec/scarce-apache2/main/img/2-scarceapache.png" width="30%"></img> <img src="https://raw.githubusercontent.com/HightechSec/scarce-apache2/main/img/3-scarceapache.png" width="30%"></img> 
## Installation
```
- git clone https://github.com/HightechSec/scarce-apache2
- cd scarce-apache2
- bash scarce.sh
``` 
or you can install in your system like this
```
- git clone https://github.com/HightechSec/scarce-apache2
- cd scarce-apache2
- sudo cp scarce.sh /usr/bin/scarce && sudo chmod +x /usr/bin/scarce
- $ scarce
```
## Usage
- Menu's
  - Menu `1` is for scanning LFI Vulnerability from a provided file that contains the `list of the target url` or a provided `single target url`.
  - Menu `2` is for scanning RCE Vulnerability from a provided file that contains the `list of the target url` or a provided `single target url`.
  - Menu `3` is for Executing RCE from a provided `single target url`. This will work for the `Maybe Vuln` Results or sometimes with a `500 Error Response`.  
- URL Format
  - Use ```http://``` like ```http://example.com``` or ```https://``` like ```https://example.com``` for the url formatting at Single Target usages
  - For Url or IP that has been provided from a ```List```, **Don't Use** the URL Formatting like eg:
    - https://target.com
    - http://hackerone.com
    - https://bugcrowd.com

## Requirements
* curl
* bash
* git

# Credits
Thanks to:
- [CVE-2021-41773 Reproduced](https://twitter.com/ptswarm/status/1445376079548624899) by [@ptswarm](https://twitter.com/ptswarm)
- [Executing RCE in CVE-2021-41773](https://twitter.com/hackerfantastic/status/1445531829985968137) by [@hackerfantastic](https://twitter.com/hackerfantastic) 
- [Removing 5xx Error when Running RCE](https://twitter.com/lukejahnke/status/1445560511270064138) by [@lukejahnke](https://twitter.com/lukejahnke)


