<a name="readme-top"></a>
<!-- PROJECT LOGO -->
<br />
<div align="center">
  <a href="https://github.com/alpine-sec/thevlad">
    <img width="488" alt="thevlad" src="https://github.com/alpine-sec/thevlad/blob/main/images/thevlad_logo.png">
  </a>
  <h3 align="center">THEVLAD: Remote execution and triage tool via EDRs API</h3>

  <p align="center">
    Analysis-oriented command line tool for remote execution and triage via EDRs API
  </p>
</div>

<!-- TABLE OF CONTENTS -->
<details>
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a></li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#examples">Examples</a></li>
    <li><a href="#Microsoft defender XDR">Microsoft Defender XDR</a></li>
    <li><a href="#roadmap">Roadmap</a></li>
    
  </ol>
</details>


<!-- ABOUT THE PROJECT -->
## About The Project

The goal of this project is to create a unique tool that allows easy execution of tools and collection of outputs remotely using the APIs available in current EDR/XDRs and abstracting from the manufacturer.

This allows researchers to execute their own tools or interact with EDRs from their own scripts and tools in a simple way.

And of course... just for fun!

<!-- USAGE EXAMPLES -->
## Usage
[**DOWNLOAD EXECUTABLE**](https://github.com/alpine-sec/thevlad/releases/latest)

**Copy portable executable of **TheVlad** to the investigator machine where you want to perform the analysis, execution or triage**

### Command Line Options
```
vlad.py [-h] [-V] -c CLIENT -v VENDOR [-l LIST_ENDPOINTS] [-s SEARCH_ENDPOINTS] [-x BASE64_COMMAND] [-m MACHINEID] [-b BINARY] [-d DOWNLOAD_FILE] [-f FORCE_EXECUTION]

```

<!-- EXAMPLES -->
## Examples

### Download of a file via Microsoft Defender XDR API
```
python3 vlad.py -c XXXXXX -v MDATP -m XXXXXX -d C:\Users\XXXXXX\Desktop\POC.png -f
```
![image](https://github.com/alpine-sec/thevlad/assets/129158763/8a8701f7-d81d-47c1-b847-08bac177ff2d)

### Procdump remote execution via Microsoft Defender XDR API
```
python3 vlad.py -c XXXXXX -v MDATP -m XXXXXX -b C:\Users\XXXXXX\Downloads\Procdump\procdump.exe -x U3RhcnQtUHJvY2VzcyAtRmlsZVBhdGggInByb2NkdW1wIiAtQXJndW1lbnRMaXN0ICItYWNjZXB0ZXVsYSAtbWEgNTU4NCAgQzpcIg== -f
```
![image](https://github.com/alpine-sec/thevlad/assets/129158763/195cedbc-201d-4ba8-a504-4c879b9839b1)
![image](https://github.com/alpine-sec/thevlad/assets/129158763/85eee1c2-490f-4e68-b015-7a51d52b7658)

<!-- MICROSOFT DEFENDER XDR -->
## Microsoft defender XDR
<!-- LIVE RESPONSE LIMITATIONS -->
### Live response requirements and limitations
#### Requirements ####
**Devices must be running one of the following:**
- Windows 11
- Windows 10
  - Version 1909 or later
  - Version 1903 with KB4515384
  - Version 1809 (RS 5) with KB4537818
  - Version 1803 (RS 4) with KB4537795
  - Version 1709 (RS 3) with KB4537816
- Windows Server 2019 - Only applicable for Public preview
  - Version 1903 or (with KB4515384) later
  - Version 1809 (with KB4537818)
- Windows Server 2022
- macOS (_Additional configuration profiles:_ https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/microsoft-defender-endpoint-mac?view=o365-worldwide)
  - 13 (Ventura)
  - 12 (Monterey)
  - 11 (Big Sur)
- Linux (_Supported Linux server distributions and kernel versions:_ https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/microsoft-defender-endpoint-linux?view=o365-worldwide)
**Microsoft 365 Defender Portal Features Required **
![image](https://github.com/alpine-sec/thevlad/assets/129158763/c7442f18-edfa-433c-b313-b691a177d703)


#### Live response limitations ####
- 25 response sessions at a time
- Idle time for a session is 30 minutes.
- Individual live response commands have a time limit of 10
- Getfile, findfile and run have a limit of 30 minutes
- A single user can initiate 10 concurrent sessions
- A device can only be in one session

**The following file size limits are applicable:**
   - getfile limit: 3 GB
   - fileinfo limit: 30 GB
   - library limit: 250 MB

_Source:_ https://jeffreyappel.nl/how-to-troubleshoot-live-response-in-defender-for-endpoint/

<!-- LIVE RESPONSE LIMITATIONS -->
### Microsoft Defender XDR Limitations
   - 10 calls per minute limit
   - 25 concurrently running sessions
   - RunScript timeout after 10 minutes
   - Live response commands can’t be queued up and can only be executed one at a time.
   - Multiple live response commands can be run on a single API call. However, when a live response command fails all the subsequent actions won’t be executed.
   - When RBAC grouping is enabled the automated remediation level must be assigned, at least with a minimum Remediation Level
   - Multiple live response sessions can’t be executed on the same machine

_More Info:_ https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/api/run-live-response?view=o365-worldwide

<!-- ROADMAP -->
## Roadmap

- [ ] Add real-life scenarios
- [ ] Add SentinelOne Support
- [ ] Add Crowdstrike Support
- [ ] Add Cortex Support
- [ ] Add TrendMicro Vision One Support


<p align="right">(<a href="#readme-top">back to top</a>)</p>


