# [Awesome-anti-forensic](https://github.com/shadawck/Awesome-anti-forensic)

[![Awesome](https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg)](https://github.com/sindresorhus/awesome)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](http://makeapullrequest.com)
[![License](https://img.shields.io/badge/LICENSE-CC_BY_4.0-00a2ff?&style=flat-square)](https://creativecommons.org/licenses/by/4.0/)

Tools and packages that are used for countering forensic activities, including encryption, steganography, and anything that modify attributes. This all includes tools to work with anything in general that makes changes to a system for the purposes of hiding information.

## Tools

### System/Digital Image

- [Afflib](https://github.com/sshock/AFFLIBv3): An extensible open format for the storage of disk images and related forensic.information.
- [Air-Imager](https://sourceforge.net/projects/air-imager/): A GUI front-end to dd/dc3dd designed for easily creating forensic images.
- [Bmap-tools](https://github.com/intel/bmap-tools): Tool for copying largely sparse files using information from a block map file.
- [dd](): The dd command allows you to copy all or part of a disk.
  - [Dc3dd](https://doc.ubuntu-fr.org/dc3dd): A patched version of dd that includes a number of features useful for computer forensics.
  - [Dcfldd](https://doc.ubuntu-fr.org/dcfldd): DCFL (DoD Computer Forensics Lab), a dd replacement with hashing.
- [ddrescue](https://doc.ubuntu-fr.org/ddrescue): GNU data recovery tool.
- [Dmg2img](https://github.com/Lekensteyn/dmg2img): A CLI tool to uncompress Apple's compressed DMG files to the HFS+ IMG format.
- [Frida](https://github.com/frida/frida): Dynamic instrumentation toolkit for developers, reverse-engineers, and security researchers.
  - [Fridump](https://github.com/Nightbringer21/fridump): A universal memory dumper using Frida.
- [Imagemounter](https://github.com/ralphje/imagemounter): Command line utility and Python package to ease the (un)mounting of forensic disk images.

### Recovering tool / Memory Extraction

- [Extundelete](http://extundelete.sourceforge.net/): Utility for recovering deleted files from ext2, ext3 or ext4 partitions by parsing the journal.
- [Foremost](https://github.com/korczis/foremost): A console program to recover files based on their headers, footers, and internal data structures.
- [MagicRescue](https://github.com/jbj/magicrescue): Find and recover deleted files on block devices.
- [MemDump](https://github.com/kost/memdump): Dumps system memory to stdout, skipping over holes in memory maps.
- [MemFetch](https://github.com/citypw/lcamtuf-memfetch): Simple utility that can be used to dump process memory of any userspace process running on the system without affecting its execution.
- [Mxtract](https://github.com/rek7/mXtract): Memory Extractor & Analyzer.
- [Recoverjpeg](https://github.com/samueltardieu/recoverjpeg): Recover jpegs from damaged devices.
- [SafeCopy](https://doc.ubuntu-fr.org/safecopy): A disk data recovery tool to extract data from damaged media.
- [Scrounge-Ntfs](https://github.com/lcorbasson/scrounge-ntfs): Data recovery program for NTFS file systems.
- [TestDisk & PhotoRec](https://github.com/cgsecurity/testdisk): TestDisk checks the partition and boot sectors of your disks. It is very useful in recovering lost partitions. PhotoRec is file data recovery software designed to recover lost pictures from digital camera memory or even hard disks. It has been extended to search also for non audio/video headers.

### Analysis / Gathering tool (Know your ennemies)

- [Autopsy](https://github.com/sleuthkit/autopsy): The forensic browser. A GUI for the Sleuth Kit.
- [Bulk-extractor](https://github.com/simsong/bulk_extractor): Bulk Email and URL extraction tool.
- [captipper](https://github.com/omriher/CapTipper): Malicious HTTP traffic explorer tool.
- [Chromefreak](https://github.com/OsandaMalith/ChromeFreak): A Cross-Platform Forensic Framework for Google Chrome.
- [SkypeFreak](https://github.com/OsandaMalith/SkypeFreak): A Cross Platform Forensic Framework for Skype.
- [Dumpzilla](https://github.com/Busindre/dumpzilla): A forensic tool for firefox.
- [Emldump](https://github.com/DidierStevens/DidierStevensSuite/blob/master/emldump.py): Analyze MIME files.
- [Galleta](https://sourceforge.net/projects/odessa/files/Galleta/): Examine the contents of the IE's cookie files for forensic purposes.
- [Guymager](https://guymager.sourceforge.io/): A forensic imager for media acquisition.
- [Indxparse](https://github.com/williballenthin/INDXParse): A Tool suite for inspecting NTFS artifacts.
- [IOSforensic](https://github.com/Flo354/iOSForensic): iOS forensic tool.
- [IPBA2](https://github.com/PicciMario/iPhone-Backup-Analyzer-2): IOS Backup Analyzer.
- [Iphoneanalyzer](https://github.com/foreni-packages/iphoneanalyzer): Allows you to forensically examine or recover date from in iOS device.
- [LiMEaide](https://github.com/kd8bny/LiMEaide): Remotely dump RAM of a Linux client and create a volatility profile for later analysis on your local host.
- [MboxGrep](https://sourceforge.net/projects/mboxgrep/): A small, non-interactive utility that scans mail folders for messages matching regular expressions. It does matching against basic and extended POSIX regular expressions, and reads and writes a variety of mailbox formats.
- [Mobiusft](https://www.nongnu.org/mobiusft/): An open-source forensic framework written in Python/GTK that manages cases and case items, providing an abstract interface for developing extensions.
- [Naft](https://blog.didierstevens.com/programs/network-appliance-forensic-toolkit/): Network Appliance Forensic Toolkit.  
[Networkminer](https://www.netresec.com/?page=Networkminer) A Network Forensic Analysis Tool for advanced Network Traffic Analysis, sniffer and packet analyzer.
- [Nfex](https://github.com/deadbits/nfex): A tool for extracting files from the network in real-time or post-capture from an offline tcpdump pcap savefile.
[Ntdsxtract](https://github.com/csababarta/ntdsxtract) [windows]: Active Directory forensic framework.
- [Pasco](http://b2b-download.mcafee.com/products/tools/foundstone/pasco.zip): Examines the contents of Internet Explorer's cache files for forensic purposes.                                          |
- [PcapXray](https://github.com/Srinivas11789/PcapXray): Network Forensics Tool - To visualize a Packet Capture offline as a Network Diagram including device identification, highlight important communication and file extraction
- [ReplayProxy](https://github.com/sparrowt/replayproxy): Forensic tool to replay web-based attacks (and also general HTTP traffic) that were captured in a pcap file.
- [Pdfbook-analyzer](https://sourceforge.net/projects/pdfbook/): Utility for facebook memory forensics.
- [Pdfid](https://github.com/DidierStevens/DidierStevensSuite/blob/master/pdfid.py): Scan a file to look for certain PDF keywords.
- [PdfResurrect](https://github.com/enferex/pdfresurrect): A tool aimed at analyzing PDF documents.  
- [Peepdf](https://github.com/jesparza/peepdf): A Python tool to explore PDF files in order to find out if the file can be harmful or not.
- [Pev](https://github.com/merces/pev): Command line based tool for PE32/PE32+ file analysis.
- [Rekall](https://github.com/google/rekall): Memory Forensic Framework.
- [Recuperabit](https://github.com/Lazza/RecuperaBit): A tool for forensic file system reconstruction.  
- [Rifiuti2](https://github.com/abelcheung/rifiuti2): A rewrite of rifiuti, a great tool from Foundstone folks for analyzing Windows Recycle Bin INFO2 file.
- [Rkhunter](http://rkhunter.sourceforge.net/): Checks machines for the presence of rootkits and other unwanted tools.
- [Sleuthkit](https://github.com/sleuthkit/sleuthkit): A library and collection of command line digital forensics tools that allow you to investigate volume and file system data.
- [Swap-digger](https://github.com/sevagas/swap_digger): A tool used to automate Linux swap analysis during post-exploitation or forensics.
- [Vinetto](https://sourceforge.net/projects/vinetto/): A forensics tool to examine Thumbs.db files.
- [Volafox](https://github.com/n0fate/volafox): macOS Memory Analysis Toolkit.
- [Volatility](https://github.com/volatilityfoundation/volatility): Advanced memory forensics framework.
- [Xplico](https://github.com/xplico/xplico): Internet Traffic Decoder. Network Forensic Analysis Tool (NFAT).

### Data tampering

- [Exiftool](https://github.com/qazbnm456/awesome-web-security): Reader and rewriter of EXIF informations that supports raw files.
- [Exiv2](https://github.com/Exiv2/exiv2): Exif, Iptc and XMP metadata manipulation library and tools.
- [nTimetools](https://github.com/limbenjamin/nTimetools): Timestomper and Timestamp checker with nanosecond accuracy for NTFS volumes.
- [Scalpel](https://github.com/sleuthkit/scalpel): An open source data carving tool.
- [SetMace](https://github.com/jschicht/SetMace): Manipulate timestamps on NTFS.

### Hiding process

- [Harness](https://github.com/droberson/harness): Execute ELFs in memory.
- [Unhide](http://www.unhide-forensics.info/?Linux:Download): A forensic tool to find processes hidden by rootkits, LKMs or by other techniques.  
- [Kaiser](https://github.com/ntraiseharderror/kaiser): File-less persistence, attacks and anti-forensic capabilities (Windows 7 32-bit).  
- [Papa Shango](https://github.com/droberson/papa-shango): Inject code into running processes with ptrace().
- [Saruman](https://github.com/elfmaster/saruman): ELF anti-forensics exec, for injecting full dynamic executables into process image (With thread injection).

### Cleaner / Data Destruction / Wiping / FileSystem

- [BleachBit](https://github.com/bleachbit/bleachbit): System cleaner for Windows and Linux.
- [ChainSaw](https://github.com/Inffinite/ChainSaw): ChainSaw automates the process of shredding log files and bash history from a system. It is a tool that cleans up the bloody mess you left behind when you went for a stroll behind enemy lines.
- [Clear-EventLog](https://learn.microsoft.com/powershell/module/microsoft.powershell.management/clear-eventlog?view=powershell-5.1): Powershell Command. Clears all entries from specified event logs on the local or remote computers.
- [DBAN](https://sourceforge.net/projects/dban/): Darik's Boot and Nuke ("DBAN") is a self-contained boot image that securely wipes the hard disks of most computers. DBAN is appropriate for bulk or emergency data destruction.
- [Hdpram](https://doc.ubuntu-fr.org/hdparm): get/set hard disk parameters.
- [LogKiller](https://github.com/Rizer0/Log-killer): Clear all your logs in linux/windows servers.
- [Meterpreter > clearev](https://github.com/rapid7/metasploit-payloads): The meterpreter clearev command will clear the Application, System, and Security logs on a Windows system.
- [NTFS-3G](https://github.com/tuxera/ntfs-3g): NTFS-3G Safe Read/Write NTFS Driver.
- [Nuke My LUKS](https://github.com/juliocesarfort/nukemyluks): Network panic button designed to overwrite with random data the LUKS header of computers in a LAN.
- [Permanent-Eraser](https://github.com/edenwaith/Permanent-Eraser): Secure file erasing utility for macOS.
- [Shred](https://doc.ubuntu-fr.org/shred): Overwrite a file to hide its contents, and optionally delete it.
- [Silk-guardian](https://github.com/NateBrune/silk-guardian): An anti-forensic kill-switch that waits for a change on your usb ports and then wipes your ram, deletes precious files, and turns off your computer.
- [Srm](https://sourceforge.net/projects/srm/): Srm is a command-line compatible rm which overwrites file contents before unlinking.
- [Wipe](https://github.com/berke/wipe): A Unix tool for secure deletion.
- [Wipedicks](https://github.com/Drewsif/wipedicks): Wipe files and drives securely with randoms ASCII dicks.
- [wiper](https://github.com/r3nt0n/wiper): Toolkit to perform secure destruction of sensitive virtual data, temporary files and swap memories.

### Password and Login

- [chntpw](https://doc.ubuntu-fr.org/tutoriel/chntpw): Offline NT Password Editor - reset passwords in a Windows NT SAM user database file.
- [lazagne](https://github.com/AlessandroZ/LaZagne): An open source application used to retrieve lots of passwords stored on a local computer.
- [Mimipenguin](https://github.com/huntergregal/mimipenguin): A tool to dump the login password from the current linux user.

### Encryption / Obfuscation

- [BurnEye](https://github.com/packz/binary-encryption/tree/master/binary-encryption/burneye-stripped): ELF encryption program.
- [cryptsetup](https://gitlab.com/cryptsetup/cryptsetup): Utility used to conveniently set up disk encryption based
on the DMCrypt kernel module.
  - [cryptsetup-nuke-password](https://salsa.debian.org/pkg-security-team/cryptsetup-nuke-password) : Configure a special "nuke password" that
    can be used to destroy the encryption keys required to unlock the encrypted partitions.
- [ELFcrypt](https://github.com/droberson/ELFcrypt): ELF crypter.
- [FreeOTFE](https://sourceforge.net/projects/freeotfe.mirror/): A free "on-the-fly" transparent disk encryption program for PC & PDAs.
- [Midgetpack](https://github.com/arisada/midgetpack): Midgetpack is a multiplatform secure ELF packer.
- [panic_bcast](https://github.com/niklasfemerstrand/panic_bcast) : Decentralized opsec panic button operating over UDP broadcasts and HTTP. Provides automatic ejection of encrypted drives as a safe-measure against cold-boot attacks.
- [Sherlocked](https://github.com/elfmaster/sherlocked): Universal script packer-- transforms any type of script into a protected ELF executable, encrypted with anti-debugging.
  - [suicideCrypt](https://github.com/MonolithInd/suicideCrypt) : A toolset for creating cryptographically strong volumes that destroy themselves upon tampering (event) or via issued command.
- [Tchunt-ng](https://github.com/antagon/TCHunt-ng): Reveal encrypted files stored on a filesystem.
- [TrueHunter](https://github.com/adoreste/truehunter): Detect TrueCrypt containers using a fast and memory efficient approach.

### Policies / Logging (Event) / Monitoring

- [Auditpol](https://docs.microsoft.com/en-gb/windows-server/administration/windows-commands/auditpol): Displays information about and performs functions to manipulate audit policies in Windows.
- [evtkit](https://github.com/yarox24/evtkit): Fix acquired .evt - Windows Event Log files (Forensics) [windows]
- [Grokevt](https://github.com/ecbftw/grokevt): A collection of scripts built for reading Windows® NT/2K/XP/2K eventlog files. [windows]
- [Lfle](https://github.com/williballenthin/LfLe): Recover event log entries from an image by heurisitically looking for record structures.  
- [python-evtx](https://github.com/williballenthin/python-evtx): A tool to parse the Windows XML Event Log (EVTX) format.
- [USBGuard](https://usbguard.github.io/): Software framework for implementing USB device authorization policies (what kind of USB devices are authorized) as well as method of use policies (how a USB device may interact with the system).
- [wecutil](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wecutil): Enables you to create and manage subscriptions to events that are forwarded from remote computers. The remote computer must support the WS-Management protocol. [windows]
- [Wevtutil](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil): Enables you to retrieve information about event logs and publishers. You can also use this command to install and uninstall event manifests, to run queries, and to export, archive, and clear logs (windows server).

### Steganography

- [AudioStego](https://github.com/danielcardeenas/AudioStego): Hides text or files inside audio files and retrieve them automatically.
- [ChessSteg](https://github.com/jes/chess-steg): Steganography in chess games.
- [Cloakify](https://github.com/TryCatchHCF/Cloakify): Transforms any filetype into a list of harmless-looking strings. This lets you hide the file in plain sight, and transfer the file without triggering alerts.
- [Jsteg](https://github.com/lukechampine/jsteg): jsteg is a package for hiding data inside jpeg files.
- [Mp3nema](https://github.com/enferex/mp3nema): A tool aimed at analyzing and capturing data that is hidden between frames in an MP3 file or stream, otherwise noted as "out of band" data.
- [PacketWhisper](https://github.com/TryCatchHCF/PacketWhisper): Stealthily exfiltrate data and defeat attribution using DNS queries and text-based steganography.
- [steg86](https://github.com/woodruffw/steg86): Format-agnostic steganographic tool for x86 and AMD64 binaries. You can use it to hide information in compiled programs, regardless of executable format (PE, ELF, Mach-O, raw, &c).
- [steganography](https://github.com/7thSamurai/steganography): Simple C++ Image Steganography tool to encrypt and hide files insde images using Least-Significant-Bit encoding.
- [Steganography](https://github.com/ragibson/Steganography): Least Significant Bit Steganography for bitmap images (.bmp and .png), WAV sound files, and byte sequences.
- [StegaStamp](https://github.com/tancik/StegaStamp):  Invisible Hyperlinks in Physical Photographs.
- [StegCloak](https://github.com/KuroLabs/stegcloak): Hide secrets with invisible characters in plain text securely using passwords.
- [Stegdetect](https://github.com/abeluck/stegdetect): Automated tool for detecting steganographic content in images.
- [StegFS](https://github.com/albinoloverats/stegfs): A FUSE based steganographic file system.
- [Steghide](http://steghide.sourceforge.net/): Steganography program that is able to hide data in various kinds of image- and audio-files.
- [Stegify](https://github.com/DimitarPetrov/stegify): Go tool for LSB steganography, capable of hiding any file within an image.
- [Stego](https://github.com/ajmwagar/stego):  stego is a steganographic swiss army knife.
  - [StegoGAN](https://github.com/DAI-Lab/SteganoGAN) : A tool for creating steganographic images using adversarial training.
- [stego-toolkit](https://github.com/DominicBreuker/stego-toolkit): This project is a Docker image useful for solving Steganography challenges as those you can find at CTF platforms.
- [StegoVeritas](https://github.com/bannsec/stegoVeritas):  Yet another Stego Tool.
- [tweetable-polyglot-png](https://github.com/DavidBuchanan314/tweetable-polyglot-png): Pack up to 3MB of data into a tweetable PNG polyglot file.

### Malware / AV

- [Malheur](https://github.com/rieck/malheur): A tool for the automatic analyze of malware behavior.
- [MalwareDetect](https://github.com/rfxn/linux-malware-detect): Submits a file's SHA1 sum to VirusTotal to determine whether it is a known piece of malware.

### OS/VM

- [HiddenVM](https://github.com/aforensics/HiddenVM): Use any desktop OS without leaving a trace.  
- [Tails](https://tails.boum.org/index.en.html): portable operating system that protects against surveillance and censorship.

### Hardware

- [BusKill](https://github.com/BusKill/buskill-app): BusKill is an hardware and software project that uses a hardware tripwire/dead-man-switch to trigger a computer to lock or shutdown if the user is physically separated from their machine.
- [Day Tripper](https://github.com/dekuNukem/daytripper) :  Hide-My-Windows Laser Tripwire.
- [DoNotDisturb](https://github.com/objective-see/DoNotDisturb) : Security tool for macOS that aims to detect unauthorized physical access to your laptop.
- [Silk Guardian](https://github.com/NateBrune/silk-guardian) : Anti-forensic kill-switch that waits for a change on your usb ports and then wipes your ram, deletes precious files, and turns off your computer.
- [USB Kill](https://github.com/hephaest0s/usbkill) : Anti-forensic kill-switch that waits for a change on your USB ports and then immediately shuts down your computer.
- [USB Death](https://github.com/trpt/usbdeath) : Anti-forensic tool that writes udev rules for known usb devices and do some things at unknown usb insertion or specific usb device removal.
- [xxUSBSentinel](https://github.com/thereisnotime/xxUSBSentinel) :  Windows anti-forensics USB monitoring tool.

### Android App

- [Lockup](https://github.com/levlesec/lockup) : A proof-of-concept Android application to detect and defeat some of the Cellebrite UFED forensic toolkit extraction techniques.
- [Ripple](https://github.com/guardianproject/ripple) : A "panic button" app for triggering a "ripple effect" across apps that are set up to respond to panic events.

## Contributing

Thanks for visiting ! If you have suggestions, then open an issue, or submit a PR. Contributions are welcome, and much appreciated !

## License

[![License](https://img.shields.io/badge/LICENSE-CC_BY_4.0-00a2ff)](https://creativecommons.org/licenses/by/4.0/)
Licensed under Creative Commons, CC BY 4.0, © [HUGUET Rémi @shadawck](https://github.com/shadawck) 2022
