# EZ file cloud 1.2

A password-free file inbox on your trusted local network. One standard-library
Python 3 script runs the Pi/Linux/macOS receiver and Mac/Linux/Windows senders.
No Python packages, account or admin install needed. Python 3 must already be
available on each device.

## Important privacy limit

No passwords and no encryption. **Any allowed LAN device can upload, list and
download files in any username folder.** A username is a folder label, not an
account or proof of ownership. Use only for files you are comfortable making
available to other people/devices on that network. Secure internet access does
not make other LAN devices trusted. Do not port-forward, proxy, VPN-forward or
expose this app through Cloudflare, remote.it or another tunnel. There is no
remote deletion feature.

## Start the receiver (Pi terminal)

Save the updated `ezfilecloud.py` in /root, then run:

```text
python3 ezfilecloud.py receive
```

Files appear in `/root/EZ-file-cloud/USERNAME/`. Existing files from version 1.0
remain usable. Stop the old receiver with Ctrl+C before starting the new one.
Keep the receiver terminal open. No service or system setting is installed.

## Send files (Mac/Linux terminal)

Save the same updated script in a folder your terminal can access. For example,
use ~/CrunchByte on a Mac, then:

```text
cd ~/CrunchByte
python3 ezfilecloud.py
```

Choose **2**. The app looks for receivers for about 3 seconds and verifies their
HTTP service. One receiver is selected automatically; if several are found,
choose its number. Then enter a username and file paths, one at a time. A blank
file path finishes. No receiver IP needs to be typed. Paths with spaces work
in the menu, without surrounding shell quotes. Directories are not sent; zip
one first. Use a folder your terminal has permission to read.

On Windows, run:

```text
py -3 ezfilecloud.py
```

Or double-click `EZ-file-cloud-Windows.bat` beside the script. The Mac/Linux
launchers also still work beside it. This is source code, not a packaged .exe
or .app.

## Grab files back

Run the script and choose **3**. It finds the receiver automatically. Enter the
same username you used when sending, choose a file number, then choose a save
folder. Enter accepts `~/EZ-file-cloud-downloads`. Existing local files are
never overwritten; duplicate names gain a numeric suffix. Downloads stream
and their SHA-256 checksums are verified. Failed or incomplete downloads are
removed. Repeat option 3 to grab another file.

The list is the username's folder on the receiver, shared across devices.
Other LAN users can also enter that username and read the files. It is not a
private "my files" account.

## Direct terminal commands (optional)

```text
python3 ezfilecloud.py scan
python3 ezfilecloud.py send auto Sender photo.jpg
python3 ezfilecloud.py list auto Sender
python3 ezfilecloud.py get auto Sender photo.jpg
```

Direct commands fail rather than silently choose among multiple receivers.
Use the menu to choose. A manual `IP:PORT` can replace `auto` for troubleshooting
or to send to an older receiver; discovery and grabbing require the new receiver.
Do not use public IP addresses. Multiple paths can be supplied to `send`.

## Discovery and same-network limits

The receiver answers small UDP broadcast queries on **8764**; files use HTTP
on TCP **8765** by default. This is a local discovery query, not a scan of every
host/port. A random query nonce filters stale replies, and the sender verifies
that a responding source IP runs EZ file cloud. Device names are not authenticated.

Both the receiver and sender must be updated. Allow UDP 8764 and TCP 8765 in the
receiver firewall if blocked. Guest Wi-Fi, device isolation, disabled broadcast
or a Windows routing/interface choice can prevent discovery. Multi-interface
Mac/Linux senders also try the detected subnets' directed broadcasts. Windows
uses the OS-routed local broadcast. IPv6 is not supported.

At startup the receiver detects its actual private IPv4 interface subnets and
netmasks. Discovery, lists, downloads and uploads from source addresses outside
those subnets are rejected; HTTP returns 403. It fails closed if no private LAN
subnet is found. Restart after a network change. This is IP-based filtering,
not proof of physical Wi-Fi membership: private VPN interfaces may be detected,
and a forwarded request may appear local. Do not use a tunnel or proxy.

## Storage limits

Uploads stream, verify SHA-256, remove incomplete files and never overwrite
existing files. Default file limit: 10 GiB. Four simultaneous file operations.
There is no total per-user disk quota. Lists are limited to 1000 files in a
username folder; this limit produces an error instead of hiding extra files.
Path traversal, symlink access and temporary-file downloads are rejected.
The receiver requires Linux/macOS directory-descriptor operations. Download
completion uses hard links to avoid overwriting local files, so the local save
folder must support hard links (normal Linux/macOS filesystems and Windows NTFS;
FAT/exFAT may fail safely instead of completing).

Optional settings:

```text
python3 ezfilecloud.py receive --port 8766 --max-mb 2048
python3 ezfilecloud.py receive --folder /root/MyInbox
```

Discovery reports the receiver's custom HTTP port automatically. UDP discovery
stays on 8764. Only one receiver process per device can use that UDP port.

## Tests

```text
python3 test_ezfilecloud.py
```

Tests exercise local Linux transfers, real UDP broadcast discovery, choosing
among receivers, invalid and outside-network discovery traffic, username file
lists, binary/empty/Unicode downloads, duplicate names, symlink/traversal blocks,
size limits, checksums and cleanup. Native Mac/Windows execution and real Pi
hardware are not tested by this build.

## Fullscreen Store launch

Version 1.2.1 adds a full-terminal interface when launched through the Store. Python 3 with curses and an interactive terminal are required. The original source remains available directly. Arrow keys select, Enter opens, and Q/Esc returns. Original commands temporarily take over the terminal for their prompts and output, then return to the full-terminal menu. Nested original prompts remain plain; they are not captured or rewritten. Passwords, sudo, confirmations, package changes and original limitations retain their old behavior. No administrative/package/transfer action ran during validation. Linux terminal checks passed; physical Raspberry Pi and non-Linux systems are untested.
