# Helm Remote Desktop — Help

Helm Remote Desktop connects to Windows PCs and servers (and xrdp on Linux) over the Remote Desktop Protocol. It looks and works like the Windows Remote Desktop Connection client (mstsc): type a computer name, press Connect, enter your credentials. The remote desktop opens in its own window, drawn by FreeRDP from your distribution.

Quick start
  1. Type the computer name or address in the Computer box (add :port if it is not 3389). Recent computers are in the drop-down.
  2. Optionally type your user name: user, DOMAIN\user or user@domain.
  3. Press Connect. If the computer's certificate cannot be verified Helm shows it and asks; then it asks for any missing user name or password.
  4. Show Options opens the General, Display, Local Resources, Experience and Advanced tabs. Save or open .rdp files on the General tab.

Ctrl+Alt+Enter switches the remote session between full screen and a window. In full screen the connection bar at the top lets you minimize, restore or close the session.


## Keyboard shortcuts

| Keys | Action |
|---|---|
| `F1` | This help |
| `Enter / Ctrl+Enter` | Connect |
| `Alt+O` | Show or hide the options tabs |
| `Ctrl+O` | Open an .rdp file |
| `Ctrl+S` | Save the connection settings |
| `Ctrl+Shift+S` | Save the connection settings as a new .rdp file |
| `Ctrl+L` | Show the log of the last connection |
| `Ctrl+Q` | Quit |
| `Ctrl+Alt+Enter` | In a session: toggle full screen (FreeRDP) |

## General tab

Computer: the remote computer's name or IP address, optionally with a port (pc01:3390, [fe80::1]:3390).
User name: the account on the remote computer. Use DOMAIN\user for a domain account or user@domain.
When a password is saved for the computer the tab says "Saved credentials will be used to connect to this computer" with links to edit or delete them.
"Allow me to save credentials" shows the Remember me box in the credentials window.
Save writes the settings to the open .rdp file, or to the default connection (~/.config/helm-rdp/Default.rdp) if none is open. Save As writes a new .rdp file; Open reads one. Files are compatible with mstsc on Windows.

## Display tab

Drag the slider to choose the remote desktop size; all the way to the right is Full Screen. "Use all my monitors" spans the session across every monitor (full screen only). "Resize the remote desktop when I resize the window" sends the new size to the server (dynamic resolution); "Scale the remote desktop to fit the window" scales the picture instead (smart sizing).
Colors sets the color depth: 15, 16, 24 or 32 bit.
"Display the connection bar when I use the full screen" shows the FreeRDP bar at the top of a full-screen session.

## Local Resources tab

Remote audio Settings: play remote sound on this computer, on the remote computer, or not at all, and record from this computer's microphone.
Apply Windows key combinations: on this computer, on the remote computer, or only in full screen. "On this computer" stops Helm grabbing the keyboard, so Alt+Tab and the Super key stay local.
Printers and Clipboard redirect your printers and copy/paste. More... chooses smart cards and which folders appear on the remote computer as drives: your home folder, mounted USB drives, any folder you add, all mounted drives, or drives you plug in later.

## Experience tab

Choose your connection speed and Helm turns the visual features on or off the same way mstsc does (desktop background, font smoothing, desktop composition, window contents while dragging, animations, visual styles, persistent bitmap caching). "Detect connection quality automatically" lets the server decide. "Reconnect if the connection is dropped" reconnects automatically after a network drop.

## Advanced tab

Server authentication: Helm reads the computer's TLS certificate before connecting. A certificate from a trusted authority with the right name is accepted silently. Otherwise, depending on "If server authentication fails":
  Warn me  show the certificate (name, errors, SHA-256 fingerprint) and ask; "Don't ask me again" remembers it for this computer
  Do not connect  refuse
  Connect and don't warn me  skip the check (not recommended)
The certificate you accept is pinned: FreeRDP refuses any other certificate for that connection. If a remembered certificate changes Helm warns you again. Options ▸ Saved Certificates lists and removes remembered ones.
Network Level Authentication is used when the computer supports it; untick it for old servers that fail the security negotiation.
Connect from anywhere ▸ Settings sets an RD Gateway (server name, logon method, bypass for local addresses, use the same credentials).

## Credentials and saved passwords

Helm asks for anything missing when you connect: the user name, the password, or both. Tick Remember me to save the password; it is saved only after the logon succeeds. Wrong passwords are asked again, up to three tries.
Where passwords are kept (Options ▸ Passwords):
  • Automatic: the system keychain when one is running, otherwise the encrypted vault.
  • System keychain: your login keyring (GNOME Keyring / KWallet, through the Secret Service). Unlocked when you log in; no extra password.
  • Encrypted vault: a file encrypted with AES-256-GCM using a key derived from your master password with scrypt. Asked once per session; Options ▸ Lock Password Vault locks it again. Defaults to ~/.config/helm-rdp/vault.json.
  • Don't save passwords.
Passwords are keyed by computer ("TERMSRV/pc01", like Windows). They are given to FreeRDP through a private pipe (FreeRDP 3: /args-from:fd, FreeRDP 2: stdin with /from-stdin) and never appear in .rdp files, settings.json, the command line, the environment or logs.

## Starting Helm from the command line

  helm-rdp --host HOST [--user USER] [--port PORT] [--password-fd N]
  helm-rdp file.rdp            open the file and connect
  helm-rdp --edit file.rdp     open the file without connecting
Options: --fullscreen, --width W --height H, --admin, --multimon, --no-connect. mstsc-style switches also work: /v:host[:port] /f /w:N /h:N /admin /edit.
--password-fd N reads the password from an inherited pipe (how Sonar and Porthole hand a saved password to Helm, the same as Skiff); a terminal is refused. Missing values are asked for in a window.

## Configuration files

  /etc/helm-rdp/helm-rdp.conf  master configuration: FreeRDP binary, extra FreeRDP options, log level, connect time-out
  ~/.config/helm-rdp/helm-rdp.conf  per-user override, same keys
  ~/.config/helm-rdp/settings.json  recent computers, password store choice, which computers have a saved password (never the password)
  ~/.config/helm-rdp/Default.rdp  the default connection
  ~/.config/helm-rdp/known_certs.json  certificates you chose to trust
  ~/.config/helm-rdp/vault.json  the encrypted vault, if used

## Troubleshooting

  • "Remote Desktop can't connect to the remote computer": the computer is off, not reachable, or Remote Desktop is not enabled / blocked by a firewall (TCP 3389).
  • "Remote Desktop can't find the computer": the name does not resolve; try the IP address.
  • "The logon attempt failed": wrong user name or password. For domain accounts use DOMAIN\user.
  • "An authentication error has occurred": the security negotiation failed. Try unticking Network Level Authentication on the Advanced tab.
  • "FreeRDP is not installed": sudo dnf install freerdp.
  • File ▸ Last Session Log (Ctrl+L) shows FreeRDP's output for the last connection (no passwords).
