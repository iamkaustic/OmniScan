# OmniScan

A comprehensive network utility application that combines Wake-on-LAN functionality with network scanning and diagnostic tools.

## Features

- **Wake-on-LAN**: Send magic packets to wake up computers on your network
- **Computer Management**: Save, edit, and delete computers for easy access
- **Quick Wake**: Quickly wake a computer using its MAC address without saving it
- **Network Scanning**: Scan your local network to discover connected devices
- **Network Tools**: Perform network diagnostics with Ping, Traceroute, Telnet, IPConfig, Flush DNS, and NSLookup tools
- **Active Directory Tools**: Query and manage Active Directory objects like users, groups, and domain controllers

## Requirements

- Python 3.6 or higher
- Required Python packages:
  - tkinter (usually included with Python)

## Installation

### Option 1: Run from Source
1. Clone or download this repository
2. Install the required packages:

```bash
pip install -r requirements.txt
```

Run the application:

```bash
python wol_app.py
```

### Option 2: Standalone Executable
For Windows users, a standalone executable is available in the `dist` folder:

1. Download the latest release
2. Run `OmniScan.exe` - no installation required!

## Building the Executable

If you want to build the executable yourself:

1. Install PyInstaller:
```bash
pip install pyinstaller
```

2. Run the build script:
```bash
python build_exe.py
```

3. The executable will be created in the `dist` folder

## Usage

### Managing Computers

- **Add**: Click "Add" to add a new computer with a name, MAC address, and optional IP address
- **Edit**: Select a computer and click "Edit" to modify its details
- **Delete**: Select a computer and click "Delete" to remove it from the list

### Scanning the Network

Click "Scan Network" to discover devices on your local network. The scanner will:

1. First check the ARP table for recently active devices
2. Then ping scan the remaining IP addresses in your local network
3. Display a list of discovered devices with their hostnames, IP addresses, and MAC addresses

You can select any discovered device to add it to your saved computers list or use its MAC address for a one-time wake-up.

### Waking Up Computers

There are two ways to wake up a computer:

1. Select a saved computer from the list and click "Wake Up", or
2. Enter a MAC address in the Quick Wake field and click "Wake Up"

## Network Tools

The application includes several network diagnostic tools to help you troubleshoot connectivity issues:

### Ping

Test basic connectivity to a host by sending ICMP echo requests:
- Enter the hostname or IP address
- Specify the number of ping packets to send
- View detailed ping results including response times

### Traceroute

Trace the route that packets take to reach a destination:
- Enter the hostname or IP address
- View the complete path including all intermediate hops
- See response times for each hop

### Telnet

Test connectivity to specific services on a host:
- Enter the hostname or IP address
- Specify the port number (or choose from common ports)
- Set connection timeout
- Quickly check if a service is available and accepting connections

### IPConfig

View your system's IP configuration:
- Displays all network adapters and their current IP settings
- Shows connection-specific DNS suffixes
- Provides subnet mask and default gateway information

### IPConfig /all

View detailed network configuration:
- Displays comprehensive information about all network adapters
- Shows physical (MAC) addresses
- Provides DHCP server details, DNS servers, and lease information
- Lists all connection parameters

### Flush DNS

Clear your system's DNS resolver cache:
- Removes all entries from the DNS cache
- Useful when DNS records have changed and you want to force resolution of fresh DNS data
- Helps troubleshoot DNS-related connectivity issues

### NSLookup

Perform DNS lookups for domains:
- Enter a domain name to query DNS servers
- View the IP addresses associated with the domain
- See authoritative name server information
- Useful for troubleshooting DNS resolution problems

### Network Tools

The application includes several network diagnostic tools:
- **Ping**: Test connectivity to a host
- **Traceroute**: Trace the route to a host
- **Telnet**: Connect to a host on a specific port
- **IPConfig**: Display IP configuration
- **IPConfig /all**: Display detailed IP configuration
- **Flush DNS**: Clear the DNS cache
- **NSLookup**: Query DNS for a domain

### Active Directory Tools

The application includes several Active Directory tools:
- **Domain Information**: View information about the current domain
- **List Domain Users**: View all users in the domain
- **User Information**: View detailed information about a specific user
- **List Domain Groups**: View all groups in the domain
- **Group Information**: View detailed information about a specific group
- **Domain Controllers**: View all domain controllers in the domain
- **Domain Trusts**: View all domain trusts
- **List Roles and Features**: View all installed roles and features on the server
- **Test Server Connectivity**: Test connectivity to a specific server
- **Domain IP and FQDN**: View the IP address and FQDN of the domain

## How it Works

Wake-on-LAN works by sending a special "magic packet" to a computer on the network. The magic packet contains the MAC address of the target computer repeated 16 times. When the network interface of the sleeping computer detects this packet, it signals the computer to wake up.

For this to work:
1. The target computer must have Wake-on-LAN enabled in its BIOS/UEFI settings
2. The network interface card must be configured to respond to Wake-on-LAN packets
3. The computer must be connected to power and the network

## Version Information

- Version: 1.0
- Build: A
- Author: Kaustubh Parab
- GitHub: https://github.com/iamkaustic

## License

MIT
