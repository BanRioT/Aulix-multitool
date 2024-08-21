import requests
import os
import socket
import subprocess
import ipaddress
from scapy.all import IP, ICMP, sr1, conf
from scapy.all import sniff, IP, TCP, DNS, DNSQR
import sys
import dns.resolver
import dns.reversename
import whois
from datetime import datetime
import dns.resolver
import dns.exception
import dns.query
import dns.zone
import platform
import ssl
from bs4 import BeautifulSoup
import instaloader
import time
import statistics

# MY CUSTOM COLORS
Dark_red = "\033[38;2;170;0;0m"
Dark_blue = "\033[38;2;0;0;170m"
Dark_aqua = "\033[38;2;0;170;170m"
Dark_purple = "\033[38;2;170;0;170m"
Dark_orange = "\033[38;2;255;170;0m"
Dark_gray = "\033[38;2;85;85;85m"
Dark_green = "\033[38;2;0;170;0m"
Black = "\033[38;2;30;30;30m"
Blue = "\033[38;2;85;85;255m"
Green = "\033[38;2;85;255;85m"
Aqua = "\033[38;2;85;255;255m"
Red = "\033[38;2;255;85;85m"
Purple = "\033[38;2;255;85;255m"
Yellow = "\033[38;2;255;255;85m"
White = "\033[38;2;255;255;255m"
Gray = "\033[38;2;171;171;171m"
Reset = "\033[0m"  # Reset to default color

def iplookup(ip):
    url = f"http://demo.ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,isp,org,asname,query&lang=en"
    response = requests.get(url)
    data = response.json()

    if data.get("status") == "fail":
        print("Error:", data.get("message", "Unknown error"))
    else:
        print("")
        print(f"{Dark_orange}IP Address    {White}>  {Dark_green}{data.get('query', 'N/A')}")
        print(f"{Dark_orange}Country code  {White}>  {Dark_green}{data.get('countryCode', 'N/A')}")
        print(f"{Dark_orange}Country       {White}>  {Dark_green}{data.get('country', 'N/A')}")
        print(f"{Dark_orange}Region code   {White}>  {Dark_green}{data.get('region', 'N/A')}")
        print(f"{Dark_orange}Region name   {White}>  {Dark_green}{data.get('regionName', 'N/A')}")
        print(f"{Dark_orange}City          {White}>  {Dark_green}{data.get('city', 'N/A')}")
        print(f"{Dark_orange}Zip code      {White}>  {Dark_green}{data.get('zip', 'N/A')}")
        print(f"{Dark_orange}ISP           {White}>  {Dark_green}{data.get('isp', 'N/A')}")
        print(f"{Dark_orange}Organization  {White}>  {Dark_green}{data.get('org', 'N/A')}")
        print(f"{Dark_orange}ASN           {White}>  {Dark_green}{data.get('asname', 'N/A')}")
        print(f"{Dark_orange}Latitude      {White}>  {Dark_green}{data.get('lat', 'N/A')}")
        print(f"{Dark_orange}Longitude     {White}>  {Dark_green}{data.get('lon', 'N/A')}")
        print(f"{Dark_orange}Location      {White}>  {Dark_green}{data.get('lat', 'N/A')}, {data.get('lon', 'N/A')}")
    
def clear():
    os.system("cls")

def port_scan(ip):
    # Dictionary mapping well-known port numbers to service names
    service_names = {
        1: "TCPMUX",
        5: "RJE",
        7: "ECHO",
        18: "MSP",
        20: "FTP DATA",
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        69: "TFTP",
        80: "HTTP",
        88: "Kerberos",
        102: "Iso-tsap",
        110: "POP3",
        115: "SFTP",
        119: "NNTP",
        123: "NTP",
        135: "RPC",
        137: "NetBIOS-ns",
        139: "NetBIOS",
        143: "IMAP",
        161: "SNMP",
        194: "IRC",
        381: "HP Openview",
        383: "HP Openview-data",
        443: "HTTPS",
        445: "SMB",
        465: "SMTPS",
        587: "Submission",
        593: "Microsoft DCOM",
        636: "LDAP",
        691: "MS Exchange",
        902: "VMware",
        993: "IMAPS",
        995: "POP3S",
        1194: "OpenVPN",
        1337: "WASTE",
        1433: "MSSQL",
        1589: "CISCO VQP",
        1725: "STEAM",
        2082: "cPanel",
        2083: "radsec",
        2967: "symantec AV",
        3074: "XBOX Live",
        3076: "XBOX Live",
        3306: "MySQL",
        3389: "Remote Desktop",
        3724: "WoW",
        4664: "Google Desktop",
        5632: "PCAnywhere",
        5900: "VNC",
        8086: "Kaspersky AV",
        25565: "Minecraft",
        # Add more port numbers and service names as needed
    }

    def scan_ports(ip, ports):
        open_ports = []
        for port in ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.1)  # Set a timeout for the connection attempt
                s.connect((ip, port))
                service_name = service_names.get(port, "Unknown")  # Lookup service name or use "Unknown" if not found
                print(f"{Yellow}", f"{ip}".ljust(15), f"{port}".ljust(15), f"{service_name}".ljust(20), f"{Green}OPEN")
                open_ports.append(port)
                s.close()
            except:
                service_name = service_names.get(port, "Unknown")  # Lookup service name or use "Unknown" if not found
                print(f"{Yellow}", f"{ip}".ljust(15), f"{port}".ljust(15), f"{service_name}".ljust(20), f"{Red}CLOSED")
        return open_ports

    #print(f"{white}[{aqua_green}+{white}] Enter targets IP Address to scan for open ports.")

    print(f"{Aqua}", "IP Address".ljust(15), "Port".ljust(15),  "Service".ljust(20), "Status                             ")


    ports_to_scan = [1, 5, 7, 18, 20, 21, 22, 23, 25, 53, 69, 80, 88, 102, 110, 115, 119, 123, 135, 137, 139, 143, 161, 194, 381, 383, 443, 445, 465, 587, 593, 636, 691, 902, 993, 995, 1194, 1337, 1433, 1589, 1725, 2082, 2083, 2967, 3076, 3306, 3389, 3724, 4664, 5632, 5900, 8086, 8086, 25565]
    open_ports = scan_ports(ip, ports_to_scan)

def is_valid_ip(ip):
    try:
        # Try to create an IPv4 or IPv6 address object
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        # If an exception is raised, the IP is not valid
        return False

def traceroute(target, max_hops=30, timeout=2):
    print(f"{Dark_purple}Traceroute to {Yellow}{target} {Dark_purple}with a maximum of {Red}{max_hops} {Dark_purple}hops:\n")

    # Set up conf to suppress verbose output
    conf.verb = 0

    for ttl in range(1, max_hops + 1):
        pkt = IP(dst=target, ttl=ttl) / ICMP()
        reply = sr1(pkt, timeout=timeout)

        if reply is None:
            print(f"{Dark_aqua}{ttl}{Aqua}: {Red}Request timed out.")
        elif reply.type == 11:
            print(f"{Dark_aqua}{ttl}{Aqua}: {Blue}{reply.src}")
        elif reply.type == 0:
            print(f"{Dark_aqua}{ttl}{Aqua}: {Dark_orange}{reply.src}")
            print(f"{Green}Reached target.\n")
            break

def nslookup(domain):
    try:
        # A (IPv4) records
        a_records = dns.resolver.resolve(domain, 'A')
        print(f"{Dark_aqua}A Records (IPv4) for {Aqua}{domain}{Dark_aqua}:")
        for rdata in a_records:
            print(f"{Red}└ {Dark_green}{rdata}")

        # AAAA (IPv6) records
        try:
            aaaa_records = dns.resolver.resolve(domain, 'AAAA')
            print(f"\n{Dark_aqua}AAAA Records (IPv6) for {Aqua}{domain}{Dark_aqua}:")
            for rdata in aaaa_records:
                print(f"{Red}└ {Dark_green}{rdata}")
        except dns.resolver.NoAnswer:
            print(f"\n{Red}No AAAA (IPv6) records found.")

        # MX (Mail Exchange) records
        mx_records = dns.resolver.resolve(domain, 'MX')
        print(f"\n{Dark_aqua}MX Records for {Aqua}{domain}{Dark_aqua}:")
        for rdata in mx_records:
            print(f"{Red}└ {Dark_green}{rdata.preference} {rdata.exchange}")

        # NS (Name Server) records
        ns_records = dns.resolver.resolve(domain, 'NS')
        print(f"\n{Dark_aqua}NS Records for {Aqua}{domain}{Dark_aqua}:")
        for rdata in ns_records:
            print(f"{Red}└ {Dark_green}{rdata}")

        # SOA (Start of Authority) record
        soa_record = dns.resolver.resolve(domain, 'SOA')
        print(f"\n{Dark_aqua}SOA Record for {Aqua}{domain}{Dark_aqua}:")
        for rdata in soa_record:
            print(f"{Dark_red}MNAME    {Purple}> {Yellow}{rdata.mname}")
            print(f"{Dark_red}RNAME    {Purple}> {Yellow}{rdata.rname}")
            print(f"{Dark_red}Serial   {Purple}> {Yellow}{rdata.serial}")
            print(f"{Dark_red}Refresh  {Purple}> {Yellow}{rdata.refresh}")
            print(f"{Dark_red}Retry    {Purple}> {Yellow}{rdata.retry}")
            print(f"{Dark_red}Expire   {Purple}> {Yellow}{rdata.expire}")
            print(f"{Dark_red}Minimum  {Purple}> {Yellow}{rdata.minimum}")

        # PTR (Pointer) record
        try:
            ip = a_records[0].to_text()  # Get the first A record for PTR lookup
            rev_name = dns.reversename.from_address(ip)
            ptr_records = dns.resolver.resolve(rev_name, 'PTR')
            print(f"\n{Dark_aqua}PTR Record for IP {Aqua}{ip}{Dark_aqua}:")
            for rdata in ptr_records:
                print(f"  {rdata}")
        except Exception as e:
            print(f"\n{Red}PTR Record lookup failed:", e)

    except dns.resolver.NXDOMAIN:
        print(f"{Red}The domain {Dark_red}{domain} {Red}does not exist.")
    except dns.resolver.Timeout:
        print(f"{Red}Request timed out for {Dark_red}{domain}{Red}.")
    except dns.resolver.NoAnswer:
        print(f"{Red}No answer was received for {Dark_red}{domain}{Red}.")
    except Exception as e:
        print(f"{Red}An error occurred: {Dark_red}{e}")

def ping(host, count=4, timeout=2):
    """Ping a host and return the round-trip times."""
    rtt_list = []
    for _ in range(count):
        pkt = IP(dst=host) / ICMP()
        start_time = time.time()
        reply = sr1(pkt, timeout=timeout, verbose=0)
        end_time = time.time()
        
        if reply:
            rtt = (end_time - start_time) * 1000  # Convert to milliseconds
            rtt_list.append(rtt)
        else:
            rtt_list.append(None)  # No response (timeout)

    return rtt_list

def pathping(target, max_hops=30, ping_count=4, timeout=2):
    """Perform a pathping-like operation."""
    print(f"{Dark_aqua}Pathping to {Blue}{target}{Dark_aqua} with a maximum of {Purple}{max_hops}{Dark_aqua} hops:")

    # Set up scapy to suppress verbose output
    conf.verb = 0

    max_length = 18  # Adjust this to your desired padding width

    for ttl in range(1, max_hops + 1):
        pkt = IP(dst=target, ttl=ttl) / ICMP()
        reply = sr1(pkt, timeout=timeout)

        if reply is None:
            print(f"{Red}{ttl}: Request timed out.")
            continue

        hop_ip = reply.src

        # Ping the hop multiple times and calculate statistics
        rtts = ping(hop_ip, count=ping_count, timeout=timeout)
        rtts = [rtt for rtt in rtts if rtt is not None]  # Remove None values (timeouts)

        if rtts:
            min_rtt = min(rtts)
            avg_rtt = statistics.mean(rtts)
            max_rtt = max(rtts)

            # Format hop information without color codes for alignment
            plain_hop_info = f"{ttl}: {hop_ip}"
            formatted_hop_info = f"{Blue}{ttl}{Yellow}:  {White}{hop_ip}"

            # Calculate padding
            padded_hop_info = formatted_hop_info + ' ' * (max_length - len(plain_hop_info))

            # Print hop information and RTT statistics on the same line
            print(f"{padded_hop_info}{Dark_green}Min{White}/{Aqua}Avg{White}/{Yellow}Max RTT: "
                  f"{Dark_green}{min_rtt:.2f}{White}/{Aqua}{avg_rtt:.2f}{White}/{Yellow}{max_rtt:.2f} {Gray}ms")
        else:
            print(f"{Red}{ttl}: {hop_ip} All pings timed out.")

        if reply.type == 0:  # Echo Reply, reached the target
            print("Reached target.")
            break

def get_netbios_info(ip):
    """Retrieve and display NetBIOS information for the given IP address."""
    try:
        # Convert IP address to its hostname
        hostname = socket.gethostbyaddr(ip)[0]
        print(f"Hostname: {hostname}")
    except socket.herror:
        print("Hostname: Not resolved")

    try:
        # Perform a NetBIOS name query
        # Note: NetBIOS requires UDP port 137
        # Create a UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)  # Set timeout for socket operations
        
        # NetBIOS Name Query Packet
        # Construct a NetBIOS name query packet (broadcasting on UDP port 137)
        packet = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        sock.sendto(packet, (ip, 137))

        # Receive the response
        response, _ = sock.recvfrom(1024)  # 1024 bytes buffer size

        # Print raw response for analysis
        print(f"Raw response: {response}")

        # Parse the response to extract NetBIOS names
        # NetBIOS name response parsing is complex and requires specific format understanding
        # You can use libraries like `pynbt` to parse these responses in a real scenario

    except socket.error as e:
        print(f"Socket error: {e}")
    finally:
        sock.close()

def format_date(date):
    """Format date object to a readable string."""
    if isinstance(date, list):
        date = date[0] if date else None
    return date.strftime("%Y-%m-%d %H:%M:%S") if date else "N/A"

def whois_lookup(domain):
    """Perform a WHOIS lookup for the given domain and print detailed information."""
    try:
        # Fetch WHOIS data
        domain_info = whois.whois(domain)

        print(f"WHOIS Information for {domain}:\n")
        
        # Extract and print WHOIS information
        print(f"{Dark_purple}Domain Name      {Blue}>  {Green}{domain_info.domain_name}")
        print(f"{Dark_purple}Registrar        {Blue}>  {Green}{domain_info.registrar}")
        print(f"{Dark_purple}Creation Date    {Blue}>  {Green}{format_date(domain_info.creation_date)}")
        print(f"{Dark_purple}Expiration Date  {Blue}>  {Green}{format_date(domain_info.expiration_date)}")
        print(f"{Dark_purple}Updated Date     {Blue}>  {Green}{format_date(domain_info.updated_date)}")
        print(f"{Dark_purple}Status           {Blue}>  {Green}{', '.join(domain_info.status or [])}")
        print(f"{Dark_purple}Name Servers     {Blue}>  {Green}{', '.join(domain_info.name_servers or [])}")
        print(f"{Dark_purple}Emails           {Blue}>  {Green}{', '.join(domain_info.emails or [])}")
        print(f"{Dark_purple}Org              {Blue}>  {Green}{domain_info.org or 'N/A'}")
        
    except Exception as e:
        print(f"Error performing WHOIS lookup: {e}")

def perform_query(domain, record_type):
    """Perform a DNS query for the specified record type."""
    try:
        # Resolve the DNS records
        answers = dns.resolver.resolve(domain, record_type)
        print(f"\n{Green}{record_type} {Dark_green}records for {Green}{domain}:")
        for answer in answers:
            print(f"  {Yellow}{answer.to_text()}")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        print(f"{Red}No answer or domain does not exist for {domain} with record type {record_type}.")
    except dns.exception.DNSException as e:
        print(f"{Dark_red}DNS query failed for {record_type}: {Red}{e}")

def dig_tool():
    domain = input(f" └ Enter a IP address: ")
    print(f"\nPerforming DNS queries for {domain}...\n")

    record_types = [
        'A',       # IPv4 Address
        'AAAA',    # IPv6 Address
        'MX',      # Mail Exchange
        'NS',      # Name Server
        'TXT',     # Text Record
        'CNAME',   # Canonical Name
        'SOA',     # Start of Authority
        'PTR',     # Pointer Record
        'SRV',     # Service Location
        'NAPTR',   # Naming Authority Pointer
        'DS',      # Delegation Signer
        'DNSKEY',  # DNS Key
        'RRSIG',   # DNSSEC Signature
        'TLSA',    # TLS Authentication
        'CAA'      # Certification Authority Authorization
    ]
    
    for record_type in record_types:
        perform_query(domain, record_type)

def get_weather(postal_code):
    def get_weather_info(code: str) -> dict:
        try:
            response = requests.get(
                f'http://api.weatherapi.com/v1/current.json?key=638e350524ab4650a4303224220807&q={code}&aqi=no',
                headers={'User-Agent': '5.0 (Windows NT 10.0; WOW64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.5666.197 Safari/537.36'}
            )
            if response.status_code == 200:
                return {
                    'status': True,
                    'data': response.json()
                }
            else:
                return {
                    'status': False,
                    'message': f'Invalid response ({response.status_code})'
                }
        except Exception as e:
            return {
                'status': False,
                'message': f'Unexpected error: {e}'
            }

    # Call the function to get weather info
    weather_info = get_weather_info(postal_code)

    # Check if the response was successful
    if weather_info['status']:
        data = weather_info['data']
        
        # Print weather information
        print(f"""
{Green}Time           {Yellow}> {Purple}{data["location"].get("localtime")}
{Green}City           {Yellow}> {Purple}{data["location"].get("name")}
{Green}State          {Yellow}> {Purple}{data["location"].get("region")}
{Green}Country        {Yellow}> {Purple}{data["location"].get("country")}
{Green}Timezone       {Yellow}> {Purple}{data["location"].get("tz_id")}

{Green}Clouds         {Yellow}> {Purple}{data["current"]["cloud"]}
{Green}Humidity       {Yellow}> {Purple}{data["current"]["humidity"]}%
{Green}UV Index       {Yellow}> {Purple}{data["current"]["uv"]}
{Green}Pressure       {Yellow}> {Purple}{data["current"]["pressure_in"]} in, {data["current"]["pressure_mb"]} mb.

{Green}Condition      {Yellow}> {Purple}{data["current"]["condition"]["text"]}
{Green}Day/Night      {Yellow}> {Purple}{"Day" if data["current"]["is_day"] == 1 else "Night"}
{Green}Wind Speed     {Yellow}> {Purple}{data["current"]["wind_mph"]} mph, {data["current"]["wind_kph"]} kph.

{Green}Visibility     {Yellow}> {Purple}{data["current"]["vis_miles"]} miles, {data["current"]["vis_km"]} km.
{Green}Temperature    {Yellow}> {Purple}{data["current"]["temp_f"]}°F, {data["current"]["temp_c"]}°C
{Green}Precipitation  {Yellow}> {Purple}{data["current"]["precip_in"]} in, {data["current"]["precip_mm"]} mm.""")
    else:
        # Handle error message
        print(f"Error: {weather_info['message']}")

def check_and_open_putty():
    # Define common PuTTY executable names based on platform
    putty_executables = {
        'Windows': 'putty.exe',
        'Linux': 'putty',
        'Darwin': 'putty'  # macOS
    }
    
    # Get the platform
    current_platform = platform.system()
    putty_path = None

    if current_platform in putty_executables:
        executable = putty_executables[current_platform]

        # Check system PATH
        putty_path = which(executable)
        
        # Check common installation directories (Windows example paths)
        if current_platform == 'Windows':
            common_dirs = [
                os.path.expandvars(r'%ProgramFiles%\PuTTY'),
                os.path.expandvars(r'%ProgramFiles(x86)%\PuTTY'),
                os.path.expanduser(r'~/Desktop/PuTTY')
            ]
            for dir in common_dirs:
                potential_path = os.path.join(dir, executable)
                if os.path.isfile(potential_path):
                    putty_path = potential_path
                    break

    if putty_path:
        #print(f"PuTTY found at: {putty_path}")
        try:
            # Open PuTTY
            subprocess.Popen([putty_path])
            print(f"{Green}PuTTY has been opened.")
        except Exception as e:
            print(f"{Red}Error opening PuTTY: {e}")
    else:
        print(f"{Yellow}PuTTY is not installed or cannot be found. Try moving your {Dark_orange}putty.exe{Yellow} to your desktop.")

def which(executable):
    """Check if an executable exists in the PATH."""
    paths = os.getenv("PATH").split(os.pathsep)
    for path in paths:
        full_path = os.path.join(path, executable)
        if os.path.isfile(full_path) and os.access(full_path, os.X_OK):
            return full_path
    return None

def get_public_ip():
    """Fetch the public IP address of the user."""
    try:
        response = requests.get("https://api.ipify.org?format=json")
        response.raise_for_status()  # Raise an error for bad status
        return response.json().get("ip")
    except requests.RequestException as e:
        print(f"Error fetching public IP: {e}")
        return None

def self_ip_lookup(ip):
    """Fetch and display information about the given IP address."""
    url = f"http://demo.ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,isp,org,asname,query&lang=en"
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise an error for bad status
        data = response.json()

        if data.get("status") == "fail":
            print("Error:", data.get("message", "Unknown error"))
        else:
            print("")
            print(f"{Dark_orange}IP Address    {White}>  {Dark_green}{data.get('query', 'N/A')}")
            print(f"{Dark_orange}Country code  {White}>  {Dark_green}{data.get('countryCode', 'N/A')}")
            print(f"{Dark_orange}Country       {White}>  {Dark_green}{data.get('country', 'N/A')}")
            print(f"{Dark_orange}Region code   {White}>  {Dark_green}{data.get('region', 'N/A')}")
            print(f"{Dark_orange}Region name   {White}>  {Dark_green}{data.get('regionName', 'N/A')}")
            print(f"{Dark_orange}City          {White}>  {Dark_green}{data.get('city', 'N/A')}")
            print(f"{Dark_orange}Zip code      {White}>  {Dark_green}{data.get('zip', 'N/A')}")
            print(f"{Dark_orange}ISP           {White}>  {Dark_green}{data.get('isp', 'N/A')}")
            print(f"{Dark_orange}Organization  {White}>  {Dark_green}{data.get('org', 'N/A')}")
            print(f"{Dark_orange}ASN           {White}>  {Dark_green}{data.get('asname', 'N/A')}")
            print(f"{Dark_orange}Latitude      {White}>  {Dark_green}{data.get('lat', 'N/A')}")
            print(f"{Dark_orange}Longitude     {White}>  {Dark_green}{data.get('lon', 'N/A')}")
            print(f"{Dark_orange}Location      {White}>  {Dark_green}{data.get('lat', 'N/A')}, {data.get('lon', 'N/A')}")
    except requests.RequestException as e:
        print(f"Error performing IP lookup: {e}")

# List of blacklisted domains
BLACKLIST = {"spotify.com"}

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        
        if TCP in packet:
            # Check if the packet contains HTTP data
            if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                if packet.haslayer('Raw'):
                    raw_data = packet.getlayer('Raw').load.decode(errors='ignore')
                    if 'Host:' in raw_data:
                        host_line = [line for line in raw_data.split('\n') if line.startswith('Host:')]
                        if host_line:
                            domain = host_line[0].split(' ')[1]
                            # Check if domain is in the blacklist
                            if domain.lower() not in BLACKLIST:
                                print(f"{White}[{Blue}+{White}] {Yellow}HTTP Request: {Aqua}{ip_src} {Red}-> {Dark_aqua}{ip_dst}".ljust(168), f" {Yellow}Domain: {Dark_purple}{domain}")
                    
        elif DNS in packet:
            # DNS query to detect domain names
            if packet.haslayer(DNSQR):
                dns_query = packet[DNSQR].qname.decode().strip('.')
                # Check if domain is in the blacklist
                if dns_query.lower() not in BLACKLIST:
                    print(f"{White}[{Blue}+{White}] {Yellow}DNS Query: {Aqua}{ip_src} {Red}-> {Dark_aqua}{ip_dst}".ljust(168), f" {Yellow}Domain: {Dark_purple}{dns_query}")

# List of SQL Injection payloads
SQL_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' #",
    "' OR '1'='1' /*"
]

# List of XSS payloads
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "'\"><img src=x onerror=alert(1)>"
]

# List of common HTTP methods to check
HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "OPTIONS", "TRACE"]

def check_sql_injection(url):
    """Check for SQL Injection vulnerabilities."""
    for payload in SQL_PAYLOADS:
        test_url = f"{url}?id={payload}"
        try:
            response = requests.get(test_url)
            if "error" in response.text.lower():
                print(f"{White}[{Green}+{White}] Potential SQL Injection found at{Blue}: {Dark_orange}{test_url}")
        except Exception as e:
            print(f"{White}Error testing {Yellow}SQL Injection{Dark_red}: {Red}{e}")

def check_xss_vulnerability(url):
    """Check for XSS vulnerabilities."""
    for payload in XSS_PAYLOADS:
        try:
            response = requests.get(url, params={'search': payload})
            if payload in response.text:
                print(f"{White}[{Green}+{White}] Potential XSS vulnerability found at: {Aqua}{url}{White} with payload{Blue}: {Dark_orange}{payload}")
        except Exception as e:
            print(f"{White}Error testing {Yellow}XSS{Dark_red}: {Red}{e}")

def check_http_methods(url):
    """Check for allowed HTTP methods."""
    try:
        response = requests.options(url)
        allowed_methods = response.headers.get('Allow', '')
        print(f"{White}[{Green}+{White}] Allowed HTTP Methods for {Aqua}{url}{Blue}: {Dark_orange}{allowed_methods}")
        
        for method in HTTP_METHODS:
            if method not in allowed_methods:
                print(f"{Red}# {White}Method not allowed{Blue}: {Dark_orange}{method}")
                
    except Exception as e:
        print(f"{White}Error checking {Yellow}HTTP{White} methods{Dark_red}: {Red}{e}")

def check_common_paths(url):
    """Check for common vulnerable paths."""
    COMMON_PATHS = [
        "/admin",
        "/login",
        "/dashboard",
        "/uploads",
        "/config",
    ]
    
    for path in COMMON_PATHS:
        full_url = f"{url.rstrip('/')}{path}"
        try:
            response = requests.get(full_url)
            if response.status_code == 200:
                print(f"{White}[{Green}+{White}] Found potential vulnerable path{Blue}: {Dark_orange}{full_url}")
            else:
                print(f"    {White}[{Dark_blue}*{White}] Path not found{Blue}: {Dark_orange}{full_url} {Dark_aqua}({Aqua}Status Code{Dark_red}: {Red}{response.status_code}{Dark_aqua})")
                
        except Exception as e:
            print(f"{White}Error checking path {Yellow}{full_url}{Dark_red}: {Red}{e}")

def print_underlined_link(url):
    # ANSI escape codes for underlining
    UNDERLINE_START = '\033[4m'
    UNDERLINE_END = '\033[0m'
    
    # Formatting the URL to look like a clickable link
    clickable_link = f"{UNDERLINE_START}{Blue}{url}{UNDERLINE_END}"
    
    print(f"""{Dark_gray}Note: If you are using the new windows terminal hold down Ctrl then click on the URL below to open the URL in yourbrowser
{White}Exploit Database: {clickable_link}""")

def run_netsh_command(command):
    """Executes a netsh command and returns the output."""
    try:
        result = subprocess.run(['netsh'] + command.split(), capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        return f"Error executing command: {e}"

def generate_report():
    """Generates a comprehensive report with all netsh information."""
    print("Generating Network Information Report...\n")
    
    # List network interfaces
    print("Network Interfaces:")
    interfaces_output = run_netsh_command('interface show interface')
    print(interfaces_output)
    
    # Show IP configuration
    print("IP Configuration:")
    ip_config_output = run_netsh_command('interface ip show config')
    print(ip_config_output)
    
    # Show wireless networks
    print("Available Wireless Networks:")
    wireless_networks_output = run_netsh_command('wlan show networks')
    print(wireless_networks_output)
    
    # Show firewall rules
    #print("Firewall Rules:")
    #firewall_rules_output = run_netsh_command('advfirewall firewall show rule name=all')
    #print(firewall_rules_output)
    
    # Show routing table
    print("Routing Table:")
    routing_table_output = run_netsh_command('interface ipv4 show route')
    print(routing_table_output)
    
    # Show network statistics
    print("Network Statistics:")
    network_stats_output = run_netsh_command('interface show interface')
    print(network_stats_output)

def netsh_pro():
    generate_report()

sub_domnames = [
    "www", "mail", "blog", "forum", "m", "shop", "wiki", "community", "ads",
    "docs", "news", "support", "api", "cdn", "app", "demo", "login", "test",
    "admin", "status", "portal", "webmail", "secure", "oauth", "my", "git", 
    "forum", "download", "static", "store", "help", "shop", "service", "files", 
    "calendar", "user", "chat", "support", "forum", "careers", "about", "events",
    "newsletter", "media", "partners", "partners", "developer", "api", "connect",
    "dev", "secure", "cloud", "app", "test", "home", "services", "docs", "code",
    "search", "support", "info", "portal", "intranet", "outlook", "mail", "news",
    "vpn", "store", "checkout", "book", "media", "links", "team", "careers", "jobs",
    "recruitment", "beta", "site", "play", "account", "network", "api", "login",
    "management", "console", "system", "cloud", "service", "system", "project",
    "web", "site", "partner", "partner", "marketing", "data", "group", "test", 
    "sandbox", "dev", "demo", "stage", "labs", "support", "report", "service", 
    "feedback", "customer", "support", "dashboard", "client", "portal", "product"
]

def domain_scanner(domain_name, sub_domnames):
    print('[+] Started subdomain extraction.')
    for subdomain in sub_domnames:
        url = f"https://{subdomain}.{domain_name}"
        try:
            response = requests.get(url, timeout=5)
            # Determine the color based on the HTTP status code
            if response.status_code in [200, 301, 302]:
                color = Green
            elif response.status_code in [400, 401, 403, 404, 500, 502, 503, 504]:
                color = Red
            else:
                color = Purple

            print(f"{White}[{color}{response.status_code}{White}] [{Green}+{White}] {Blue}* {Aqua}{url}")
        except requests.RequestException:
            # Handle connection errors and timeouts
            print(f"{White}[{Yellow}N/A{White}] [{Red}-{White}] {Blue}* {Aqua}{url}")

def check_tls_version(hostname, port):
    tls_versions = {
        ssl.PROTOCOL_TLS: "TLS (default)",
        ssl.PROTOCOL_TLSv1: "TLSv1.0",
        ssl.PROTOCOL_TLSv1_1: "TLSv1.1",
        ssl.PROTOCOL_TLSv1_2: "TLSv1.2",
        # Adding support for TLSv1.3 if available
    }
    for version, name in tls_versions.items():
        try:
            context = ssl.SSLContext(version)
            with socket.create_connection((hostname, port)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    print(f"{name} is supported.")
        except Exception as e:
            print(f"{name} is not supported: {e}")

def check_cipher_suites(hostname, port):
    try:
        context = ssl.create_default_context()
        context.set_ciphers("ALL")
        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                print("Cipher suites:")
                for cipher in ssock.cipher():
                    print(f"  - {cipher[0]}")
    except Exception as e:
        print(f"Error checking cipher suites: {e}")

def check_certificate(hostname, port):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                print("Certificate information:")
                print(f"  - Subject: {cert.get('subject')}")
                print(f"  - Issuer: {cert.get('issuer')}")
                print(f"  - Not Before: {cert.get('notBefore')}")
                print(f"  - Not After: {cert.get('notAfter')}")
                print(f"  - Serial Number: {cert.get('serialNumber')}")
                
    except Exception as e:
        print(f"Error checking certificate: {e}")

def ssltlsscanner():
    hostname = input("Enter Target IP Address: ").strip()
    port = input("Enter Target Port: ").strip()

    try:
        port = int(port)  # Convert port to an integer
    except ValueError:
        print("Invalid port number. Please enter a valid integer.")
        return

    print(f"Scanning {hostname}:{port}...")
    
    print("\nChecking TLS versions...")
    check_tls_version(hostname, port)
    
    print("\nChecking cipher suites...")
    check_cipher_suites(hostname, port)
    
    print("\nChecking certificate...")
    check_certificate(hostname, port)

def scrape_instagram_profile(username):
    loader = instaloader.Instaloader()

    try:
        profile = instaloader.Profile.from_username(loader.context, username)
    except instaloader.exceptions.InstaloaderException as e:
        print(f"Error: {e}")
        return

    # Display profile information
    print(f"{Dark_aqua}Username   {Purple}> {Yellow}{profile.username}")
    print(f"{Dark_aqua}Full Name  {Purple}> {Yellow}{profile.full_name}")
    print(f"{Dark_aqua}Bio        {Purple}> {Yellow}{profile.biography}")
    print(f"{Dark_aqua}Followers  {Purple}> {Yellow}{profile.followers}")
    print(f"{Dark_aqua}Following  {Purple}> {Yellow}{profile.followees}")
    print(f"{Dark_aqua}Posts      {Purple}> {Yellow}{profile.mediacount}")

    # Optionally, display recent posts
    print(f"\n{Red}Recent Posts:")
    for post in profile.get_posts():
        print(f"- {post.url}")

    











computer_name = socket.gethostname()

os.system("title Aulix")

print(f"""✨ {Aqua}Welcome {Dark_aqua}{computer_name} {Aqua}to Aulix {Black}Build Version: 1.0.3a
\n{Yellow}📌 Aulix {Purple}version: {White}1.0 {Dark_gray}(Use changelog to view the changelog)""")

while True:
    cmd = input(f"{Red} » {White}")

    if cmd == 'help':
        print(f"""
{Yellow}- {Purple}[{Green}Basic commands{Purple}]{Reset}:
{Blue}help {White}- Shows a list of available commands.
{Blue}about {White}- Shows information about Aulix.
{Blue}clear {White}- Clears the terminal.
{Blue}changelog {White}- Shows the changelog information.
{Blue}exit {White}- Closes Aulix.

{Yellow}- {Purple}[{Green}Network commands{Purple}]{Reset}:
{Blue}port.scan {White}- Scans a host for open ports.
{Blue}ip.valid {White}- Validates a IP address.
{Blue}ddos {White}- Boot a IP Address offline.
{Blue}tracert {White}- Trace the path that an Internet Protocol (IP) packet takes to its destination.
{Blue}nslookup {White}- Find out the corresponding IP address or domain name system (DNS) record.
{Blue}path.ping {White}- Combines the functionality of ping with that of tracert.
{Blue}nbtstat {White}- Displays protocol statistics and current TCP/IP connections using NBT (NetBIOS over TCP/IP).
{Blue}dig {White}- (domain information groper) Command is a flexible tool for interrogating DNS name servers.
{Blue}nmap {White}- Map out a network or host.
{Blue}net.sniff {White}- Capture and displays your network interfaces packets. {Dark_green}[Beta]
{Blue}web.scan {White}- Scan a website for vulnerabilities. {Dark_green}[Work in progress]
{Blue}ssltls.scanner {White}- checks a server's service on any port to support TLS/SSL ciphers, protocols. {Dark_green}[Work in progress] {Dark_gray}(SSL/TLS Vulnerability Scanner)
{Blue}netsh {White}- shows your network interfaces. {Dark_red}✖  WARNING: This command will reveal sensitive information. ✖

{Yellow}- {Purple}[{Green}Cracking commands{Purple}]{Reset}:
{Blue}ssh.cracker {White}- Attempts to crack a SSH connection locked behind a password. {Red}[Broken]

{Yellow}- {Purple}[{Green}Osint commands{Purple}]{Reset}:
{Blue}gamertag.search {White}- Search through the database for a targets IP (Xbox gamertag to IP address).
{Blue}lookup {White}- Lookup information on an IP address.
{Blue}whois {White}- Lookup website information like hosting service, domain owner info, etc.
{Blue}phone.lookup {White}- Lookup phone number information like host, location, etc. {Yellow}[In developement]
{Blue}weather.resolver {White}- Gives you the current weather thats near the specified postal code.
{Blue}subdomain.sniff {White}- Gives you the current weather thats near the specified postal code.
{Blue}web.scraper {White}- Scrapes the internet for information based on Username, etc. {Red}[Broken]
{Blue}instagram.scraper {White}- Scrapes Instagram for information for post info, account information, etc.
{Blue}doxtool {White}- Attempts to find publicly available information about someone including Addresses, social media accounts, etc. {Dark_green}[Beta]

{Yellow}- {Purple}[{Green}Misc Commands{Purple}]{Reset}:
{Blue}PuTTY {White}- Scrapes the internet for information based on a gamertag or name.
{Blue}ip.info {White}- Shows your ip address information. {Dark_red}✖  WARNING: This command will reveal sensitive information. ✖
{Blue}exploit.db {White}- Opens the Exploit Database.
""")
        
    elif cmd == 'changelog':
        print(f"""
{Red}🧾 Patch update {Yellow}1.0.3a {Dark_gray}[8/21/24]{Reset}
{Yellow} # {Gray}Fixed 'port.scan' not working.
{Red} - {Gray}Removed 'Pinger'
{Yellow} # {Gray}Fixed the crash issue
        
{Red}🧾 Changelog info for update {Yellow}1.0 {Dark_gray}[8/18/24]{Reset}
{Green} + {Gray}Aulix release
""")
        
    elif cmd == 'about':
        print(f"""
{Yellow}[{Dark_orange}👑{Yellow}] {Aqua}Creator and Lead developer: {Red}Ban RioT

{Yellow}[{Dark_orange}💎{Yellow}] {Aqua}Contributors: {Red}DeadtrosGaming, Rico34
""")
        
    elif cmd == 'lookup':
        ip = input(f" └ Enter an IP address: ")
        iplookup(ip)

    elif cmd == 'clear':
        clear()

    elif cmd == 'exit':
        print(f"{Green}Goodbye! {Dark_green}Aulix{Green} has been closed.{Reset}")
        break

    elif cmd == 'port.scan':
        ip = input(f" └ Enter an IP address: ")
        port_scan(ip)
    
    elif cmd == 'ip-valid':
        # Example usage in tool.py
        ip = input(" └ Enter an IP address to validate: ")

        if is_valid_ip(ip):
            print(f"{ip} is a valid IP address.")
        else:
            print(f"{ip} is not a valid IP address.")

    elif cmd == 'ddos':
        print(f"{Red} This is currently under development.")

    elif cmd == 'tracert':
        target = input(f" └ Enter an IP address: ")
        traceroute(target)

    elif cmd == 'nslookup':
        domain = input(f" └ Enter an IP address: ")
        nslookup(domain)

    elif cmd == 'path.ping':
        target = input(f" └ Enter an IP address: ")
        pathping(target)

    elif cmd == 'nbtstat':
        ip = input(f" └ Enter an IP address: ")
        get_netbios_info(ip)

    elif cmd == 'gamertag.search':
        print(f"{Red}This is currently under development.")

    elif cmd == 'whois':
        domain = input(f" └ Enter a domain name: ")
        whois_lookup(domain)

    elif cmd == 'dig':
        dig_tool()

    elif cmd == 'phone.lookup':
        print(f"{Red}This is currently under development.")

    elif cmd == 'weather.resolver':
        postal_code = input(f" └ Enter a postal code: ")
        get_weather(postal_code)

    elif cmd == 'putty':
        check_and_open_putty()

    elif cmd == 'ip.info':
        public_ip = get_public_ip()
        if public_ip:
            #print(f"Your public IP address is: {public_ip}")
            self_ip_lookup(public_ip)
        else:
            print("Unable to determine public IP address.")

    elif cmd == 'net.sniff':
        print("Starting network sniffer...")
    
        # Sniff packets on the network interface
        sniff(prn=packet_callback, store=False)
    elif cmd == 'web.scan':
        target_url = input("Enter the target URL (e.g., http://example.com): ").strip()
        
        print(f"{Dark_aqua}Starting scan on {Yellow}{target_url}...")
        check_http_methods(target_url)
        check_common_paths(target_url)
        check_sql_injection(target_url)
        check_xss_vulnerability(target_url)
        print(f"{Dark_green}Scan completed {Green}successfully")

    elif cmd == 'exploit.db':
        url = 'https://www.exploit-db.com'
        print_underlined_link(url)

    elif cmd == 'netsh':
        netsh_pro()

    elif cmd == 'subdomain.sniff':
        domain_name = input("Enter the domain to scan (e.g., example.com): ").strip()
        domain_scanner(domain_name, sub_domnames)
    
    elif cmd == 'ssltls.scanner':
        ssltlsscanner()

    elif cmd == 'instagram.scraper':
        username = input('Username: ')
        scrape_instagram_profile(username)

    elif cmd == 'doxtool':
        print(f"{Red}This is currently under development.")
