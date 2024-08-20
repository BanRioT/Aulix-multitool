
# Aulix created by Ban RioT
_e='partner'
_d='system'
_c='partners'
_b='careers'
_a='secure'
_Z='search'
_Y='asname'
_X='regionName'
_W='countryCode'
_V='Unknown error'
_U='Error:'
_T='\x1b[0m'
_S='service'
_R='portal'
_Q='test'
_P='api'
_O='forum'
_N='putty'
_M='cloud'
_L='data'
_K='region'
_J='country'
_I=False
_H='lon'
_G='lat'
_F='support'
_E='message'
_D=None
_C=True
_B='status'
_A='N/A'
import requests,os,socket,subprocess,ipaddress
from scapy.all import IP,ICMP,sr1,conf,sniff,IP,TCP,DNS,DNSQR
import sys,dns.resolver,dns.reversename,whois
from datetime import datetime
import dns.resolver,dns.exception,dns.query,dns.zone,platform,socket,ssl
from bs4 import BeautifulSoup
import instaloader
Dark_red='\x1b[38;2;170;0;0m'
Dark_blue='\x1b[38;2;0;0;170m'
Dark_aqua='\x1b[38;2;0;170;170m'
Dark_purple='\x1b[38;2;170;0;170m'
Dark_orange='\x1b[38;2;255;170;0m'
Dark_gray='\x1b[38;2;85;85;85m'
Dark_green='\x1b[38;2;0;170;0m'
Black='\x1b[38;2;30;30;30m'
Blue='\x1b[38;2;85;85;255m'
Green='\x1b[38;2;85;255;85m'
Aqua='\x1b[38;2;85;255;255m'
Red='\x1b[38;2;255;85;85m'
Purple='\x1b[38;2;255;85;255m'
Yellow='\x1b[38;2;255;255;85m'
White='\x1b[38;2;255;255;255m'
Gray='\x1b[38;2;171;171;171m'
Reset=_T
def iplookup(ip):
	B=f"http://demo.ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,isp,org,asname,query&lang=en";C=requests.get(B);A=C.json()
	if A.get(_B)=='fail':print(_U,A.get(_E,_V))
	else:print('');print(f"{Dark_orange}IP Address    {White}>  {Dark_green}{A.get('query',_A)}");print(f"{Dark_orange}Country code  {White}>  {Dark_green}{A.get(_W,_A)}");print(f"{Dark_orange}Country       {White}>  {Dark_green}{A.get(_J,_A)}");print(f"{Dark_orange}Region code   {White}>  {Dark_green}{A.get(_K,_A)}");print(f"{Dark_orange}Region name   {White}>  {Dark_green}{A.get(_X,_A)}");print(f"{Dark_orange}City          {White}>  {Dark_green}{A.get('city',_A)}");print(f"{Dark_orange}Zip code      {White}>  {Dark_green}{A.get('zip',_A)}");print(f"{Dark_orange}ISP           {White}>  {Dark_green}{A.get('isp',_A)}");print(f"{Dark_orange}Organization  {White}>  {Dark_green}{A.get('org',_A)}");print(f"{Dark_orange}ASN           {White}>  {Dark_green}{A.get(_Y,_A)}");print(f"{Dark_orange}Latitude      {White}>  {Dark_green}{A.get(_G,_A)}");print(f"{Dark_orange}Longitude     {White}>  {Dark_green}{A.get(_H,_A)}");print(f"{Dark_orange}Location      {White}>  {Dark_green}{A.get(_G,_A)}, {A.get(_H,_A)}")
def clear():os.system('cls')
def port_scan(ip):
	A='XBOX Live';D={1:'TCPMUX',5:'RJE',7:'ECHO',18:'MSP',20:'FTP DATA',21:'FTP',22:'SSH',23:'Telnet',25:'SMTP',53:'DNS',69:'TFTP',80:'HTTP',88:'Kerberos',102:'Iso-tsap',110:'POP3',115:'SFTP',119:'NNTP',123:'NTP',135:'RPC',137:'NetBIOS-ns',139:'NetBIOS',143:'IMAP',161:'SNMP',194:'IRC',381:'HP Openview',383:'HP Openview-data',443:'HTTPS',445:'SMB',465:'SMTPS',587:'Submission',593:'Microsoft DCOM',636:'LDAP',691:'MS Exchange',902:'VMware',993:'IMAPS',995:'POP3S',1194:'OpenVPN',1337:'WASTE',1433:'MSSQL',1589:'CISCO VQP',1725:'STEAM',2082:'cPanel',2083:'radsec',2967:'symantec AV',3074:A,3076:A,3306:'MySQL',3389:'Remote Desktop',3724:'WoW',4664:'Google Desktop',5632:'PCAnywhere',5900:'VNC',8086:'Kaspersky AV',25565:'Minecraft'}
	def B(ip,ports):
		F='Unknown';E=[]
		for A in ports:
			try:B=socket.socket(socket.AF_INET,socket.SOCK_STREAM);B.settimeout(.1);B.connect((ip,A));C=D.get(A,F);print(f"{Yellow}",f"{ip}".ljust(15),f"{A}".ljust(15),f"{C}".ljust(20),f"{Green}OPEN");E.append(A);B.close()
			except:C=D.get(A,F);print(f"{Yellow}",f"{ip}".ljust(15),f"{A}".ljust(15),f"{C}".ljust(20),f"{Red}CLOSED")
		return E
	print(f"{Aqua}",'IP Address'.ljust(15),'Port'.ljust(15),'Service'.ljust(20),'Status                             ');C=[1,5,7,18,20,21,22,23,25,53,69,80,88,102,110,115,119,123,135,137,139,143,161,194,381,383,443,445,465,587,593,636,691,902,993,995,1194,1337,1433,1589,1725,2082,2083,2967,3076,3306,3389,3724,4664,5632,5900,8086,8086,25565];E=B(ip,C)
def ping(ip):
	L='Minimum = ';K='Packets: Sent = ';H='ms';print(f"Please wait...",end='\r',flush=_C);C=subprocess.Popen(['ping','-n','4',ip],stdout=subprocess.PIPE).communicate()[0];C=C.decode('utf-8');D=0;A=0;E=0;I=f"{Red}DEAD";F=f"{Gray}"
	for B in C.split('\n'):
		if B.find(K)!=-1:J=B.strip().split(',');D=int(J[0].strip().replace(K,''));A=int(J[1].strip().replace('Received = ','').split()[0]);E=D-A
	if A>0:I=f"{Green}ALIVE"
	if E<1:F=f"{Green}"
	else:target,ip
	F=f"{Red}";print(f"{Purple}Sent     {Blue}: {Dark_aqua}{D}");print(f"{Purple}Received {Blue}: {Dark_aqua}{A}");print(f"{Purple}Lost     {Blue}: {Dark_aqua}{F}{E} ({E/D*100:.2f}% loss)");print(f"{Purple}Status   {Blue}: {Dark_aqua}{I}")
	if A>0:
		for B in C.split('\n'):
			if B.find(L)!=-1:G=B.strip().split(',');M=int(G[0].strip().replace(L,'').replace(H,''));N=int(G[1].strip().replace('Maximum = ','').replace(H,''));O=int(G[2].strip().replace('Average = ','').replace(H,''));print(f"{Purple}Minimum {Blue}: {Dark_aqua}{M}ms");print(f"{Purple}Maximum {Blue}: {Dark_aqua}{N}ms");print(f"{Purple}Average {Blue}: {Dark_aqua}{O}ms")
def is_valid_ip(ip):
	try:ipaddress.ip_address(ip);return _C
	except ValueError:return _I
def traceroute(target,max_hops=30,timeout=2):
	D=max_hops;C=target;print(f"{Dark_purple}Traceroute to {Yellow}{C} {Dark_purple}with a maximum of {Red}{D} {Dark_purple}hops:\n");conf.verb=0
	for B in range(1,D+1):
		E=IP(dst=C,ttl=B)/ICMP();A=sr1(E,timeout=timeout)
		if A is _D:print(f"{Dark_aqua}{B}{Aqua}: {Red}Request timed out.")
		elif A.type==11:print(f"{Dark_aqua}{B}{Aqua}: {Blue}{A.src}")
		elif A.type==0:print(f"{Dark_aqua}{B}{Aqua}: {Dark_orange}{A.src}");print(f"{Green}Reached target.\n");break
def nslookup(domain):
	B=domain
	try:
		D=dns.resolver.resolve(B,'A');print(f"{Dark_aqua}A Records (IPv4) for {Aqua}{B}{Dark_aqua}:")
		for A in D:print(f"{Red}└ {Dark_green}{A}")
		try:
			F=dns.resolver.resolve(B,'AAAA');print(f"\n{Dark_aqua}AAAA Records (IPv6) for {Aqua}{B}{Dark_aqua}:")
			for A in F:print(f"{Red}└ {Dark_green}{A}")
		except dns.resolver.NoAnswer:print(f"\n{Red}No AAAA (IPv6) records found.")
		G=dns.resolver.resolve(B,'MX');print(f"\n{Dark_aqua}MX Records for {Aqua}{B}{Dark_aqua}:")
		for A in G:print(f"{Red}└ {Dark_green}{A.preference} {A.exchange}")
		H=dns.resolver.resolve(B,'NS');print(f"\n{Dark_aqua}NS Records for {Aqua}{B}{Dark_aqua}:")
		for A in H:print(f"{Red}└ {Dark_green}{A}")
		I=dns.resolver.resolve(B,'SOA');print(f"\n{Dark_aqua}SOA Record for {Aqua}{B}{Dark_aqua}:")
		for A in I:print(f"{Dark_red}MNAME    {Purple}> {Yellow}{A.mname}");print(f"{Dark_red}RNAME    {Purple}> {Yellow}{A.rname}");print(f"{Dark_red}Serial   {Purple}> {Yellow}{A.serial}");print(f"{Dark_red}Refresh  {Purple}> {Yellow}{A.refresh}");print(f"{Dark_red}Retry    {Purple}> {Yellow}{A.retry}");print(f"{Dark_red}Expire   {Purple}> {Yellow}{A.expire}");print(f"{Dark_red}Minimum  {Purple}> {Yellow}{A.minimum}")
		try:
			E=D[0].to_text();J=dns.reversename.from_address(E);K=dns.resolver.resolve(J,'PTR');print(f"\n{Dark_aqua}PTR Record for IP {Aqua}{E}{Dark_aqua}:")
			for A in K:print(f"  {A}")
		except Exception as C:print(f"\n{Red}PTR Record lookup failed:",C)
	except dns.resolver.NXDOMAIN:print(f"{Red}The domain {Dark_red}{B} {Red}does not exist.")
	except dns.resolver.Timeout:print(f"{Red}Request timed out for {Dark_red}{B}{Red}.")
	except dns.resolver.NoAnswer:print(f"{Red}No answer was received for {Dark_red}{B}{Red}.")
	except Exception as C:print(f"{Red}An error occurred: {Dark_red}{C}")
import time,statistics
from scapy.all import IP,ICMP,sr1,conf
def ping(host,count=4,timeout=2):
	'Ping a host and return the round-trip times.';A=[]
	for G in range(count):
		B=IP(dst=host)/ICMP();C=time.time();D=sr1(B,timeout=timeout,verbose=0);E=time.time()
		if D:F=(E-C)*1000;A.append(F)
		else:A.append(_D)
	return A
def pathping(target,max_hops=30,ping_count=4,timeout=2):
	'Perform a pathping-like operation.';G=timeout;F=max_hops;E=target;print(f"{Dark_aqua}Pathping to {Blue}{E}{Dark_aqua} with a maximum of {Purple}{F}{Dark_aqua} hops:");conf.verb=0;H=18
	for B in range(1,F+1):
		I=IP(dst=E,ttl=B)/ICMP();D=sr1(I,timeout=G)
		if D is _D:print(f"{Red}{B}: Request timed out.");continue
		C=D.src;A=ping(C,count=ping_count,timeout=G);A=[A for A in A if A is not _D]
		if A:J=min(A);K=statistics.mean(A);L=max(A);M=f"{B}: {C}";N=f"{Blue}{B}{Yellow}:  {White}{C}";O=N+' '*(H-len(M));print(f"{O}{Dark_green}Min{White}/{Aqua}Avg{White}/{Yellow}Max RTT: {Dark_green}{J:.2f}{White}/{Aqua}{K:.2f}{White}/{Yellow}{L:.2f} {Gray}ms")
		else:print(f"{Red}{B}: {C} All pings timed out.")
		if D.type==0:print('Reached target.');break
def get_netbios_info(ip):
	'Retrieve and display NetBIOS information for the given IP address.'
	try:B=socket.gethostbyaddr(ip)[0];print(f"Hostname: {B}")
	except socket.herror:print('Hostname: Not resolved')
	try:A=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);A.settimeout(2);C=b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00';A.sendto(C,(ip,137));D,F=A.recvfrom(1024);print(f"Raw response: {D}")
	except socket.error as E:print(f"Socket error: {E}")
	finally:A.close()
def format_date(date):
	'Format date object to a readable string.';A=date
	if isinstance(A,list):A=A[0]if A else _D
	return A.strftime('%Y-%m-%d %H:%M:%S')if A else _A
def whois_lookup(domain):
	'Perform a WHOIS lookup for the given domain and print detailed information.';C=domain;B=', '
	try:A=whois.whois(C);print(f"WHOIS Information for {C}:\n");print(f"{Dark_purple}Domain Name      {Blue}>  {Green}{A.domain_name}");print(f"{Dark_purple}Registrar        {Blue}>  {Green}{A.registrar}");print(f"{Dark_purple}Creation Date    {Blue}>  {Green}{format_date(A.creation_date)}");print(f"{Dark_purple}Expiration Date  {Blue}>  {Green}{format_date(A.expiration_date)}");print(f"{Dark_purple}Updated Date     {Blue}>  {Green}{format_date(A.updated_date)}");print(f"{Dark_purple}Status           {Blue}>  {Green}{B.join(A.status or[])}");print(f"{Dark_purple}Name Servers     {Blue}>  {Green}{B.join(A.name_servers or[])}");print(f"{Dark_purple}Emails           {Blue}>  {Green}{B.join(A.emails or[])}");print(f"{Dark_purple}Org              {Blue}>  {Green}{A.org or _A}")
	except Exception as D:print(f"Error performing WHOIS lookup: {D}")
def perform_query(domain,record_type):
	'Perform a DNS query for the specified record type.';B=domain;A=record_type
	try:
		C=dns.resolver.resolve(B,A);print(f"\n{Green}{A} {Dark_green}records for {Green}{B}:")
		for D in C:print(f"  {Yellow}{D.to_text()}")
	except(dns.resolver.NoAnswer,dns.resolver.NXDOMAIN):print(f"{Red}No answer or domain does not exist for {B} with record type {A}.")
	except dns.exception.DNSException as E:print(f"{Dark_red}DNS query failed for {A}: {Red}{E}")
def dig_tool():
	A=input(f" └ Enter a IP address: ");print(f"\nPerforming DNS queries for {A}...\n");B=['A','AAAA','MX','NS','TXT','CNAME','SOA','PTR','SRV','NAPTR','DS','DNSKEY','RRSIG','TLSA','CAA']
	for C in B:perform_query(A,C)
def get_weather(postal_code):
	C='location';B='current'
	def E(code):
		try:
			A=requests.get(f"http://api.weatherapi.com/v1/current.json?key=638e350524ab4650a4303224220807&q={code}&aqi=no",headers={'User-Agent':'5.0 (Windows NT 10.0; WOW64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.5666.197 Safari/537.36'})
			if A.status_code==200:return{_B:_C,_L:A.json()}
			else:return{_B:_I,_E:f"Invalid response ({A.status_code})"}
		except Exception as B:return{_B:_I,_E:f"Unexpected error: {B}"}
	D=E(postal_code)
	if D[_B]:A=D[_L];print(f"""
{Green}Time           {Yellow}> {Purple}{A[C].get("localtime")}
{Green}City           {Yellow}> {Purple}{A[C].get("name")}
{Green}State          {Yellow}> {Purple}{A[C].get(_K)}
{Green}Country        {Yellow}> {Purple}{A[C].get(_J)}
{Green}Timezone       {Yellow}> {Purple}{A[C].get("tz_id")}

{Green}Clouds         {Yellow}> {Purple}{A[B][_M]}
{Green}Humidity       {Yellow}> {Purple}{A[B]["humidity"]}%
{Green}UV Index       {Yellow}> {Purple}{A[B]["uv"]}
{Green}Pressure       {Yellow}> {Purple}{A[B]["pressure_in"]} in, {A[B]["pressure_mb"]} mb.

{Green}Condition      {Yellow}> {Purple}{A[B]["condition"]["text"]}
{Green}Day/Night      {Yellow}> {Purple}{"Day"if A[B]["is_day"]==1 else"Night"}
{Green}Wind Speed     {Yellow}> {Purple}{A[B]["wind_mph"]} mph, {A[B]["wind_kph"]} kph.

{Green}Visibility     {Yellow}> {Purple}{A[B]["vis_miles"]} miles, {A[B]["vis_km"]} km.
{Green}Temperature    {Yellow}> {Purple}{A[B]["temp_f"]}°F, {A[B]["temp_c"]}°C
{Green}Precipitation  {Yellow}> {Purple}{A[B]["precip_in"]} in, {A[B]["precip_mm"]} mm.""")
	else:print(f"Error: {D[_E]}")
def check_and_open_putty():
	F='Windows';C={F:'putty.exe','Linux':_N,'Darwin':_N};B=platform.system();A=_D
	if B in C:
		D=C[B];A=which(D)
		if B==F:
			G=[os.path.expandvars('%ProgramFiles%\\PuTTY'),os.path.expandvars('%ProgramFiles(x86)%\\PuTTY'),os.path.expanduser('~/Desktop/PuTTY')]
			for dir in G:
				E=os.path.join(dir,D)
				if os.path.isfile(E):A=E;break
	if A:
		try:subprocess.Popen([A]);print(f"{Green}PuTTY has been opened.")
		except Exception as H:print(f"{Red}Error opening PuTTY: {H}")
	else:print(f"{Yellow}PuTTY is not installed or cannot be found. Try moving your {Dark_orange}putty.exe{Yellow} to your desktop.")
def which(executable):
	'Check if an executable exists in the PATH.';B=os.getenv('PATH').split(os.pathsep)
	for C in B:
		A=os.path.join(C,executable)
		if os.path.isfile(A)and os.access(A,os.X_OK):return A
def get_public_ip():
	'Fetch the public IP address of the user.'
	try:A=requests.get('https://api.ipify.org?format=json');A.raise_for_status();return A.json().get('ip')
	except requests.RequestException as B:print(f"Error fetching public IP: {B}");return
def self_ip_lookup(ip):
	'Fetch and display information about the given IP address.';C=f"http://demo.ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,isp,org,asname,query&lang=en"
	try:
		B=requests.get(C);B.raise_for_status();A=B.json()
		if A.get(_B)=='fail':print(_U,A.get(_E,_V))
		else:print('');print(f"{Dark_orange}IP Address    {White}>  {Dark_green}{A.get('query',_A)}");print(f"{Dark_orange}Country code  {White}>  {Dark_green}{A.get(_W,_A)}");print(f"{Dark_orange}Country       {White}>  {Dark_green}{A.get(_J,_A)}");print(f"{Dark_orange}Region code   {White}>  {Dark_green}{A.get(_K,_A)}");print(f"{Dark_orange}Region name   {White}>  {Dark_green}{A.get(_X,_A)}");print(f"{Dark_orange}City          {White}>  {Dark_green}{A.get('city',_A)}");print(f"{Dark_orange}Zip code      {White}>  {Dark_green}{A.get('zip',_A)}");print(f"{Dark_orange}ISP           {White}>  {Dark_green}{A.get('isp',_A)}");print(f"{Dark_orange}Organization  {White}>  {Dark_green}{A.get('org',_A)}");print(f"{Dark_orange}ASN           {White}>  {Dark_green}{A.get(_Y,_A)}");print(f"{Dark_orange}Latitude      {White}>  {Dark_green}{A.get(_G,_A)}");print(f"{Dark_orange}Longitude     {White}>  {Dark_green}{A.get(_H,_A)}");print(f"{Dark_orange}Location      {White}>  {Dark_green}{A.get(_G,_A)}, {A.get(_H,_A)}")
	except requests.RequestException as D:print(f"Error performing IP lookup: {D}")
BLACKLIST={'spotify.com'}
def packet_callback(packet):
	I='Host:';H='Raw';A=packet
	if IP in A:
		B=A[IP].src;C=A[IP].dst
		if TCP in A:
			if A[TCP].dport==80 or A[TCP].sport==80:
				if A.haslayer(H):
					D=A.getlayer(H).load.decode(errors='ignore')
					if I in D:
						E=[A for A in D.split('\n')if A.startswith(I)]
						if E:
							F=E[0].split(' ')[1]
							if F.lower()not in BLACKLIST:print(f"{White}[{Blue}+{White}] {Yellow}HTTP Request: {Aqua}{B} {Red}-> {Dark_aqua}{C}".ljust(168),f" {Yellow}Domain: {Dark_purple}{F}")
		elif DNS in A:
			if A.haslayer(DNSQR):
				G=A[DNSQR].qname.decode().strip('.')
				if G.lower()not in BLACKLIST:print(f"{White}[{Blue}+{White}] {Yellow}DNS Query: {Aqua}{B} {Red}-> {Dark_aqua}{C}".ljust(168),f" {Yellow}Domain: {Dark_purple}{G}")
SQL_PAYLOADS=["' OR '1'='1","' OR '1'='1' --","' OR '1'='1' #","' OR '1'='1' /*"]
XSS_PAYLOADS=["<script>alert('XSS')</script>","<img src=x onerror=alert('XSS')>",'\'"><img src=x onerror=alert(1)>']
HTTP_METHODS=['GET','POST','PUT','DELETE','OPTIONS','TRACE']
def check_sql_injection(url):
	'Check for SQL Injection vulnerabilities.'
	for B in SQL_PAYLOADS:
		A=f"{url}?id={B}"
		try:
			C=requests.get(A)
			if'error'in C.text.lower():print(f"{White}[{Green}+{White}] Potential SQL Injection found at{Blue}: {Dark_orange}{A}")
		except Exception as D:print(f"{White}Error testing {Yellow}SQL Injection{Dark_red}: {Red}{D}")
def check_xss_vulnerability(url):
	'Check for XSS vulnerabilities.'
	for A in XSS_PAYLOADS:
		try:
			B=requests.get(url,params={_Z:A})
			if A in B.text:print(f"{White}[{Green}+{White}] Potential XSS vulnerability found at: {Aqua}{url}{White} with payload{Blue}: {Dark_orange}{A}")
		except Exception as C:print(f"{White}Error testing {Yellow}XSS{Dark_red}: {Red}{C}")
def check_http_methods(url):
	'Check for allowed HTTP methods.'
	try:
		C=requests.options(url);A=C.headers.get('Allow','');print(f"{White}[{Green}+{White}] Allowed HTTP Methods for {Aqua}{url}{Blue}: {Dark_orange}{A}")
		for B in HTTP_METHODS:
			if B not in A:print(f"{Red}# {White}Method not allowed{Blue}: {Dark_orange}{B}")
	except Exception as D:print(f"{White}Error checking {Yellow}HTTP{White} methods{Dark_red}: {Red}{D}")
def check_common_paths(url):
	'Check for common vulnerable paths.';C=['/admin','/login','/dashboard','/uploads','/config']
	for D in C:
		A=f"{url.rstrip('/')}{D}"
		try:
			B=requests.get(A)
			if B.status_code==200:print(f"{White}[{Green}+{White}] Found potential vulnerable path{Blue}: {Dark_orange}{A}")
			else:print(f"    {White}[{Dark_blue}*{White}] Path not found{Blue}: {Dark_orange}{A} {Dark_aqua}({Aqua}Status Code{Dark_red}: {Red}{B.status_code}{Dark_aqua})")
		except Exception as E:print(f"{White}Error checking path {Yellow}{A}{Dark_red}: {Red}{E}")
def print_underlined_link(url):A='\x1b[4m';B=_T;C=f"{A}{Blue}{url}{B}";print(f"{Dark_gray}Note: If you are using the new windows terminal hold down Ctrl then click on the URL below to open the URL in yourbrowser\n{White}Exploit Database: {C}")
def run_netsh_command(command):
	'Executes a netsh command and returns the output.'
	try:A=subprocess.run(['netsh']+command.split(),capture_output=_C,text=_C,check=_C);return A.stdout
	except subprocess.CalledProcessError as B:return f"Error executing command: {B}"
def generate_report():'Generates a comprehensive report with all netsh information.';A='interface show interface';print('Generating Network Information Report...\n');print('Network Interfaces:');B=run_netsh_command(A);print(B);print('IP Configuration:');C=run_netsh_command('interface ip show config');print(C);print('Available Wireless Networks:');D=run_netsh_command('wlan show networks');print(D);print('Routing Table:');E=run_netsh_command('interface ipv4 show route');print(E);print('Network Statistics:');F=run_netsh_command(A);print(F)
def netsh_pro():generate_report()
sub_domnames=['www','mail','blog',_O,'m','shop','wiki','community','ads','docs','news',_F,_P,'cdn','app','demo','login',_Q,'admin',_B,_R,'webmail',_a,'oauth','my','git',_O,'download','static','store','help','shop',_S,'files','calendar','user','chat',_F,_O,_b,'about','events','newsletter','media',_c,_c,'developer',_P,'connect','dev',_a,_M,'app',_Q,'home','services','docs','code',_Z,_F,'info',_R,'intranet','outlook','mail','news','vpn','store','checkout','book','media','links','team',_b,'jobs','recruitment','beta','site','play','account','network',_P,'login','management','console',_d,_M,_S,_d,'project','web','site',_e,_e,'marketing',_L,'group',_Q,'sandbox','dev','demo','stage','labs',_F,'report',_S,'feedback','customer',_F,'dashboard','client',_R,'product']
def domain_scanner(domain_name,sub_domnames):
	print('[+] Started subdomain extraction.')
	for D in sub_domnames:
		A=f"https://{D}.{domain_name}"
		try:
			B=requests.get(A,timeout=5)
			if B.status_code in[200,301,302]:C=Green
			elif B.status_code in[400,401,403,404,500,502,503,504]:C=Red
			else:C=Purple
			print(f"{White}[{C}{B.status_code}{White}] [{Green}+{White}] {Blue}* {Aqua}{A}")
		except requests.RequestException:print(f"{White}[{Yellow}N/A{White}] [{Red}-{White}] {Blue}* {Aqua}{A}")
def check_tls_version(hostname,port):
	A=hostname;C={ssl.PROTOCOL_TLS:'TLS (default)',ssl.PROTOCOL_TLSv1:'TLSv1.0',ssl.PROTOCOL_TLSv1_1:'TLSv1.1',ssl.PROTOCOL_TLSv1_2:'TLSv1.2'}
	for(D,B)in C.items():
		try:
			E=ssl.SSLContext(D)
			with socket.create_connection((A,port))as F:
				with E.wrap_socket(F,server_hostname=A)as H:print(f"{B} is supported.")
		except Exception as G:print(f"{B} is not supported: {G}")
def check_cipher_suites(hostname,port):
	A=hostname
	try:
		B=ssl.create_default_context();B.set_ciphers('ALL')
		with socket.create_connection((A,port))as C:
			with B.wrap_socket(C,server_hostname=A)as D:
				print('Cipher suites:')
				for E in D.cipher():print(f"  - {E[0]}")
	except Exception as F:print(f"Error checking cipher suites: {F}")
def check_certificate(hostname,port):
	B=hostname
	try:
		C=ssl.create_default_context()
		with socket.create_connection((B,port))as D:
			with C.wrap_socket(D,server_hostname=B)as E:A=E.getpeercert();print('Certificate information:');print(f"  - Subject: {A.get('subject')}");print(f"  - Issuer: {A.get('issuer')}");print(f"  - Not Before: {A.get('notBefore')}");print(f"  - Not After: {A.get('notAfter')}");print(f"  - Serial Number: {A.get('serialNumber')}")
	except Exception as F:print(f"Error checking certificate: {F}")
def ssltlsscanner():
	B=input('Enter Target IP Address: ').strip();A=input('Enter Target Port: ').strip()
	try:A=int(A)
	except ValueError:print('Invalid port number. Please enter a valid integer.');return
	print(f"Scanning {B}:{A}...");print('\nChecking TLS versions...');check_tls_version(B,A);print('\nChecking cipher suites...');check_cipher_suites(B,A);print('\nChecking certificate...');check_certificate(B,A)
import instaloader,sys
def scrape_instagram_profile(username):
	B=instaloader.Instaloader()
	try:A=instaloader.Profile.from_username(B.context,username)
	except instaloader.exceptions.InstaloaderException as C:print(f"Error: {C}");return
	print(f"{Dark_aqua}Username   {Purple}> {Yellow}{A.username}");print(f"{Dark_aqua}Full Name  {Purple}> {Yellow}{A.full_name}");print(f"{Dark_aqua}Bio        {Purple}> {Yellow}{A.biography}");print(f"{Dark_aqua}Followers  {Purple}> {Yellow}{A.followers}");print(f"{Dark_aqua}Following  {Purple}> {Yellow}{A.followees}");print(f"{Dark_aqua}Posts      {Purple}> {Yellow}{A.mediacount}");print(f"\n{Red}Recent Posts:")
	for D in A.get_posts():print(f"- {D.url}")
computer_name=socket.gethostname()
os.system('title Aulix')
print(f"✨ {Aqua}Welcome {Dark_aqua}{computer_name} {Aqua}to Aulix {Black}Build Version: 1.0.0\n\n{Yellow}📌 Aulix {Purple}version: {White}1.0 {Dark_gray}(Use changelog to view the changelog)")
while _C:
	cmd=input(f"{Red} » {White}")
	if cmd=='help':print(f"""
{Yellow}- {Purple}[{Green}Basic commands{Purple}]{Reset}:
{Blue}help {White}- Shows a list of available commands.
{Blue}about {White}- Shows information about Aulix.
{Blue}clear {White}- Clears the terminal.
{Blue}changelog {White}- Shows the changelog information.
{Blue}exit {White}- Closes Aulix.

{Yellow}- {Purple}[{Green}Network commands{Purple}]{Reset}:
{Blue}port.scan {White}- Scans a host for open ports.
{Blue}ping {White}- Sends packets to check the status of a host.
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
{Blue}phone.lookup {White}- Lookup website information like hosting service, domain owner info, etc.
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
	elif cmd=='changelog':print(f"\n{Red}🧾 Changelog info for update {Yellow}1.0 {Dark_gray}[8/18/24]{Reset}\n{Green} + {Gray}Aulix release{Reset}\n")
	elif cmd=='about':print(f"\n{Yellow}[{Dark_orange}👑{Yellow}] {Aqua}Creator and Lead developer: {Red}Ban RioT\n\n{Yellow}[{Dark_orange}💎{Yellow}] {Aqua}Contributors: {Red}DeadtrosGaming, Rico34\n")
	elif cmd=='lookup':ip=input(f" └ Enter an IP address: ");iplookup(ip)
	elif cmd=='clear':clear()
	elif cmd=='exit':print(f"{Green}Goodbye! {Dark_green}Aulix{Green} has been closed.{Reset}");break
	elif cmd=='pscan':ip=input(f" └ Enter an IP address: ");port_scan(ip)
	elif cmd=='ping':ip=input(f" └ Enter an IP address: ");ping(ip)
	elif cmd=='ip-valid':
		ip=input(' └ Enter an IP address to validate: ')
		if is_valid_ip(ip):print(f"{ip} is a valid IP address.")
		else:print(f"{ip} is not a valid IP address.")
	elif cmd=='ddos':print(f"{Red} This is currently under development.")
	elif cmd=='tracert':target=input(f" └ Enter an IP address: ");traceroute(target)
	elif cmd=='nslookup':domain=input(f" └ Enter an IP address: ");nslookup(domain)
	elif cmd=='path.ping':target=input(f" └ Enter an IP address: ");pathping(target)
	elif cmd=='nbtstat':ip=input(f" └ Enter an IP address: ");get_netbios_info(ip)
	elif cmd=='gamertag.search':print(f"{Red}This is currently under development.")
	elif cmd=='whois':domain=input(f" └ Enter a domain name: ");whois_lookup(domain)
	elif cmd=='dig':dig_tool()
	elif cmd=='phone.lookup':print(f"{Red}This is currently under development.")
	elif cmd=='weather.resolver':postal_code=input(f" └ Enter a postal code: ");get_weather(postal_code)
	elif cmd==_N:check_and_open_putty()
	elif cmd=='ip.info':
		public_ip=get_public_ip()
		if public_ip:self_ip_lookup(public_ip)
		else:print('Unable to determine public IP address.')
	elif cmd=='net.sniff':print('Starting network sniffer...');sniff(prn=packet_callback,store=_I)
	elif cmd=='web.scan':target_url=input('Enter the target URL (e.g., http://example.com): ').strip();print(f"{Dark_aqua}Starting scan on {Yellow}{target_url}...");check_http_methods(target_url);check_common_paths(target_url);check_sql_injection(target_url);check_xss_vulnerability(target_url);print(f"{Dark_green}Scan completed {Green}successfully")
	elif cmd=='exploit.db':url='https://www.exploit-db.com';print_underlined_link(url)
	elif cmd=='netsh':netsh_pro()
	elif cmd=='subdomain.sniff':domain_name=input('Enter the domain to scan (e.g., example.com): ').strip();domain_scanner(domain_name,sub_domnames)
	elif cmd=='ssltls.scanner':ssltlsscanner()
	elif cmd=='instagram.scraper':username=input('Username: ');scrape_instagram_profile(username)
	elif cmd=='doxtool':print(f"{Red}This is currently under development.")
