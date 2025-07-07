# Writeup
# Wireshark

## Objective
Use Wireshark to dissect a series of “real-world” PCAPs and answer targeted questions:

FTP capture (ftp.pcap): count failed logins, pull file sizes, extract filenames & commands

Chunked HTTP/2 (https/Exercise.pcap + KeysLogFile.txt): locate Client Hello, decrypt, count frames, read pseudo-headers, export flag

DHCP + NetBIOS + Kerberos (dhcp-netbios-kerberos/*.pcap): decode DHCP options, tally NBNS registrations, spot Kerberos CNameStrings and addresses

ICMP tunnel (dns-icmp/icmp-tunnel.pcap): identify the encapsulated protocol

Log4j attack (http/user-agent.cap + dns-icmp/icmp-tunnel.pcap): spot the anomalous User-Agent, then find and decode the base64 JNDI payload

### Skills Learned
Wireshark display-filter fluency

ftp.response.code == 530 → 737 login failures

ftp.response.code == 213 → file size 39424 (and then extracted resume.doc)

http.request or tls.handshake.type == 1 → Client Hello at frame 16 to accounts.google.com

After loading KeysLogFile.txt, filter http2 → 115 HTTP/2 packets

Frame 322 → :authority: safebrowsing.googleapis.com

Stream reassembly & object export

“Follow TCP Stream” on resume.doc → saw SITE CHMOD 777 resume.doc

“Export → HTTP object list” → pulled ASCII art and revealed FLAG{THM-PACKETMASTER}

DHCP / NetBIOS / Kerberos analysis

dhcp.option.requested_ip_address == 172.16.13.85 → Host Name Galaxy-A12, MAC 9a:81:41:cb:96:6c

nbns.flags.opcode==5 and nbns.name contains "LIVALJM" → 16 registration requests from 192.168.0.52

kerberos.CNameString → saw u5 in AS-REQ → IP 10[.]1[.]12[.]2; in TGS-REP saw xp1$

Anomaly spotting

In http/user-agent.cap, applied http.user_agent as a column → found 6 packets using the misspelled “Mozilla/5.0 (Windows; U; Windows NT 6.4;…)” at packet 52

ICMP tunneling

In icmp-tunnel.pcap, filtered icmp and looked inside the payload → discovered it was carrying DNS-style queries

Log4j base64 forensic

Located the initial JNDI lookup in an HTTP GET, extracted the Base64 string, decoded it to reveal the callback to 10[.]10.[]25[.]42 (for example)

### Tools Used
Wireshark (v3.x)

Display filters, stream follow, TLS decryption via pre-master-secret log

“Export HTTP object list”

Text editor (Pluma) to view ASCII-art and inspect decoded base64

Base64 decoder (built-in or external)

## Steps
---
Ref.1: Scenario
<img width="510" alt="act2- 1scenario" src="https://github.com/user-attachments/assets/f81e4031-af6a-400b-a782-7ae70b3eafe8" />
---
Ref.2: Question 1
<img width="342" alt="act2-2 quesion 1" src="https://github.com/user-attachments/assets/5b7ea894-6fb0-41b8-825c-cb6a34d719d1" />
---
Ref.3: 737 Packets
<img width="718" alt="act2-3 737 packets" src="https://github.com/user-attachments/assets/c6894bc6-0341-41b3-8d02-9c57ca09599b" />
---
Ref.4: Question 2
<img width="509" alt="act2-4 question 2" src="https://github.com/user-attachments/assets/db874cf0-6d45-4be4-9328-dd68148452af" />
---
Ref.5: filtering 213 response code
<img width="742" alt="act2-5 filtering 213 response code" src="https://github.com/user-attachments/assets/ee3955d0-4d3e-4bc9-939e-a6acc62a3461" />
---
Ref.6: followeed tcp stream found resume.doc size
<img width="695" alt="act2-6 followed tcp stream found resume  doc size" src="https://github.com/user-attachments/assets/f277e23f-ef2d-4559-a66e-57f41e385030" />
---
Ref.7: answer is resume.doc
<img width="501" alt="act2-7 answer is obvious resume doc" src="https://github.com/user-attachments/assets/73ee956a-9cbb-4e87-85bf-388a54677713" />
---
Ref.8: Question
<img width="472" alt="act2-8 last question" src="https://github.com/user-attachments/assets/cc35fd4b-bc9d-492c-9e1c-c376130d66b5" />
---
Ref.9: chmod change command 777
<img width="341" alt="act2-9 chmod change command 777" src="https://github.com/user-attachments/assets/90a312d8-a9a9-4f89-876d-bcd46c3de9bb" />
---
Ref.10: All questions answered
<img width="509" alt="act2- 10 all questions answered" src="https://github.com/user-attachments/assets/2baa4209-30e7-4fc9-b755-56c1cdfcc774" />
---
Ref.11: Scenario
<img width="300" alt="hello4-1 scenario" src="https://github.com/user-attachments/assets/3e35c7a8-3a03-472c-91c5-a791776ebd52" />
---
Ref.12: Question 1
<img width="313" alt="hello4-2 question 1" src="https://github.com/user-attachments/assets/a582296a-c462-4021-aee9-c35bbd144aa1" />
---
Ref.13: frame 16 has servername accounts.google.com
<img width="888" alt="hello4-3 frame 16 has servername  accounts google com" src="https://github.com/user-attachments/assets/0e81391b-028e-4ada-a86d-8803b34f9e73" />
---
Ref.14: question 2
<img width="310" alt="hello4-4 question 2" src="https://github.com/user-attachments/assets/84107660-5b43-4f4e-973d-e98edfb67e7b" />
---
Ref.15: imported key and searched http2 finding 115 packets
<img width="925" alt="hello4-5 imported key and searched http2 finding 115 packets" src="https://github.com/user-attachments/assets/a0fb0a59-fe17-4208-a766-c39fd2170a64" />
---
Ref.16: question 3
<img width="301" alt="hello4-6 question 3" src="https://github.com/user-attachments/assets/d9903590-e39d-400e-9bbc-99547078f846" />
---
Ref.17: went to frame 332 and found authority header of http2
<img width="930" alt="hello4-7 went to frame 322 and found authority header of http2 " src="https://github.com/user-attachments/assets/f704e70b-5562-46c8-aa00-3b254897343f" />
---
Ref.18 Next question
<img width="298" alt="hello4-8 question" src="https://github.com/user-attachments/assets/b03872f8-44e3-4abd-9d51-38c395fad00d" />
---
Ref.19: Exporting packets 
<img width="554" alt="hello4-9 exporting packets" src="https://github.com/user-attachments/assets/87f87fb2-0a29-4ada-af97-6ad5384c1169" />
---
Ref.20: found key in exported packet
<img width="854" alt="hello4-10 found key in exported packet" src="https://github.com/user-attachments/assets/49e65c93-2721-4388-a5d8-f656e3bf197b" />
---
Ref.21: All answers
<img width="320" alt="hello4-10 answers" src="https://github.com/user-attachments/assets/db9b80a2-b860-4dd7-9646-d6694c2d4750" />
---
Ref.22: question 
<img width="542" alt="p 1-1 - question" src="https://github.com/user-attachments/assets/a210c8bb-8278-4d39-ad68-a92971cd70dd" />
---
Ref.23: Searching Galaxy-A30 and finding mac address
<img width="681" alt="p 1-2 - searching Galaxy-A30 and finding mac address" src="https://github.com/user-attachments/assets/ebc60938-d83c-496e-b5fa-d6ff6b52c5ca" />
---
Ref.24: Next question
<img width="559" alt="p 1-3 - question 2" src="https://github.com/user-attachments/assets/43c7fef6-766e-4684-9cd3-7dc851988c90" />
---
Ref.25: nbns flag opcode ==5 and nbns.name contain which displays 16 packets
<img width="682" alt="p 1-4 nbns flag opcode ==5 and nbns name contain  which displays 16 packets" src="https://github.com/user-attachments/assets/9dd6648b-f261-4df8-9780-3101894c7c99" />
---
Ref.26: Next question
<img width="682" alt="p 1-4 nbns flag opcode ==5 and nbns name contain  which displays 16 packets" src="https://github.com/user-attachments/assets/210e40dc-7c82-497a-bc3c-bc76b7d3bc74" />
---
Ref.27: dhcp requested hostname and found answer in packet
<img width="695" alt="p 1-6 dhcp requested hostname and found answer in packet" src="https://github.com/user-attachments/assets/bdcb6178-a2f3-4bee-a654-cd47be64b848" />
---
Ref.28: Next question
<img width="539" alt="p 1-7 question 4" src="https://github.com/user-attachments/assets/2e97e310-eccd-4abc-b097-a0e583eb9fae" />
---
Ref.29: searching u5
<img width="689" alt="p 1-8 searching u5" src="https://github.com/user-attachments/assets/621209cd-926f-4d59-a8cb-1c5e3caeb1c8" />
---
Ref.30: Next question
<img width="569" alt="p 1-9 question 5" src="https://github.com/user-attachments/assets/94bb9bef-e45b-4ed3-90d5-a19c92766a87" />
---
Ref.31: searching cname and finding the one with $
<img width="683" alt="p -10 searching cname and finding the one with $" src="https://github.com/user-attachments/assets/12cb1f39-2d0e-41fb-a198-531409ea3937" />
---
Ref.32: All questions answered
<img width="554" alt="p 11- allquestions answered" src="https://github.com/user-attachments/assets/681877c6-4a94-4af1-a7e8-3efbcf7d99ea" />
---
Ref.34: Scenario
<img width="601" alt="yep3 -1 scenario" src="https://github.com/user-attachments/assets/140272ad-7698-4ecf-8c8f-479131878212" />
---
Ref.35: Question 1
<img width="613" alt="yep3-2 question 1" src="https://github.com/user-attachments/assets/4e774f54-33a7-4421-91ba-09553f5350fb" />
---
Ref.36: did http user.agent then applied the user agent as a column and since windows nt 6.4 is anomolous there is 6 packets
<img width="931" alt="yep3-3 did http user agent then applient the user agent as a column and since windows nt 6 4 is anomalous there is 6 packets" src="https://github.com/user-attachments/assets/6735f3ea-82fc-421b-a1db-afab7823e397" />
---
Ref.36: Next question
<img width="314" alt="yep3-4 question 2" src="https://github.com/user-attachments/assets/51211be3-c9e5-46ea-9172-9f5b6aaf9f3e" />
---
Ref.37: packet 52 spells mozilla like mozlila
<img width="958" alt="yep3-5 packet 52 spells mozilla like mozlila" src="https://github.com/user-attachments/assets/cbf61728-4654-4647-a10f-9c2124d75d19" />
---
Ref.37: Next question
<img width="289" alt="yep3-6 question" src="https://github.com/user-attachments/assets/80142e23-e1ef-4017-b951-0291c61528ff" />
---
Ref.38: 444 is first log4j packet
<img width="946" alt="yep3- 7 444 is first log4j packet" src="https://github.com/user-attachments/assets/9188cd27-c5fd-40cd-a0ed-3c702342825d" />
---
Ref.39: Next question
<img width="340" alt="yep3- 8 question" src="https://github.com/user-attachments/assets/ccf4c4dc-abc5-49be-864a-b0e59212befc" />
---
Ref.40: decoding base64 command
<img width="1012" alt="yep3-10 decoding base64 command" src="https://github.com/user-attachments/assets/e2a3b823-239a-47fc-ae1c-05353c554b03" />
---
Ref.41: All questions answered
<img width="305" alt="yep3-11 question answers" src="https://github.com/user-attachments/assets/8999f269-487e-43d2-9af0-811c6a0c35a2" />
---



















