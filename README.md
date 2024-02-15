# packet-Analysis



<img width="300" alt="ans" src="https://github.com/wngh1212/CTF-packet-Analysis/assets/88926634/12de3557-1925-4348-9d2b-fcd14b352cfe"><br>
다른 사용자가 검색한 문자열 3가지를 찾는 문제이다.
HTTP통신으로 넘어가는 암호화된 문자열들을 발견하였고
<img width="1564" alt="pac" src="https://github.com/wngh1212/CTF-packet-Analysis/assets/88926634/ce76b5a0-03a5-4951-80be-024de6fc4000"><br>
일일이 찾아가며 복사하여 디코딩하는 것은 비효율 적이기 때문에 q= 파라미터로 넘어가는 값들을 파이썬 스크립트로 추출
```import scapy.all as scapy


def extract_search_queries(pcap_file):
    queries = []

    # Read the pcap file
    packets = scapy.rdpcap(pcap_file)

    for packet in packets:
        if packet.haslayer(scapy.TCP):
            if packet[scapy.TCP].dport == 80 and packet.haslayer(scapy.Raw):
                http_data = packet[scapy.Raw].load.decode('utf-8', errors='ignore')
                if "GET" in http_data and "Host" in http_data:
                    url = http_data.split(" ")[1]
                    if "q=" in url:
                        query = url.split("q=")[1].split("&")[0]
                        queries.append(query)

    return queries

pcap_file_path = 'net02.pcap'

search_queries = extract_search_queries(pcap_file_path)

for query in search_queries:
    print(query)
```
<img width="720" alt="sd" src="https://github.com/wngh1212/CTF-packet-Analysis/assets/88926634/b46a80e5-ca47-43e6-b609-85ec0f6c5c05"><br>
해당 값을 디코딩 해주면 된다
<img width="988" alt="en" src="https://github.com/wngh1212/CTF-packet-Analysis/assets/88926634/323ab4fa-a014-4946-a97f-5d87a4fd6911">


