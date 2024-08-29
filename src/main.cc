#include "../include/FirstHandler.hh"
#include "../include/SecondHandler.hh"
#include "../include/ThirdHandler.hh"
#include <cstdint>
#include <cstring>
#include <iostream>
#include <thread>

struct IPRange {
  struct in_addr start;
  struct in_addr end;
};

// Функция для проверки, находится ли IP в заданном диапазоне
bool is_ip_in_range(const struct in_addr &ip, const IPRange &range) {
  return (ntohl(ip.s_addr) >= ntohl(range.start.s_addr) &&
          ntohl(ip.s_addr) <= ntohl(range.end.s_addr));
}

void distributeAndProcess(const pcap_pkthdr &header,
                          const std::vector<uint8_t> &data,
                          IPRange &rangeForFirst, IPRange &rangeForSecond) {
  std::unique_ptr<Packet> packet =
      std::make_unique<Packet>(std::move(header), std::move(data));

  uint16_t destPort;

  // Проверяем, какой транспортный протокол используется
  if (packet->ipHeader->ip_p == IPPROTO_TCP) {
    const struct tcphdr *tcpHeader =
        reinterpret_cast<const struct tcphdr *>(packet->transportHeader);
    destPort = ntohs(tcpHeader->th_dport);
  } else if (packet->ipHeader->ip_p == IPPROTO_UDP) {
    const struct udphdr *udpHeader =
        reinterpret_cast<const struct udphdr *>(packet->transportHeader);
    destPort = ntohs(udpHeader->uh_dport);
  }

  if (is_ip_in_range(packet->ipHeader->ip_dst, rangeForFirst)) {
    firstQueue.push(std::move(packet));
  } else if (is_ip_in_range(packet->ipHeader->ip_dst, rangeForSecond) &&
             destPort == 8080) {
    secondQueue.push(std::move(packet));
  } else {
    thirdQueue.push(std::move(packet));
  }
}

int main(int argc, char *argv[]) {
  if (argc != 2) {
    std::cerr << "Usage: " << argv[0] << " <pcap file path>" << std::endl;
    return 1;
  }

  char *filePath = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];

  pcap_t *handle = pcap_open_offline(filePath, errbuf);

  if (!handle) {
    std::cerr << "Couldn't open pcap file: " << errbuf << std::endl;
    return 1;
  }

  IPRange rangeForFirst, rangeForSecond;
  inet_pton(AF_INET, "11.0.0.3", &rangeForFirst.start);
  inet_pton(AF_INET, "11.0.0.200", &rangeForFirst.end);
  inet_pton(AF_INET, "12.0.0.3", &rangeForSecond.start);
  inet_pton(AF_INET, "12.0.0.200", &rangeForSecond.end);

  std::thread t1(FirstHandler::handler);
  std::thread t2(SecondHandler::handler);
  std::thread t3(ThirdHandler::handler);

  pcap_pkthdr *header;
  const u_char *packet;

  while (pcap_next_ex(handle, &header, &packet) > 0) {
    // Создаем копии данных для передачи в очередь,
    // т.к. pcap_next_ext не гарантирует того, что указатели будут указывать на
    // корректные данные
    const pcap_pkthdr headerCopy = *header;
    const std::vector<uint8_t> packetCopy(packet, packet + header->caplen);

    distributeAndProcess(headerCopy, packetCopy, rangeForFirst, rangeForSecond);
  }

  firstQueue.push(nullptr);
  secondQueue.push(nullptr);
  thirdQueue.push(nullptr);

  pcap_close(handle);

  t1.join();
  t2.join();
  t3.join();

  return 0;
}
