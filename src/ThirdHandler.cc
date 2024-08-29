#include "../include/ThirdHandler.hh"
#include <iostream>
#include <thread>

std::queue<std::unique_ptr<Packet>> thirdQueue;

void ThirdHandler::processHandler(std::unique_ptr<Packet> packet,
                                  pcap_dumper_t *dumper) {
  uint16_t destPort;
  uint16_t srcPort;

  // Проверяем, какой транспортный протокол используется
  if (packet->ipHeader->ip_p == IPPROTO_TCP) {
    const struct tcphdr *tcpHeader =
        reinterpret_cast<const struct tcphdr *>(packet->transportHeader);

    std::this_thread::sleep_for(std::chrono::seconds(2)); // ждем 2 секунды
    auto now = std::chrono::system_clock::now();
    auto seconds = std::chrono::time_point_cast<std::chrono::seconds>(now);

    // Если текущее время в секунданх кратно двум, то записываем
    if (seconds.time_since_epoch().count() % 2 == 0) {
      pcap_dump((u_char *)dumper, &packet->header, packet->data.data());
    }

  } else if (packet->ipHeader->ip_p == IPPROTO_UDP) {
    const struct udphdr *udpHeader =
        reinterpret_cast<const struct udphdr *>(packet->transportHeader);
    uint16_t destPort = ntohs(udpHeader->uh_dport);
    uint16_t srcPort = ntohs(udpHeader->uh_sport);
    // Если порты получения и отправки одинаковы, то записываем
    if (srcPort == destPort) {
      pcap_dump((u_char *)dumper, &packet->header, packet->data.data());
      std::cout << "Обработчик 3: Найдено совпадение port = " << srcPort
                << std::endl;
    }
  }
}

void ThirdHandler::handler() {
  const char *name = "result_3.pcap";
  pcap_t *handle = pcap_open_dead(DLT_EN10MB, 65535);
  pcap_dumper_t *dumper = pcap_dump_open(handle, name);

  while (true) {

    if (thirdQueue.empty()) {
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
      continue;
    }

    std::unique_ptr<Packet> packet = std::move(thirdQueue.front());
    thirdQueue.pop();

    if (packet == nullptr)
      break;

    processHandler(std::move(packet), dumper);
  }
  pcap_dump_close(dumper);
  pcap_close(handle);
}
