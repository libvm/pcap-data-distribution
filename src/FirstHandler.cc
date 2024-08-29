#include "../include/FirstHandler.hh"
#include <iostream>
#include <thread>

std::queue<std::unique_ptr<Packet>> firstQueue;

void FirstHandler::processHandler(std::unique_ptr<Packet> packet,
                                  pcap_dumper_t *dumper, size_t &packetCount) {
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
  if (destPort == 7070) {
    std::cout << "Обработчик 1: Пакет под номером " << packetCount
              << " игнорируется" << std::endl;
  } else {
    pcap_dump((u_char *)dumper, &packet->header, packet->data.data());
    packetCount++;
  }
}

void FirstHandler::handler() {
  size_t packetCount = 0;
  const char *name = "result_1.pcap";
  pcap_t *handle = pcap_open_dead(DLT_EN10MB, 65535);
  pcap_dumper_t *dumper = pcap_dump_open(handle, name);

  while (true) {
    // Ждем пока не появятся элементы в очереди
    if (firstQueue.empty()) {
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
      continue;
    }

    std::unique_ptr<Packet> packet = std::move(firstQueue.front());
    firstQueue.pop();

    if (packet == nullptr)
      break;

    processHandler(std::move(packet), dumper, packetCount);
  }
  pcap_dump_close(dumper);
  pcap_close(handle);
};
