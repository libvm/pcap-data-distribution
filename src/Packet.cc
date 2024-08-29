#include "../include/Packet.hh"

Packet::Packet(const pcap_pkthdr _header, const std::vector<uint8_t> _data)
    : header(_header), data(_data) {
  // Получаем указатели для более удобной навигации по пакету
  initEthHeader();
  initIPHeader();
  initTransportHeader();
}

void Packet::initEthHeader() {
  ethHeader = reinterpret_cast<const struct ether_header *>(data.data());
}

void Packet::initIPHeader() {
  if (ntohs(ethHeader->ether_type) == ETHERTYPE_IP) {
    ipHeader = reinterpret_cast<const struct ip *>(data.data() +
                                                   sizeof(struct ether_header));
  }
}

void Packet::initTransportHeader() {
  size_t ipHeaderLength = ipHeader->ip_hl * 4;
  transportHeader = data.data() + sizeof(struct ether_header) + ipHeaderLength;
}
