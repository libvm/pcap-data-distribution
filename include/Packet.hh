#pragma once

#include <cstdint>
#include <netinet/ether.h> // Для структуры ether_header
#include <netinet/ip.h>    // Для структуры iphdr
#include <netinet/tcp.h>   // Для структуры tcphdr
#include <netinet/udp.h>   // Для структуры udphdr
#include <pcap.h>
#include <vector>

struct Packet {
  const pcap_pkthdr header;
  const std::vector<uint8_t> data;
  const struct ether_header *ethHeader;
  const struct ip *ipHeader;
  const uint8_t *transportHeader;

  Packet(const pcap_pkthdr _header, const std::vector<uint8_t> _data);

private:
  void initEthHeader();
  void initIPHeader();
  void initTransportHeader();
};
