#pragma once

#include "Packet.hh"
#include <memory>
#include <queue>

extern std::queue<std::unique_ptr<Packet>> firstQueue;

class FirstHandler {
private:
  static void processHandler(std::unique_ptr<Packet> packet,
                             pcap_dumper_t *dumper, size_t &packetCount);

public:
  static void handler();
};
