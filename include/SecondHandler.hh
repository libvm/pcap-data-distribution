#pragma once

#include "Packet.hh"
#include <cstring>
#include <memory>
#include <queue>

extern std::queue<std::unique_ptr<Packet>> secondQueue;

class SecondHandler {
private:
  static void processHandler(std::unique_ptr<Packet> packet,
                             pcap_dumper_t *dumper);

public:
  static void handler();
};
