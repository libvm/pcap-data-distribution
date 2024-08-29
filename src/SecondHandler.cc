#include "../include/SecondHandler.hh"
#include <algorithm>
#include <thread>

std::queue<std::unique_ptr<Packet>> secondQueue;

void SecondHandler::processHandler(std::unique_ptr<Packet> packet,
                                   pcap_dumper_t *dumper) {

  // Ищем позицию символа 'x' в data
  auto iter = std::find(packet->data.begin(), packet->data.end(), 'x');
  size_t lengthToCopy = packet->header.caplen;

  if (iter != packet->data.end()) {
    // Если 'x' найден,то копируем до и включая 'x'
    lengthToCopy = std::distance(packet->data.begin(), iter) + 1;
  }

  // Создаем новый вектор для хранения данных
  std::vector<uint8_t> newData(lengthToCopy);
  std::memcpy(newData.data(), packet->data.data(), lengthToCopy);

  pcap_dump((u_char *)dumper, &packet->header, newData.data());
}

void SecondHandler::handler() {
  const char *name = "result_2.pcap";
  pcap_t *handle = pcap_open_dead(DLT_EN10MB, 65535);
  pcap_dumper_t *dumper = pcap_dump_open(handle, name);

  while (true) {

    if (secondQueue.empty()) {
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
      continue;
    }

    std::unique_ptr<Packet> packet = std::move(secondQueue.front());
    secondQueue.pop();

    if (packet == nullptr)
      break;

    processHandler(std::move(packet), dumper);
  }
  pcap_dump_close(dumper);
  pcap_close(handle);
}
