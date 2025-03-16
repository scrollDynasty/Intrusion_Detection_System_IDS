#ifndef TCP_HDR_H
#define TCP_HDR_H

#include <cstdint>

// Структура TCP-заголовка
struct tcp_hdr {
    uint16_t src_port;    // Порт источника
    uint16_t dst_port;    // Порт назначения
    uint32_t seq;         // Номер последовательности
    uint32_t ack;         // Номер подтверждения
    uint8_t  data_offset; // Смещение данных (4 бита) и зарезервировано (4 бита)
    uint8_t  flags;       // Флаги (FIN, SYN, RST, PSH, ACK, URG)
    uint16_t window;      // Размер окна
    uint16_t checksum;    // Контрольная сумма
    uint16_t urgent_ptr;  // Указатель срочных данных
};

#endif // TCP_HDR_H 