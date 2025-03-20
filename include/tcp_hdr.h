#ifndef TCP_HDR_H
#define TCP_HDR_H

#include <cstdint>

// Используем собственные структуры только для Windows или если они не определены в системных заголовках
#if defined(_WIN32) || !defined(HAVE_NETINET_TCP_H)

// Структура TCP-заголовка
struct ids_tcp_hdr {
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

#else
// В Linux используем системные определения из netinet/tcp.h
#include <netinet/tcp.h>
// Определяем псевдоним для нашей структуры
typedef struct tcphdr ids_tcp_hdr;
#endif

#endif // TCP_HDR_H 