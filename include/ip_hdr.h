#ifndef IP_HDR_H
#define IP_HDR_H

#include <cstdint>

// Структура IP-заголовка (IPv4)
struct ip_hdr {
    uint8_t  ip_hl:4,     // Длина заголовка
             ip_v:4;      // Версия
    uint8_t  ip_tos;      // Тип обслуживания
    uint16_t ip_len;      // Общая длина
    uint16_t ip_id;       // Идентификация
    uint16_t ip_off;      // Флаги фрагментации и смещение
    uint8_t  ip_ttl;      // Время жизни
    uint8_t  ip_p;        // Протокол
    uint16_t ip_sum;      // Контрольная сумма
    uint32_t ip_src;      // IP-адрес источника
    uint32_t ip_dst;      // IP-адрес назначения
};

#endif // IP_HDR_H 