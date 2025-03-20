#ifndef IP_HDR_H
#define IP_HDR_H

#include <cstdint>

// Используем собственные структуры только для Windows или если они не определены в системных заголовках
#if defined(_WIN32) || !defined(HAVE_NETINET_IP_H)

// Структура IP-заголовка (IPv4)
struct ids_ip_hdr {
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

#else
// В Linux используем системные определения из netinet/ip.h
#include <netinet/ip.h>
// Определяем псевдоним для нашей структуры
typedef struct ip ids_ip_hdr;
#endif

#endif // IP_HDR_H 