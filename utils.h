/*
 * Copyright Antti Kultanen <antti.kultanen@molukki.com>
 *
 * nflog_dns is licensed under GNU GPL v2 or later; see LICENSE file
 */

#pragma once

#include <string>
#include <cstdint>
#include <syslog.h>
#include <spdlog/logger.h>
#include "config.h"

struct _code;
typedef struct _code CODE;
extern CODE facilitynames[];

struct Stats {
    uint64_t invalid_packets = 0;
    uint64_t dns_responses = 0;
    uint64_t logged_records = 0;
    uint64_t logged_errors = 0;
};
extern Stats packet_stats;

std::string bool_to_string(const bool value);

bool is_number(const char* facility_arg);

int parse_syslog_code(const char* facility_arg, const CODE* syslog_code_table);

int parse_bool(const char *str);

void set_setting(const RecordOption opt, const bool setting_value);

std::string qtype_to_string(const Tins::DNS::QueryType queryType);

std::string rcode_to_string(const ns_rcode rcode);

void log_stats(spdlog::logger& dns_logger);

void process_dns_packet(const uint8_t* payload,
    const int payload_len,
    spdlog::logger& dns_logger);
