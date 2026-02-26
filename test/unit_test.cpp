/*
 * Copyright Antti Kultanen <antti.kultanen@molukki.com>
 *
 * nflog_dns is licensed under GNU GPL v2 or later; see LICENSE file
 */

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <spdlog/spdlog.h>
#include <spdlog/sinks/ostream_sink.h>
#include <sstream>

#include "../config.h"
#include "../utils.h"

// ============================================================================
// Helpers
// ============================================================================

// Reset config state to defaults before each test that touches it
static void reset_config() {
    // Reset qtypes to all enabled
    enable_qtype(Tins::DNS::A);
    enable_qtype(Tins::DNS::AAAA);
    enable_qtype(Tins::DNS::CNAME);
    enable_qtype(Tins::DNS::MX);
    enable_qtype(Tins::DNS::PTR);
    enable_qtype(Tins::DNS::TXT);
    // Reset rcodes: only NOERROR enabled by default
    enable_rcode(ns_r_noerror);
    disable_rcode(ns_r_formerr);
    disable_rcode(ns_r_servfail);
    disable_rcode(ns_r_nxdomain);
    disable_rcode(ns_r_notimpl);
    disable_rcode(ns_r_refused);
}

// Reset stats to zero
static void reset_stats() {
    packet_stats = Stats{};
}

// Create a test logger that captures output to a string stream
static std::shared_ptr<spdlog::logger> make_test_logger(std::ostringstream& oss) {
    auto sink = std::make_shared<spdlog::sinks::ostream_sink_mt>(oss);
    auto logger = std::make_shared<spdlog::logger>("test", sink);
    logger->set_level(spdlog::level::trace);
    logger->set_pattern("%v");  // message only, no timestamp/level prefix
    return logger;
}

// ============================================================================
// bool_to_string
// ============================================================================

TEST_CASE("bool_to_string") {
    CHECK(bool_to_string(true)  == "yes");
    CHECK(bool_to_string(false) == "no");
}

// ============================================================================
// is_number
// ============================================================================

TEST_CASE("is_number - valid integers") {
    CHECK(is_number("0")     == true);
    CHECK(is_number("1")     == true);
    CHECK(is_number("123")   == true);
    CHECK(is_number("65535") == true);  // USHRT_MAX
}

TEST_CASE("is_number - out of range") {
    CHECK(is_number("65536") == false);  // USHRT_MAX + 1
    CHECK(is_number("99999") == false);
}

TEST_CASE("is_number - non-numeric input") {
    CHECK(is_number("")       == false);
    CHECK(is_number("abc")    == false);
    CHECK(is_number("12abc")  == false);
    CHECK(is_number("abc12")  == false);
    CHECK(is_number(" 123")   == false);
    CHECK(is_number("12 3")   == false);
}

TEST_CASE("is_number - negative numbers") {
    CHECK(is_number("-1")  == false);
    CHECK(is_number("-0")  == false);
}

TEST_CASE("is_number - floating point") {
    CHECK(is_number("1.0") == false);
    CHECK(is_number("1.5") == false);
}

// ============================================================================
// parse_bool
// ============================================================================

TEST_CASE("parse_bool - true values") {
    CHECK(parse_bool("1")      == 1);
    CHECK(parse_bool("enable") == 1);
    CHECK(parse_bool("on")     == 1);
    CHECK(parse_bool("true")   == 1);
    CHECK(parse_bool("yes")    == 1);
}

TEST_CASE("parse_bool - true values case insensitive") {
    CHECK(parse_bool("YES")    == 1);
    CHECK(parse_bool("True")   == 1);
    CHECK(parse_bool("ON")     == 1);
    CHECK(parse_bool("Enable") == 1);
    CHECK(parse_bool("TRUE")   == 1);
}

TEST_CASE("parse_bool - false values") {
    CHECK(parse_bool("0")       == 0);
    CHECK(parse_bool("disable") == 0);
    CHECK(parse_bool("off")     == 0);
    CHECK(parse_bool("false")   == 0);
    CHECK(parse_bool("no")      == 0);
}

TEST_CASE("parse_bool - false values case insensitive") {
    CHECK(parse_bool("NO")      == 0);
    CHECK(parse_bool("False")   == 0);
    CHECK(parse_bool("OFF")     == 0);
    CHECK(parse_bool("Disable") == 0);
    CHECK(parse_bool("FALSE")   == 0);
}

TEST_CASE("parse_bool - invalid values") {
    CHECK(parse_bool("")        == -1);
    CHECK(parse_bool("2")       == -1);
    CHECK(parse_bool("maybe")   == -1);
    CHECK(parse_bool("yep")     == -1);
    CHECK(parse_bool("nope")    == -1);
    CHECK(parse_bool("tru")     == -1);
    CHECK(parse_bool("fals")    == -1);
    CHECK(parse_bool(" yes")    == -1);
    CHECK(parse_bool("yes ")    == -1);
}

// ============================================================================
// parse_syslog_code
// ============================================================================

TEST_CASE("parse_syslog_code - numeric input") {
    CHECK(parse_syslog_code("0",  facilitynames) == 0);
    CHECK(parse_syslog_code("16", facilitynames) == 16);
    CHECK(parse_syslog_code("24", facilitynames) == 24);
}

TEST_CASE("parse_syslog_code - known facility names") {
    CHECK(parse_syslog_code("user",   facilitynames) == LOG_USER);
    CHECK(parse_syslog_code("daemon", facilitynames) == LOG_DAEMON);
    CHECK(parse_syslog_code("local0", facilitynames) == LOG_LOCAL0);
    CHECK(parse_syslog_code("local7", facilitynames) == LOG_LOCAL7);
    CHECK(parse_syslog_code("kern",   facilitynames) == LOG_KERN);
    CHECK(parse_syslog_code("mail",   facilitynames) == LOG_MAIL);
}

TEST_CASE("parse_syslog_code - case insensitive") {
    CHECK(parse_syslog_code("USER",   facilitynames) == LOG_USER);
    CHECK(parse_syslog_code("User",   facilitynames) == LOG_USER);
    CHECK(parse_syslog_code("DAEMON", facilitynames) == LOG_DAEMON);
    CHECK(parse_syslog_code("LOCAL0", facilitynames) == LOG_LOCAL0);
}

TEST_CASE("parse_syslog_code - invalid input") {
    CHECK(parse_syslog_code("",          facilitynames) == -1);
    CHECK(parse_syslog_code("invalid",   facilitynames) == -1);
    CHECK(parse_syslog_code("notafacility", facilitynames) == -1);
}

// ============================================================================
// qtype_to_string
// ============================================================================

TEST_CASE("qtype_to_string - known types") {
    CHECK(qtype_to_string(Tins::DNS::A)     == "A");
    CHECK(qtype_to_string(Tins::DNS::AAAA)  == "AAAA");
    CHECK(qtype_to_string(Tins::DNS::CNAME) == "CNAME");
    CHECK(qtype_to_string(Tins::DNS::MX)    == "MX");
    CHECK(qtype_to_string(Tins::DNS::PTR)   == "PTR");
    CHECK(qtype_to_string(Tins::DNS::TXT)   == "TXT");
}

TEST_CASE("qtype_to_string - unknown type") {
    // Unknown types should return numeric representation
    const std::string result = qtype_to_string(static_cast<Tins::DNS::QueryType>(9999));
    CHECK(result == "(9999)");
}

// ============================================================================
// rcode_to_string
// ============================================================================

TEST_CASE("rcode_to_string - known rcodes") {
    CHECK(rcode_to_string(ns_r_noerror)  == "NOERROR");
    CHECK(rcode_to_string(ns_r_formerr)  == "FORMERR");
    CHECK(rcode_to_string(ns_r_servfail) == "SERVFAIL");
    CHECK(rcode_to_string(ns_r_nxdomain) == "NXDOMAIN");
    CHECK(rcode_to_string(ns_r_notimpl)  == "NOTIMPL");
    CHECK(rcode_to_string(ns_r_refused)  == "REFUSED");
}

TEST_CASE("rcode_to_string - unknown rcode") {
    const std::string result = rcode_to_string(static_cast<ns_rcode>(99));
    CHECK(result == "(99)");
}

// ============================================================================
// qtype_enabled / enable_qtype / disable_qtype
// ============================================================================

TEST_CASE("qtype_enabled - defaults") {
    reset_config();
    CHECK(qtype_enabled(Tins::DNS::A)     == true);
    CHECK(qtype_enabled(Tins::DNS::AAAA)  == true);
    CHECK(qtype_enabled(Tins::DNS::CNAME) == true);
    CHECK(qtype_enabled(Tins::DNS::MX)    == true);
    CHECK(qtype_enabled(Tins::DNS::PTR)   == true);
    CHECK(qtype_enabled(Tins::DNS::TXT)   == true);
}

TEST_CASE("qtype_enabled - disable and re-enable") {
    reset_config();

    disable_qtype(Tins::DNS::A);
    CHECK(qtype_enabled(Tins::DNS::A) == false);

    enable_qtype(Tins::DNS::A);
    CHECK(qtype_enabled(Tins::DNS::A) == true);
}

TEST_CASE("qtype_enabled - disable one does not affect others") {
    reset_config();

    disable_qtype(Tins::DNS::MX);
    CHECK(qtype_enabled(Tins::DNS::A)     == true);
    CHECK(qtype_enabled(Tins::DNS::AAAA)  == true);
    CHECK(qtype_enabled(Tins::DNS::CNAME) == true);
    CHECK(qtype_enabled(Tins::DNS::MX)    == false);
    CHECK(qtype_enabled(Tins::DNS::PTR)   == true);
    CHECK(qtype_enabled(Tins::DNS::TXT)   == true);

    reset_config();
}

TEST_CASE("qtype_enabled - disable all") {
    reset_config();

    disable_qtype(Tins::DNS::A);
    disable_qtype(Tins::DNS::AAAA);
    disable_qtype(Tins::DNS::CNAME);
    disable_qtype(Tins::DNS::MX);
    disable_qtype(Tins::DNS::PTR);
    disable_qtype(Tins::DNS::TXT);

    CHECK(qtype_enabled(Tins::DNS::A)     == false);
    CHECK(qtype_enabled(Tins::DNS::AAAA)  == false);
    CHECK(qtype_enabled(Tins::DNS::CNAME) == false);
    CHECK(qtype_enabled(Tins::DNS::MX)    == false);
    CHECK(qtype_enabled(Tins::DNS::PTR)   == false);
    CHECK(qtype_enabled(Tins::DNS::TXT)   == false);

    reset_config();
}

TEST_CASE("qtype_enabled - idempotent enable") {
    reset_config();
    enable_qtype(Tins::DNS::A);
    enable_qtype(Tins::DNS::A);
    CHECK(qtype_enabled(Tins::DNS::A) == true);
}

TEST_CASE("qtype_enabled - idempotent disable") {
    reset_config();
    disable_qtype(Tins::DNS::A);
    disable_qtype(Tins::DNS::A);
    CHECK(qtype_enabled(Tins::DNS::A) == false);
    reset_config();
}

// ============================================================================
// rcode_enabled / enable_rcode / disable_rcode
// ============================================================================

TEST_CASE("rcode_enabled - defaults") {
    reset_config();
    CHECK(rcode_enabled(ns_r_noerror)  == true);
    CHECK(rcode_enabled(ns_r_formerr)  == false);
    CHECK(rcode_enabled(ns_r_servfail) == false);
    CHECK(rcode_enabled(ns_r_nxdomain) == false);
    CHECK(rcode_enabled(ns_r_notimpl)  == false);
    CHECK(rcode_enabled(ns_r_refused)  == false);
}

TEST_CASE("rcode_enabled - enable and disable") {
    reset_config();

    enable_rcode(ns_r_nxdomain);
    CHECK(rcode_enabled(ns_r_nxdomain) == true);

    disable_rcode(ns_r_nxdomain);
    CHECK(rcode_enabled(ns_r_nxdomain) == false);

    reset_config();
}

TEST_CASE("rcode_enabled - enable one does not affect others") {
    reset_config();

    enable_rcode(ns_r_servfail);
    CHECK(rcode_enabled(ns_r_noerror)  == true);
    CHECK(rcode_enabled(ns_r_formerr)  == false);
    CHECK(rcode_enabled(ns_r_servfail) == true);
    CHECK(rcode_enabled(ns_r_nxdomain) == false);
    CHECK(rcode_enabled(ns_r_notimpl)  == false);
    CHECK(rcode_enabled(ns_r_refused)  == false);

    reset_config();
}

TEST_CASE("rcode_enabled - enable all") {
    reset_config();

    enable_rcode(ns_r_noerror);
    enable_rcode(ns_r_formerr);
    enable_rcode(ns_r_servfail);
    enable_rcode(ns_r_nxdomain);
    enable_rcode(ns_r_notimpl);
    enable_rcode(ns_r_refused);

    CHECK(rcode_enabled(ns_r_noerror)  == true);
    CHECK(rcode_enabled(ns_r_formerr)  == true);
    CHECK(rcode_enabled(ns_r_servfail) == true);
    CHECK(rcode_enabled(ns_r_nxdomain) == true);
    CHECK(rcode_enabled(ns_r_notimpl)  == true);
    CHECK(rcode_enabled(ns_r_refused)  == true);

    reset_config();
}

TEST_CASE("rcode_enabled - disable noerror") {
    reset_config();
    disable_rcode(ns_r_noerror);
    CHECK(rcode_enabled(ns_r_noerror) == false);
    reset_config();
}

// ============================================================================
// set_setting
// ============================================================================

TEST_CASE("set_setting - enable/disable record qtypes") {
    reset_config();

    set_setting(OPT_A,     false); CHECK(qtype_enabled(Tins::DNS::A)     == false);
    set_setting(OPT_AAAA,  false); CHECK(qtype_enabled(Tins::DNS::AAAA)  == false);
    set_setting(OPT_CNAME, false); CHECK(qtype_enabled(Tins::DNS::CNAME) == false);
    set_setting(OPT_MX,    false); CHECK(qtype_enabled(Tins::DNS::MX)    == false);
    set_setting(OPT_PTR,   false); CHECK(qtype_enabled(Tins::DNS::PTR)   == false);
    set_setting(OPT_TXT,   false); CHECK(qtype_enabled(Tins::DNS::TXT)   == false);

    set_setting(OPT_A,     true);  CHECK(qtype_enabled(Tins::DNS::A)     == true);
    set_setting(OPT_AAAA,  true);  CHECK(qtype_enabled(Tins::DNS::AAAA)  == true);
    set_setting(OPT_CNAME, true);  CHECK(qtype_enabled(Tins::DNS::CNAME) == true);
    set_setting(OPT_MX,    true);  CHECK(qtype_enabled(Tins::DNS::MX)    == true);
    set_setting(OPT_PTR,   true);  CHECK(qtype_enabled(Tins::DNS::PTR)   == true);
    set_setting(OPT_TXT,   true);  CHECK(qtype_enabled(Tins::DNS::TXT)   == true);

    reset_config();
}

TEST_CASE("set_setting - enable/disable error rcodes") {
    reset_config();

    set_setting(OPT_NOERROR,  false); CHECK(rcode_enabled(ns_r_noerror)  == false);
    set_setting(OPT_FORMERR,  true);  CHECK(rcode_enabled(ns_r_formerr)  == true);
    set_setting(OPT_SERVFAIL, true);  CHECK(rcode_enabled(ns_r_servfail) == true);
    set_setting(OPT_NXDOMAIN, true);  CHECK(rcode_enabled(ns_r_nxdomain) == true);
    set_setting(OPT_NOTIMPL,  true);  CHECK(rcode_enabled(ns_r_notimpl)  == true);
    set_setting(OPT_REFUSED,  true);  CHECK(rcode_enabled(ns_r_refused)  == true);

    set_setting(OPT_NOERROR,  true);  CHECK(rcode_enabled(ns_r_noerror)  == true);
    set_setting(OPT_FORMERR,  false); CHECK(rcode_enabled(ns_r_formerr)  == false);
    set_setting(OPT_SERVFAIL, false); CHECK(rcode_enabled(ns_r_servfail) == false);
    set_setting(OPT_NXDOMAIN, false); CHECK(rcode_enabled(ns_r_nxdomain) == false);
    set_setting(OPT_NOTIMPL,  false); CHECK(rcode_enabled(ns_r_notimpl)  == false);
    set_setting(OPT_REFUSED,  false); CHECK(rcode_enabled(ns_r_refused)  == false);

    reset_config();
}

TEST_CASE("set_setting - boundary values OPT_RECORDS_START and OPT_RECORDS_END are not valid") {
    reset_config();
    // These boundary sentinels should be no-ops
    set_setting(OPT_RECORDS_START, true);
    set_setting(OPT_RECORDS_END,   true);
    set_setting(OPT_ERRORS_START,  true);
    set_setting(OPT_ERRORS_END,    true);
    // Config should be unchanged from defaults
    CHECK(qtype_enabled(Tins::DNS::A)    == true);
    CHECK(rcode_enabled(ns_r_noerror)    == true);
    CHECK(rcode_enabled(ns_r_nxdomain)   == false);
    reset_config();
}

// ============================================================================
// process_dns_packet - stats counting
// ============================================================================

// Hex packet helpers — raw DNS payload bytes (no IP/UDP headers), used via
// sockets in integration tests. For unit tests we need full IP+UDP+DNS packets.

// IPv4 + UDP + DNS A reply: example.com A 127.0.0.1
// IP src=172.31.53.123, dst=172.31.53.123, UDP sport=53
static const std::vector<uint8_t> PKT_A_REPLY = [] {
    // IPv4 header (20 bytes): version=4, IHL=5, TTL=64, proto=17(UDP)
    // src=172.31.53.123, dst=172.31.53.1
    // UDP header (8 bytes): sport=53, dport=12345, len=...
    // DNS: example.com A 127.0.0.1 (NOERROR, QR=1, 1 question, 1 answer)
    std::vector<uint8_t> pkt = {
        // IPv4 header
        0x45, 0x00, 0x00, 0x4d, // version/IHL, DSCP, total length=77
        0x00, 0x00, 0x40, 0x00, // ID, flags, frag offset
        0x40, 0x11, 0x00, 0x00, // TTL=64, proto=UDP, checksum (ignored by libtins parse)
        0xac, 0x1f, 0x35, 0x7b, // src: 172.31.53.123
        0xac, 0x1f, 0x35, 0x01, // dst: 172.31.53.1
        // UDP header
        0x00, 0x35, 0x30, 0x39, // sport=53, dport=12345
        0x00, 0x39, 0x00, 0x00, // length=57, checksum=0
        // DNS: ID=0x1234, QR=1, OPCODE=0, AA=0, TC=0, RD=1, RA=1, RCODE=0
        // QDCOUNT=1, ANCOUNT=1, NSCOUNT=0, ARCOUNT=0
        0x12, 0x34, 0x81, 0x80,
        0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        // Question: example.com A IN
        0x07, 'e','x','a','m','p','l','e',
        0x03, 'c','o','m', 0x00,
        0x00, 0x01, 0x00, 0x01, // QTYPE=A, QCLASS=IN
        // Answer: example.com A 127.0.0.1 TTL=60
        0xc0, 0x0c,             // name pointer to offset 12
        0x00, 0x01, 0x00, 0x01, // TYPE=A, CLASS=IN
        0x00, 0x00, 0x00, 0x3c, // TTL=60
        0x00, 0x04,             // RDLENGTH=4
        0x7f, 0x00, 0x00, 0x01  // 127.0.0.1
    };
    return pkt;
}();

// IPv4 + UDP + DNS NXDOMAIN reply: example.com A -> NXDOMAIN
static const std::vector<uint8_t> PKT_NXDOMAIN_REPLY = [] {
    std::vector<uint8_t> pkt = {
        // IPv4 header
        0x45, 0x00, 0x00, 0x39,
        0x00, 0x00, 0x40, 0x00,
        0x40, 0x11, 0x00, 0x00,
        0xac, 0x1f, 0x35, 0x7b, // src: 172.31.53.123
        0xac, 0x1f, 0x35, 0x01,
        // UDP header
        0x00, 0x35, 0x30, 0x39,
        0x00, 0x25, 0x00, 0x00,
        // DNS: NXDOMAIN (RCODE=3), QR=1, 1 question, 0 answers
        0x12, 0x34, 0x81, 0x83,
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // Question: example.com A IN
        0x07, 'e','x','a','m','p','l','e',
        0x03, 'c','o','m', 0x00,
        0x00, 0x01, 0x00, 0x01
    };
    return pkt;
}();

// Too short to be valid IPv4 DNS packet
static const std::vector<uint8_t> PKT_TOO_SHORT = {
    0x45, 0x00, 0x00, 0x14,
    0x00, 0x00, 0x40, 0x00,
    0x40, 0x11, 0x00, 0x00,
    0xac, 0x1f, 0x35, 0x7b,
    0xac, 0x1f, 0x35, 0x01
    // only 20 bytes — too short for IPv4+UDP+DNS
};

// Unknown IP version (version nibble = 9)
static const std::vector<uint8_t> PKT_BAD_IP_VERSION = [] {
    std::vector<uint8_t> pkt(60, 0xff);
    pkt[0] = 0x95; // version=9
    return pkt;
}();

// DNS QUERY (not a response, QR bit = 0)
static const std::vector<uint8_t> PKT_DNS_QUERY = [] {
    std::vector<uint8_t> pkt = {
        0x45, 0x00, 0x00, 0x41,
        0x00, 0x00, 0x40, 0x00,
        0x40, 0x11, 0x00, 0x00,
        0xac, 0x1f, 0x35, 0x7b,
        0xac, 0x1f, 0x35, 0x01,
        0x00, 0x35, 0x30, 0x39,
        0x00, 0x2d, 0x00, 0x00,
        // DNS query: QR=0 (query, not response)
        0x12, 0x34, 0x01, 0x00,
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x07, 'e','x','a','m','p','l','e',
        0x03, 'c','o','m', 0x00,
        0x00, 0x01, 0x00, 0x01
    };
    return pkt;
}();

// DNS NXDOMAIN with 0 questions (invalid)
static const std::vector<uint8_t> PKT_NOQUESTION = [] {
    std::vector<uint8_t> pkt = {
        0x45, 0x00, 0x00, 0x28,
        0x00, 0x00, 0x40, 0x00,
        0x40, 0x11, 0x00, 0x00,
        0xac, 0x1f, 0x35, 0x7b,
        0xac, 0x1f, 0x35, 0x01,
        0x00, 0x35, 0x30, 0x39,
        0x00, 0x14, 0x00, 0x00,
        // DNS: NXDOMAIN, 0 questions, 0 answers
        0x12, 0x34, 0x81, 0x83,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    return pkt;
}();

TEST_CASE("process_dns_packet - valid A reply increments dns_responses and logged_records") {
    reset_config();
    reset_stats();
    std::ostringstream oss;
    auto logger = make_test_logger(oss);

    process_dns_packet(PKT_A_REPLY.data(), (int)PKT_A_REPLY.size(), *logger);

    CHECK(packet_stats.dns_responses   == 1);
    CHECK(packet_stats.logged_records  == 1);
    CHECK(packet_stats.logged_errors   == 0);
    CHECK(packet_stats.invalid_packets == 0);
}

TEST_CASE("process_dns_packet - valid A reply log output contains expected fields") {
    reset_config();
    reset_stats();
    std::ostringstream oss;
    auto logger = make_test_logger(oss);

    process_dns_packet(PKT_A_REPLY.data(), (int)PKT_A_REPLY.size(), *logger);

    const std::string output = oss.str();
    CHECK(output.find("172.31.53.123") != std::string::npos);
    CHECK(output.find("reply")         != std::string::npos);
    CHECK(output.find("A")             != std::string::npos);
    CHECK(output.find("example.com")   != std::string::npos);
    CHECK(output.find("127.0.0.1")     != std::string::npos);
}

TEST_CASE("process_dns_packet - A reply with A disabled does not log record") {
    reset_config();
    reset_stats();
    disable_qtype(Tins::DNS::A);
    std::ostringstream oss;
    auto logger = make_test_logger(oss);

    process_dns_packet(PKT_A_REPLY.data(), (int)PKT_A_REPLY.size(), *logger);

    CHECK(packet_stats.dns_responses  == 1);
    CHECK(packet_stats.logged_records == 0);
    CHECK(oss.str().empty());

    reset_config();
}

TEST_CASE("process_dns_packet - A reply with NOERROR disabled does not log") {
    reset_config();
    reset_stats();
    disable_rcode(ns_r_noerror);
    std::ostringstream oss;
    auto logger = make_test_logger(oss);

    process_dns_packet(PKT_A_REPLY.data(), (int)PKT_A_REPLY.size(), *logger);

    CHECK(packet_stats.dns_responses  == 1);
    CHECK(packet_stats.logged_records == 0);
    CHECK(oss.str().empty());

    reset_config();
}

TEST_CASE("process_dns_packet - NXDOMAIN reply with nxdomain disabled does not log error") {
    reset_config();
    reset_stats();
    // ns_r_nxdomain is disabled by default
    std::ostringstream oss;
    auto logger = make_test_logger(oss);

    process_dns_packet(PKT_NXDOMAIN_REPLY.data(), (int)PKT_NXDOMAIN_REPLY.size(), *logger);

    CHECK(packet_stats.dns_responses  == 1);
    CHECK(packet_stats.logged_errors  == 0);
    CHECK(oss.str().empty());
}

TEST_CASE("process_dns_packet - NXDOMAIN reply with nxdomain enabled logs error") {
    reset_config();
    reset_stats();
    enable_rcode(ns_r_nxdomain);
    std::ostringstream oss;
    auto logger = make_test_logger(oss);

    process_dns_packet(PKT_NXDOMAIN_REPLY.data(), (int)PKT_NXDOMAIN_REPLY.size(), *logger);

    CHECK(packet_stats.dns_responses  == 1);
    CHECK(packet_stats.logged_errors  == 1);
    CHECK(packet_stats.logged_records == 0);

    const std::string output = oss.str();
    CHECK(output.find("NXDOMAIN")     != std::string::npos);
    CHECK(output.find("example.com")  != std::string::npos);
    CHECK(output.find("172.31.53.123") != std::string::npos);

    reset_config();
}

TEST_CASE("process_dns_packet - too short packet increments invalid_packets") {
    reset_config();
    reset_stats();
    std::ostringstream oss;
    auto logger = make_test_logger(oss);

    process_dns_packet(PKT_TOO_SHORT.data(), (int)PKT_TOO_SHORT.size(), *logger);

    CHECK(packet_stats.invalid_packets == 1);
    CHECK(packet_stats.dns_responses   == 0);
    CHECK(oss.str().empty());
}

TEST_CASE("process_dns_packet - unknown IP version increments invalid_packets") {
    reset_config();
    reset_stats();
    std::ostringstream oss;
    auto logger = make_test_logger(oss);

    process_dns_packet(PKT_BAD_IP_VERSION.data(), (int)PKT_BAD_IP_VERSION.size(), *logger);

    CHECK(packet_stats.invalid_packets == 1);
    CHECK(packet_stats.dns_responses   == 0);
}

TEST_CASE("process_dns_packet - DNS query (not response) is not counted") {
    reset_config();
    reset_stats();
    std::ostringstream oss;
    auto logger = make_test_logger(oss);

    process_dns_packet(PKT_DNS_QUERY.data(), (int)PKT_DNS_QUERY.size(), *logger);

    CHECK(packet_stats.dns_responses   == 0);
    CHECK(packet_stats.invalid_packets == 0);
    CHECK(packet_stats.logged_records  == 0);
    CHECK(oss.str().empty());
}

TEST_CASE("process_dns_packet - NXDOMAIN with no questions increments invalid_packets") {
    reset_config();
    reset_stats();
    enable_rcode(ns_r_nxdomain);
    std::ostringstream oss;
    auto logger = make_test_logger(oss);

    process_dns_packet(PKT_NOQUESTION.data(), (int)PKT_NOQUESTION.size(), *logger);

    CHECK(packet_stats.dns_responses   == 1);
    CHECK(packet_stats.invalid_packets == 1);
    CHECK(packet_stats.logged_errors   == 0);

    reset_config();
}

TEST_CASE("process_dns_packet - stats accumulate across multiple packets") {
    reset_config();
    reset_stats();
    std::ostringstream oss;
    auto logger = make_test_logger(oss);

    process_dns_packet(PKT_A_REPLY.data(),    (int)PKT_A_REPLY.size(),    *logger);
    process_dns_packet(PKT_A_REPLY.data(),    (int)PKT_A_REPLY.size(),    *logger);
    process_dns_packet(PKT_TOO_SHORT.data(),  (int)PKT_TOO_SHORT.size(),  *logger);

    CHECK(packet_stats.dns_responses   == 2);
    CHECK(packet_stats.logged_records  == 2);
    CHECK(packet_stats.invalid_packets == 1);
}

// ============================================================================
// log_stats
// ============================================================================

TEST_CASE("log_stats - output contains all stat fields") {
    reset_stats();
    packet_stats.invalid_packets = 3;
    packet_stats.dns_responses   = 7;
    packet_stats.logged_records  = 5;
    packet_stats.logged_errors   = 2;

    std::ostringstream oss;
    auto logger = make_test_logger(oss);

    log_stats(*logger);

    const std::string output = oss.str();
    CHECK(output.find("received_packets=10") != std::string::npos);
    CHECK(output.find("invalid_packets=3")   != std::string::npos);
    CHECK(output.find("dns_responses=7")     != std::string::npos);
    CHECK(output.find("logged_records=5")    != std::string::npos);
    CHECK(output.find("logged_errors=2")     != std::string::npos);
}

TEST_CASE("log_stats - zero stats") {
    reset_stats();
    std::ostringstream oss;
    auto logger = make_test_logger(oss);

    log_stats(*logger);

    const std::string output = oss.str();
    CHECK(output.find("received_packets=0") != std::string::npos);
    CHECK(output.find("invalid_packets=0")  != std::string::npos);
    CHECK(output.find("dns_responses=0")    != std::string::npos);
    CHECK(output.find("logged_records=0")   != std::string::npos);
    CHECK(output.find("logged_errors=0")    != std::string::npos);
}

TEST_CASE("log_stats - received_packets is sum of invalid and responses") {
    reset_stats();
    packet_stats.invalid_packets = 4;
    packet_stats.dns_responses   = 6;

    std::ostringstream oss;
    auto logger = make_test_logger(oss);

    log_stats(*logger);

    CHECK(oss.str().find("received_packets=10") != std::string::npos);
}
