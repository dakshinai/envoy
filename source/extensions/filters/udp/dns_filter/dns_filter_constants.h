#pragma once

#include "envoy/common/platform.h"

namespace Envoy {
namespace Extensions {
namespace UdpFilters {
namespace DnsFilter {

constexpr uint16_t DNS_RECORD_CLASS_IN = 1;

constexpr uint16_t DNS_RECORD_TYPE_A = 0x01;
constexpr uint16_t DNS_RECORD_TYPE_AAAA = 0x1C;
constexpr uint16_t DNS_RECORD_TYPE_SRV = 0x21;
constexpr uint16_t DNS_RECORD_TYPE_OPT = 0x29;

constexpr uint16_t DNS_RESPONSE_CODE_NO_ERROR = 0;
constexpr uint16_t DNS_RESPONSE_CODE_FORMAT_ERROR = 1;
constexpr uint16_t DNS_RESPONSE_CODE_NAME_ERROR = 3;
constexpr uint16_t DNS_RESPONSE_CODE_NOT_IMPLEMENTED = 4;

constexpr size_t MIN_QUERY_NAME_LENGTH = 3;
constexpr size_t MAX_LABEL_LENGTH = 63;
constexpr size_t MAX_NAME_LENGTH = 255;

constexpr size_t MAX_SUFFIX_LABEL_COUNT = 2;

// Amazon Route53 will return up to 8 records in an answer
// https://aws.amazon.com/route53/faqs/#associate_multiple_ip_with_single_record
constexpr size_t MAX_RETURNED_RECORDS = 8;

// Ensure that responses stay below the 512 byte byte limit. If we are to exceed this we must
// add DNS extension fields
constexpr uint64_t MAX_DNS_RESPONSE_SIZE = 512;

/**
 * Converts a DNS class value to its corresponding string representation.
 */
inline std::string dnsClassToString(uint16_t class_value) {
    switch (class_value) {
    case DNS_RECORD_CLASS_IN:
      return "IN"; // Internet
    default:
      return "UNKNOWN_CLASS";
    }
  }
  
/**
 * Converts a DNS record type value to its corresponding string representation.
 */
inline std::string dnsTypeToString(uint16_t type_value) {
    switch (type_value) {
    case DNS_RECORD_TYPE_A:
      return "A"; // IPv4 Address
    case DNS_RECORD_TYPE_AAAA:
      return "AAAA"; // IPv6 Address
    case DNS_RECORD_TYPE_SRV:
      return "SRV"; // Service Record
    case DNS_RECORD_TYPE_OPT:
      return "OPT"; // EDNS Option
    default:
      return "UNKNOWN_TYPE";
    }
  }
  
/**
 * Converts a DNS response code to its corresponding string representation.
 */
inline std::string dnsResponseCodeToString(uint16_t response_code) {
    switch (response_code) {
    case DNS_RESPONSE_CODE_NO_ERROR:
      return "NO_ERROR";
    case DNS_RESPONSE_CODE_FORMAT_ERROR:
      return "FORMAT_ERROR";
    case DNS_RESPONSE_CODE_NAME_ERROR:
      return "NAME_ERROR";
    case DNS_RESPONSE_CODE_NOT_IMPLEMENTED:
      return "NOT_IMPLEMENTED";
    default:
      return "UNKNOWN_RESPONSE_CODE";
    }
  }

} // namespace DnsFilter
} // namespace UdpFilters
} // namespace Extensions
} // namespace Envoy
