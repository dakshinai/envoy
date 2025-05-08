#include "source/extensions/filters/udp/dns_filter/config.h"

namespace Envoy {
namespace Extensions {
namespace UdpFilters {
namespace DnsFilter {

Network::UdpListenerFilterFactoryCb DnsFilterConfigFactory::createFilterFactoryFromProto(
    const Protobuf::Message& config, Server::Configuration::ListenerFactoryContext& context) {
  // TODO: @dakshinai -  This change is temporary until we support access log configuration in the filter config.
  // Initialize access log configuration
  envoy::config::accesslog::v3::AccessLog log_config;
  log_config.set_name("envoy.access_loggers.file");

  // Pack the FileAccessLog configuration into the typed_config field
  google::protobuf::Any* file_config = log_config.mutable_typed_config();
  envoy::extensions::access_loggers::file::v3::FileAccessLog file_access_log;
  file_access_log.set_path("dns_filter_access.log");
  file_access_log.mutable_log_format()->mutable_text_format_source()->set_inline_string(
      "Request Start Time (ms): %DYNAMIC_METADATA(envoy.extensions.filters.udp.dns_filter.request:request_start_time_ms)%\n"
      "Remote IP: %DYNAMIC_METADATA(envoy.extensions.filters.udp.dns_filter.request:remote_ip)%\n"
      "Local IP: %DYNAMIC_METADATA(envoy.extensions.filters.udp.dns_filter.request:local_ip)%\n"
      "DNS Question Name: %DYNAMIC_METADATA(envoy.extensions.filters.udp.dns_filter.request:dns_question_name)%\n"
      "DNS Question Type: %DYNAMIC_METADATA(envoy.extensions.filters.udp.dns_filter.request:dns_question_type)%\n"
      "DNS Question Class: %DYNAMIC_METADATA(envoy.extensions.filters.udp.dns_filter.request:dns_question_class)%\n");
  file_config->PackFrom(file_access_log);

  // Create the access log instance
  std::vector<AccessLog::InstanceSharedPtr> access_logs;
  access_logs.emplace_back(AccessLog::AccessLogFactory::fromProto(log_config, context));

  // Create the shared configuration with the log_config
  auto shared_config = std::make_shared<DnsFilterEnvoyConfig>(
      context, MessageUtil::downcastAndValidate<
                   const envoy::extensions::filters::udp::dns_filter::v3::DnsFilterConfig&>(
                   config, context.messageValidationVisitor()), std::move(access_logs));

  return [shared_config](Network::UdpListenerFilterManager& filter_manager,
                         Network::UdpReadFilterCallbacks& callbacks) -> void {
    filter_manager.addReadFilter(std::make_unique<DnsFilter>(callbacks, shared_config));
  };
}

ProtobufTypes::MessagePtr DnsFilterConfigFactory::createEmptyConfigProto() {
  return std::make_unique<envoy::extensions::filters::udp::dns_filter::v3::DnsFilterConfig>();
}

std::string DnsFilterConfigFactory::name() const { return "envoy.filters.udp.dns_filter"; }

/**
 * Static registration for the DNS Filter. @see RegisterFactory.
 */
static Registry::RegisterFactory<DnsFilterConfigFactory,
                                 Server::Configuration::NamedUdpListenerFilterConfigFactory>
    register_;

} // namespace DnsFilter
} // namespace UdpFilters
} // namespace Extensions
} // namespace Envoy
