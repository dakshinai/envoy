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
  log_config.set_name("envoy.access_loggers.stdout");

  // Pack the StdoutAccessLog configuration into the typed_config field
  google::protobuf::Any* file_config = log_config.mutable_typed_config();
  envoy::extensions::access_loggers::stream::v3::StdoutAccessLog stdout_access_log;

  stdout_access_log.mutable_log_format()->mutable_text_format_source()->set_inline_string(
    "peer_ip=%DYNAMIC_METADATA(envoy.extensions.filters.udp.dns_filter.request:peer_ip)% "
    "local_ip=%DYNAMIC_METADATA(envoy.extensions.filters.udp.dns_filter.request:local_ip)% "
    "dns_question_name=%DYNAMIC_METADATA(envoy.extensions.filters.udp.dns_filter.request:dns_question_name)% "
    "dns_question_class=%DYNAMIC_METADATA(envoy.extensions.filters.udp.dns_filter.request:dns_question_class)% "
    "dns_question_type=%DYNAMIC_METADATA(envoy.extensions.filters.udp.dns_filter.request:dns_question_type)% "
    "request_start_time=%DYNAMIC_METADATA(envoy.extensions.filters.udp.dns_filter.request:request_start_time)% "
    "response_code=%DYNAMIC_METADATA(envoy.extensions.filters.udp.dns_filter.response:response_code)% "
    "dns_answer=%DYNAMIC_METADATA(envoy.extensions.filters.udp.dns_filter.response:dns_answer)%\n"
  );

  file_config->PackFrom(stdout_access_log);

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
