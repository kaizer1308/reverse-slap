#pragma once

// pki for tls interception on cryptoapi, a local ca and per host certs,
// trusting the ca is an explicit user action

#include <optional>
#include <string>

namespace slop::core::network::mitm {

// Generate (once) a self-signed RSA-2048 CA named CN=<ca_name> into the
// current-user Personal store. Returns false when creation fails
bool generate_ca(const std::string& ca_name, std::string* error = nullptr);

bool ca_exists();

// Copy the CA certificate into the CurrentUser Root store so schannel /
// browser stacks trust certificates issued by it
bool install_ca_root(std::string* error = nullptr);

// Issue (and cache) a leaf certificate for `host` signed by the CA
// Returns the PEM-ish base64 blob path written under the cache dir
std::optional<std::string> issue_host_cert(const std::string& host,
                                           std::string* error = nullptr);

} // namespace slop::core::network::mitm
