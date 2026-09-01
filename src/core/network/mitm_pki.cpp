// src/core/net/mitm_pki.cpp

#include "core/network/mitm_pki.hpp"

#include <windows.h>
#include <wincrypt.h>

#include <filesystem>
#include <vector>

#pragma comment(lib, "crypt32.lib")

namespace slop::core::network::mitm {

namespace {

constexpr wchar_t kCaKeyContainer[] = L"reverse-slop-ca-key";
constexpr const char* kCaSubject = "CN=reverse-slop Local CA";

std::wstring cache_dir_w() {
    char base[MAX_PATH]{};
    const DWORD n = GetEnvironmentVariableA("LOCALAPPDATA", base, MAX_PATH);
    std::string dir = n ? std::string(base) + "\\reverse-slop\\certs"
                        : ".\\certs";
    CreateDirectoryA(dir.c_str(), nullptr);
    return std::wstring(dir.begin(), dir.end());
}

PCCERT_CONTEXT find_ca_in_my() {
    PCCERT_CONTEXT found = nullptr;
    HCERTSTORE store = CertOpenSystemStoreW(0, L"MY");
    if (!store) return nullptr;
    PCCERT_CONTEXT it = nullptr;
    while ((it = CertEnumCertificatesInStore(store, it)) != nullptr) {
        char subj[256] = {};
        CertGetNameStringA(it, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr,
                           subj, sizeof(subj));
        if (std::string(subj).find("reverse-slop Local CA") !=
            std::string::npos) {
            found = CertDuplicateCertificateContext(it);
            break;
        }
    }
    if (it) CertFreeCertificateContext(it);
    CertCloseStore(store, 0);
    return found;
}

bool encode_subject(const std::string& cn, CERT_NAME_BLOB* blob) {
    const std::string dn = "CN=" + cn;
    if (!CertStrToNameA(X509_ASN_ENCODING, dn.c_str(), CERT_X500_NAME_STR,
                        nullptr, nullptr, &blob->cbData, nullptr))
        return false;
    blob->pbData =
        static_cast<BYTE*>(LocalAlloc(LMEM_ZEROINIT, blob->cbData));
    if (!blob->pbData) return false;
    return CertStrToNameA(X509_ASN_ENCODING, dn.c_str(), CERT_X500_NAME_STR,
                          nullptr, blob->pbData, &blob->cbData,
                          nullptr) != FALSE;
}

} // namespace

bool generate_ca(const std::string& /*ca_name*/, std::string* error) {
    if (find_ca_in_my()) return true;

    HCRYPTPROV prov = 0;
    if (!CryptAcquireContextW(&prov, kCaKeyContainer, nullptr, PROV_RSA_AES,
                              CRYPT_NEWKEYSET)) {
        if (GetLastError() != NTE_EXISTS) {
            if (error) *error = "CA key container create failed";
            return false;
        }
    } else {
        CryptReleaseContext(prov, 0);
    }

    CERT_NAME_BLOB subject{};
    if (!encode_subject(kCaSubject + 3, &subject)) {   // strip "CN="
        if (error) *error = "subject encode failed";
        return false;
    }

    CRYPT_KEY_PROV_INFO key_prov{};
    key_prov.pwszContainerName = const_cast<LPWSTR>(kCaKeyContainer);
    key_prov.dwProvType = PROV_RSA_AES;
    key_prov.dwKeySpec = AT_SIGNATURE;

    CRYPT_ALGORITHM_IDENTIFIER sig_alg{};
    sig_alg.pszObjId = const_cast<LPSTR>(szOID_RSA_SHA256RSA);

    SYSTEMTIME now{}, not_after{};
    GetSystemTime(&now);
    not_after = now;
    not_after.wYear += 10;

    CERT_EXTENSIONS exts{};
    PCCERT_CONTEXT cert = CertCreateSelfSignCertificate(
        0, &subject, 0, &key_prov, &sig_alg, &now, &not_after, &exts);
    LocalFree(subject.pbData);
    if (!cert) {
        if (error) *error = "CertCreateSelfSignCertificate failed";
        return false;
    }

    HCERTSTORE my = CertOpenSystemStoreW(0, L"MY");
    bool ok = my != nullptr &&
              CertAddCertificateContextToStore(
                  my, cert, CERT_STORE_ADD_USE_EXISTING, nullptr) != FALSE;
    if (my) CertCloseStore(my, 0);

    // Export .cer next to the cache for inspection / other-tool import
    if (ok) {
        const std::wstring cer_path =
            cache_dir_w() + L"\\reverse-slop-ca.cer";
        HANDLE f = CreateFileW(cer_path.c_str(), GENERIC_WRITE, 0, nullptr,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,
                               nullptr);
        if (f != INVALID_HANDLE_VALUE) {
            DWORD written = 0;
            WriteFile(f, cert->pbCertEncoded, cert->cbCertEncoded,
                      &written, nullptr);
            CloseHandle(f);
        }
    }
    CertFreeCertificateContext(cert);
    if (!ok && error) *error = "cannot add CA to MY store";
    return ok;
}

bool ca_exists() { return find_ca_in_my() != nullptr; }

bool install_ca_root(std::string* error) {
    PCCERT_CONTEXT ca = find_ca_in_my();
    if (!ca) {
        if (error) *error = "CA not generated yet";
        return false;
    }
    HCERTSTORE root = CertOpenSystemStoreW(0, L"ROOT");
    if (!root) {
        if (error) *error = "cannot open ROOT store";
        CertFreeCertificateContext(ca);
        return false;
    }
    const BOOL added = CertAddCertificateContextToStore(
        root, ca, CERT_STORE_ADD_USE_EXISTING, nullptr);
    CertCloseStore(root, 0);
    CertFreeCertificateContext(ca);
    if (!added && error) *error = "install rejected or failed";
    return added != FALSE;
}

std::optional<std::string> issue_host_cert(const std::string& host,
                                           std::string* error) {
    PCCERT_CONTEXT ca = find_ca_in_my();
    if (!ca) {
        if (error) *error = "CA not generated yet";
        return std::nullopt;
    }

    // Host signing key comes from its own container
    const std::wstring host_container =
        L"reverse-slop-host-" +
        std::wstring(host.begin(), host.end());
    HCRYPTPROV host_prov = 0;
    if (!CryptAcquireContextW(&host_prov, host_container.c_str(), nullptr,
                              PROV_RSA_AES, CRYPT_NEWKEYSET)) {
        if (GetLastError() == NTE_EXISTS)
            CryptAcquireContextW(&host_prov, host_container.c_str(),
                                 nullptr, PROV_RSA_AES, 0);
    }
    if (!host_prov) {
        if (error) *error = "host keyset failed";
        CertFreeCertificateContext(ca);
        return std::nullopt;
    }
    CryptReleaseContext(host_prov, 0);

    // CA private key provider
    DWORD kb_size = 0;
    if (!CertGetCertificateContextProperty(
            ca, CERT_KEY_PROV_INFO_PROP_ID, nullptr, &kb_size)) {
        if (error) *error = "CA has no key provider info";
        CertFreeCertificateContext(ca);
        return std::nullopt;
    }
    std::vector<BYTE> key_info_buf(kb_size);
    auto* ca_key = reinterpret_cast<CRYPT_KEY_PROV_INFO*>(
        key_info_buf.data());
    CertGetCertificateContextProperty(ca, CERT_KEY_PROV_INFO_PROP_ID,
                                      ca_key, &kb_size);

    HCRYPTPROV ca_prov = 0;
    if (!CryptAcquireContextW(&ca_prov, ca_key->pwszContainerName,
                              ca_key->pwszProvName ? ca_key->pwszProvName
                                                   : nullptr,
                              ca_key->dwProvType, 0)) {
        if (error) *error = "cannot open CA key";
        CertFreeCertificateContext(ca);
        return std::nullopt;
    }

    CERT_NAME_BLOB subject{};
    if (!encode_subject(host, &subject)) {
        if (error) *error = "host subject encode failed";
        CryptReleaseContext(ca_prov, 0);
        CertFreeCertificateContext(ca);
        return std::nullopt;
    }

    static volatile uint64_t serial_counter = 0x5109000000000000ull;
    uint64_t serial = ++serial_counter;
    serial &= 0x7FFFFFFFFFFFFFFFull;   // positive

    CRYPT_INTEGER_BLOB serial_blob{
        8, reinterpret_cast<BYTE*>(&serial)};
    FILETIME now_ft{}, later_ft{};
    GetSystemTimeAsFileTime(&now_ft);
    later_ft = now_ft;
    later_ft.dwHighDateTime += 4000;   // roughly one year of 100ns ticks

    CERT_INFO info{};
    info.dwVersion = CERT_V3;
    info.SerialNumber = serial_blob;
    info.SignatureAlgorithm.pszObjId =
        const_cast<LPSTR>(szOID_RSA_SHA256RSA);
    info.Issuer = ca->pCertInfo->Subject;
    info.NotBefore = now_ft;
    info.NotAfter = later_ft;
    info.Subject = subject;

    DWORD der_len = 0;
    if (!CryptSignAndEncodeCertificate(ca_prov, AT_SIGNATURE,
                                       X509_ASN_ENCODING,
                                       X509_CERT_TO_BE_SIGNED, &info,
                                       &info.SignatureAlgorithm, nullptr,
                                       nullptr, &der_len) ||
        der_len == 0) {
        if (error) *error = "sign length query failed";
        LocalFree(subject.pbData);
        CryptReleaseContext(ca_prov, 0);
        CertFreeCertificateContext(ca);
        return std::nullopt;
    }
    std::vector<BYTE> der(der_len);
    if (!CryptSignAndEncodeCertificate(ca_prov, AT_SIGNATURE,
                                       X509_ASN_ENCODING,
                                       X509_CERT_TO_BE_SIGNED, &info,
                                       &info.SignatureAlgorithm, nullptr,
                                       der.data(), &der_len)) {
        if (error) *error = "sign failed";
        LocalFree(subject.pbData);
        CryptReleaseContext(ca_prov, 0);
        CertFreeCertificateContext(ca);
        return std::nullopt;
    }

    LocalFree(subject.pbData);
    CryptReleaseContext(ca_prov, 0);
    CertFreeCertificateContext(ca);

    char base_narrow[MAX_PATH]{};
    const DWORD n_narrow =
        GetEnvironmentVariableA("LOCALAPPDATA", base_narrow, MAX_PATH);
    std::string cert_dir =
        n_narrow ? std::string(base_narrow) + "\\reverse-slop\\certs"
                 : ".\\certs";
    CreateDirectoryA(cert_dir.c_str(), nullptr);
    const std::string out_path = cert_dir + "\\" + host + ".cer";
    HANDLE hf = CreateFileA(out_path.c_str(), GENERIC_WRITE, 0,
                            nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,
                            nullptr);
    if (hf == INVALID_HANDLE_VALUE) {
        if (error)
            *error = "cannot write issued certificate (gle " +
                     std::to_string(GetLastError()) + " len " +
                     std::to_string(out_path.size()) + " path=" + out_path +
                     ")";
        return std::nullopt;
    }
    DWORD written = 0;
    WriteFile(hf, der.data(), static_cast<DWORD>(der.size()), &written,
              nullptr);
    CloseHandle(hf);
    return out_path;
}

} // namespace slop::core::network::mitm
