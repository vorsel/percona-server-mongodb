/*======
This file is part of Percona Server for MongoDB.

Copyright (C) 2019-present Percona and/or its affiliates. All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the Server Side Public License, version 1,
    as published by MongoDB, Inc.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    Server Side Public License for more details.

    You should have received a copy of the Server Side Public License
    along with this program. If not, see
    <http://www.mongodb.com/licensing/server-side-public-license>.

    As a special exception, the copyright holders give permission to link the
    code of portions of this program with the OpenSSL library under certain
    conditions as described in each individual source file and distribute
    linked combinations including the program with the OpenSSL library. You
    must comply with the Server Side Public License in all respects for
    all of the code used other than as permitted herein. If you modify file(s)
    with this exception, you may extend this exception to your version of the
    file(s), but you are not obligated to do so. If you do not wish to do so,
    delete this exception statement from your version. If you delete this
    exception statement from all source files in the program, then also delete
    it in the license file.
======= */

#define MONGO_LOG_DEFAULT_COMPONENT ::mongo::logger::LogComponent::kNetwork

#include "mongo/db/encryption/encryption_vault.h"

#include <curl/curl.h>

#include "mongo/base/disallow_copying.h"
#include "mongo/db/encryption/encryption_options.h"
#include "mongo/db/json.h"
#include "mongo/util/log.h"

namespace mongo {

namespace {

class CURLGuard {
    MONGO_DISALLOW_COPYING(CURLGuard);

public:
    CURLGuard() {}
    ~CURLGuard() {
        curl_global_cleanup();
    }

    void initialize() {
        CURLcode ret = curl_global_init(CURL_GLOBAL_ALL);
        if (ret != CURLE_OK) {
            throw std::runtime_error(str::stream()
                                     << "failed to initialize CURL: " << static_cast<int64_t>(ret));
        }

        curl_version_info_data* version_data = curl_version_info(CURLVERSION_NOW);
        if (!(version_data->features & CURL_VERSION_SSL)) {
            throw std::runtime_error(str::stream()
                                     << "Curl lacks SSL support, cannot continue");
        }
    }
};

class Curl_session_guard {
    MONGO_DISALLOW_COPYING(Curl_session_guard);

public:
    Curl_session_guard(CURL *curl)
        : curl(curl)
    {}
    ~Curl_session_guard()
    {
        if (curl != nullptr)
            curl_easy_cleanup(curl);
    }

private:
    CURL *curl;
};

class Curl_slist_guard {
    MONGO_DISALLOW_COPYING(Curl_slist_guard);

public:
    Curl_slist_guard(curl_slist *list)
        : list(list)
    {}
    ~Curl_slist_guard() {
        if (list != nullptr)
            curl_slist_free_all(list);
    }

private:
    curl_slist *list;
};

} // namespace
size_t write_response_callback(char *ptr, size_t size, size_t nmemb, void *userdata) {
    *(str::stream*)userdata << std::string(ptr, nmemb);
    return CURLE_OK;
}

CURLcode setup_curl_options(CURL *curl) {
    CURLcode curl_res = CURLE_OK;
    (curl_res = curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L)) != CURLE_OK
    || (curl_res = curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L)) != CURLE_OK;
    return curl_res;
}

std::string vaultReadKey() {
    CURLGuard guard;
    guard.initialize();

    CURL *curl = curl_easy_init();
    if (curl == nullptr) {
        throw std::runtime_error(str::stream()
                                 << "Cannot initialize curl session");
    }
    Curl_session_guard curl_session_guard(curl);

    char curl_errbuf[CURL_ERROR_SIZE]; //error from CURL
    CURLcode curl_res = CURLE_OK;
    str::stream response;

    curl_slist *headers = nullptr;
    headers = curl_slist_append(headers, std::string(str::stream() << "X-Vault-Token: " << encryptionGlobalParams.vaultToken).c_str());
    Curl_slist_guard curl_slist_guard(headers);

    curl_res = setup_curl_options(curl);
    curl_res = curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, curl_errbuf);
    curl_res = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_response_callback);
    curl_res = curl_easy_setopt(curl, CURLOPT_WRITEDATA, static_cast<void*>(&response));
    curl_res = curl_easy_setopt(curl, CURLOPT_URL,
                                std::string(str::stream()
                                << "http://" << encryptionGlobalParams.vaultServerName
                                << ':'       << encryptionGlobalParams.vaultPort
                                << "/v1/"    << encryptionGlobalParams.vaultSecret).c_str());
    curl_res = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_res = curl_easy_perform(curl);

    log() << std::string(response);
    BSONObj bson = fromjson(response);
    BSONElement data1 = bson["data"];
    if (data1.eoo() || !data1.isABSONObj()) {
        throw std::runtime_error("Error parsing Vault response");
    }
    BSONElement data2 = data1.Obj()["data"];
    if (data2.eoo() || !data2.isABSONObj()) {
        throw std::runtime_error("Error parsing Vault response");
    }
    BSONElement value = data2.Obj()["value"];
    if (value.eoo() || value.type() != mongo::String) {
        throw std::runtime_error("Error parsing Vault response");
    }
    return value.String();
}

void vaultWriteKey(std::string const& key) {
    CURLGuard guard;
    guard.initialize();

    CURL *curl = curl_easy_init();
    if (curl == nullptr) {
        throw std::runtime_error(str::stream()
                                 << "Cannot initialize curl session");
    }
    Curl_session_guard curl_session_guard(curl);

    char curl_errbuf[CURL_ERROR_SIZE]; //error from CURL
    CURLcode curl_res = CURLE_OK;
    str::stream response;

    curl_slist *headers = nullptr;
    headers = curl_slist_append(headers, std::string(str::stream() << "X-Vault-Token: " << encryptionGlobalParams.vaultToken).c_str());
    Curl_slist_guard curl_slist_guard(headers);

    curl_res = setup_curl_options(curl);
    curl_res = curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, curl_errbuf);
    curl_res = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_response_callback);
    curl_res = curl_easy_setopt(curl, CURLOPT_WRITEDATA, static_cast<void*>(&response));
    std::string urlstr = std::string(str::stream()
                                << "http://" << encryptionGlobalParams.vaultServerName
                                << ':'       << encryptionGlobalParams.vaultPort
                                << "/v1/"    << encryptionGlobalParams.vaultSecret);
    curl_res = curl_easy_setopt(curl, CURLOPT_URL,
                                urlstr.c_str());
    curl_res = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    std::string postdata = std::string(str::stream()
                                << "{\"data\": "
                                << "{\"value\": \"" << key
                                << "\"}}");
    curl_res = curl_easy_setopt(curl, CURLOPT_POSTFIELDS,
                                postdata.c_str());
    curl_res = curl_easy_perform(curl);

    log() << std::string(response);
}

}  // namespace mongo
