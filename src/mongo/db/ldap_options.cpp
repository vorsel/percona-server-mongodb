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

#include "mongo/db/ldap_options.h"
#include "mongo/db/ldap_options_gen.h"

#include <regex>

#include <fmt/format.h>

#include "mongo/bson/json.h"

namespace mongo {

using namespace fmt::literals;

LDAPGlobalParams ldapGlobalParams;

std::string LDAPGlobalParams::logString() const {
    return fmt::format(
        "ldapServers: {}; "
        "ldapTransportSecurity: {}; "
        "ldapBindMethod: {}; "
        "ldapBindSaslMechanisms: {}",
        std::string{*ldapServers},
        ldapTransportSecurity,
        ldapBindMethod,
        ldapBindSaslMechanisms);
}

Status validateLDAPBindMethod(const std::string& value) {
    constexpr auto kSimple = "simple"_sd;
    constexpr auto kSasl = "sasl"_sd;

    if (!kSimple.equalCaseInsensitive(value) && !kSasl.equalCaseInsensitive(value)) {
        return {ErrorCodes::BadValue, "security.ldap.bind.method expects one of 'simple' or 'sasl'"};
    }

    return Status::OK();
}

Status validateLDAPTransportSecurity(const std::string& value) {
    constexpr auto kNone = "none"_sd;
    constexpr auto kTls = "tls"_sd;

    if (!kNone.equalCaseInsensitive(value) && !kTls.equalCaseInsensitive(value)) {
        return {ErrorCodes::BadValue, "security.ldap.transportSecurity expects one of 'none' or 'tls'"};
    }

    return Status::OK();
}

Status validateLDAPUserToDNMapping(const std::string& mapping) {
    if (!isArray(mapping))
        return {ErrorCodes::BadValue, "security.ldap.userToDNMapping: User to DN mapping must be json array of objects"};

    BSONArray bsonmapping{fromjson(mapping)};
    for (const auto& elt: bsonmapping) {
        auto step = elt.Obj();
        BSONElement elmatch = step["match"];
        if (!elmatch)
            return {ErrorCodes::BadValue, "security.ldap.userToDNMapping: Each object in user to DN mapping array must contain the 'match' string"};
        BSONElement eltempl = step["substitution"];
        if (!eltempl)
            eltempl = step["ldapQuery"];
        if (!eltempl)
            return {ErrorCodes::BadValue, "security.ldap.userToDNMapping: Each object in user to DN mapping array must contain either 'substitution' or 'ldapQuery' string"};
        try {
            std::regex rex{elmatch.str()};
            const auto sm_count = rex.mark_count();
            // validate placeholders in template
            std::regex placeholder_rex{R"(\{(\d+)\})"};
            const std::string stempl = eltempl.str();
            std::sregex_iterator it{stempl.begin(), stempl.end(), placeholder_rex};
            std::sregex_iterator end;
            for(; it != end; ++it){
                if (std::stol((*it)[1].str()) >= sm_count)
                    return {ErrorCodes::BadValue,
                            "security.ldap.userToDNMapping: "
                            "Regular expresssion '{}' has {} capture groups so '{}' placeholder is invalid "
                            "(placeholder number must be less than number of capture groups)"_format(
                                elmatch.str(), sm_count, it->str())};
            }
        } catch (std::regex_error& e) {
            return {ErrorCodes::BadValue,
                    "security.ldap.userToDNMapping: std::regex_error exception while validating '{}'. "
                    "Error message is: {}"_format(elmatch.str(), e.what())};
        }
    }

    return Status::OK();
}

}  // namespace mongo
