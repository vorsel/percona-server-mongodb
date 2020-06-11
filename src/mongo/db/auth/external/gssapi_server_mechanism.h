/*======
This file is part of Percona Server for MongoDB.

Copyright (C) 2020-present Percona and/or its affiliates. All rights reserved.

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

#pragma once

#include "mongo/db/auth/external/cyrus_sasl_server_session.h"
#include "mongo/db/auth/sasl_authentication_session.h"

namespace mongo {

class GSSAPIServerSession : public SaslAuthenticationSession {
    MONGO_DISALLOW_COPYING(GSSAPIServerSession);
public:
    explicit GSSAPIServerSession(AuthorizationSession* authSession);
    virtual ~GSSAPIServerSession();

private:
    CyrusSASLServerSession _sess;
    std::string _mechanism;

    virtual Status start(StringData authenticationDatabase,
                         StringData mechanism,
                         StringData serviceName,
                         StringData serviceHostname,
                         int64_t conversationId,
                         bool autoAuthorize) override final;
    virtual Status step(StringData inputData, std::string* outputData) override final;
    virtual std::string getPrincipalId() const override final;
    virtual const char* getMechanism() const override final;
};

}  // namespace mongo
