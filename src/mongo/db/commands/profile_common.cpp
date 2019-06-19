/**
 *    Copyright (C) 2018-present MongoDB, Inc.
 *
 *    This program is free software: you can redistribute it and/or modify
 *    it under the terms of the Server Side Public License, version 1,
 *    as published by MongoDB, Inc.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    Server Side Public License for more details.
 *
 *    You should have received a copy of the Server Side Public License
 *    along with this program. If not, see
 *    <http://www.mongodb.com/licensing/server-side-public-license>.
 *
 *    As a special exception, the copyright holders give permission to link the
 *    code of portions of this program with the OpenSSL library under certain
 *    conditions as described in each individual source file and distribute
 *    linked combinations including the program with the OpenSSL library. You
 *    must comply with the Server Side Public License in all respects for
 *    all of the code used other than as permitted herein. If you modify file(s)
 *    with this exception, you may extend this exception to your version of the
 *    file(s), but you are not obligated to do so. If you do not wish to do so,
 *    delete this exception statement from your version. If you delete this
 *    exception statement from all source files in the program, then also delete
 *    it in the license file.
 */

#include "mongo/platform/basic.h"

#include "mongo/db/auth/authorization_session.h"
#include "mongo/db/commands/profile_common.h"
#include "mongo/db/commands/profile_gen.h"
#include "mongo/idl/idl_parser.h"

namespace mongo {

Status ProfileCmdBase::checkAuthForCommand(Client* client,
                                           const std::string& dbName,
                                           const BSONObj& cmdObj) const {
    AuthorizationSession* authzSession = AuthorizationSession::get(client);

    auto request = ProfileCmdRequest::parse(IDLParserErrorContext("profile"), cmdObj);
    const auto profilingLevel = request.getCommandParameter();

    if (profilingLevel < 0 && !request.getSlowms() && !request.getSampleRate() && !request.getRatelimit()) {
        // If the user just wants to view the current values of 'slowms' and 'sampleRate', they
        // only need read rights on system.profile, even if they can't change the profiling level.
        if (authzSession->isAuthorizedForActionsOnResource(
                ResourcePattern::forExactNamespace({dbName, "system.profile"}), ActionType::find)) {
            return Status::OK();
        }
    }

    return authzSession->isAuthorizedForActionsOnResource(ResourcePattern::forDatabaseName(dbName),
                                                          ActionType::enableProfiler)
        ? Status::OK()
        : Status(ErrorCodes::Unauthorized, "unauthorized");
}

bool ProfileCmdBase::run(OperationContext* opCtx,
                         const std::string& dbName,
                         const BSONObj& cmdObj,
                         BSONObjBuilder& result) {
    auto request = ProfileCmdRequest::parse(IDLParserErrorContext("profile"), cmdObj);
    const auto profilingLevel = request.getCommandParameter();

    // Delegate to _applyProfilingLevel to set the profiling level appropriately whether we are on
    // mongoD or mongoS.
    int oldLevel = _applyProfilingLevel(opCtx, dbName, profilingLevel);

    result.append("was", oldLevel);
    result.append("slowms", serverGlobalParams.slowMS);
    result.append("ratelimit", serverGlobalParams.rateLimit);
    result.append("sampleRate", serverGlobalParams.sampleRate);

    if (auto slowms = request.getSlowms()) {
        serverGlobalParams.slowMS = *slowms;
    }
    int newRateLimit = serverGlobalParams.rateLimit;
    if (auto optRateLimit = request.getRatelimit()) {
        const decltype(optRateLimit)::value_type rateLimit = *optRateLimit;
        uassert(ErrorCodes::BadValue,
                str::stream() << "ratelimit must be between 0 and " << RATE_LIMIT_MAX << " inclusive",
                0 <= rateLimit && rateLimit <= RATE_LIMIT_MAX);
        newRateLimit = std::max(rateLimit, static_cast<decltype(rateLimit)>(1));

    }
    double newSampleRate = serverGlobalParams.sampleRate;
    if (auto sampleRate = request.getSampleRate()) {
        uassert(ErrorCodes::BadValue,
                "'sampleRate' must be between 0.0 and 1.0 inclusive",
                *sampleRate >= 0.0 && *sampleRate <= 1.0);
        newSampleRate = *sampleRate;
    }
    uassert(ErrorCodes::BadValue,
            "cannot set both sampleRate and ratelimit to non-default values",
            newSampleRate == 1.0 || newRateLimit == 1);
    serverGlobalParams.rateLimit = newRateLimit;
    serverGlobalParams.sampleRate = newSampleRate;

    return true;
}
}  // namespace mongo
