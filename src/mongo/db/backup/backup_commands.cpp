/*======
This file is part of Percona Server for MongoDB.

Copyright (C) 2018-present Percona and/or its affiliates. All rights reserved.

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

#include <boost/filesystem.hpp>

#include "mongo/db/auth/action_type.h"
#include "mongo/db/auth/authorization_session.h"
#include "mongo/db/backup/backupable.h"
#include "mongo/db/commands.h"
#include "mongo/db/service_context.h"
#include "mongo/db/storage/engine_extension.h"
#include "mongo/db/storage/storage_options.h"

namespace mongo {
    extern StorageGlobalParams storageGlobalParams;
}
using namespace mongo;

namespace percona {

class CreateBackupCommand : public ErrmsgCommandDeprecated {
public:
    CreateBackupCommand() : ErrmsgCommandDeprecated("createBackup") {}
    void help(std::stringstream& help) const override {
        help << "Creates a hot backup, into the given directory, of the files currently in the "
                "storage engine's data directory."
             << std::endl
             << "{ createBackup: 1, backupDir: <destination directory> }";
    }
    Status checkAuthForCommand(Client* client,
                               const std::string& dbname,
                               const BSONObj& cmdObj) override {
        return AuthorizationSession::get(client)->isAuthorizedForActionsOnResource(
                   ResourcePattern::forAnyNormalResource(), ActionType::startBackup)
            ? Status::OK()
            : Status(ErrorCodes::Unauthorized, "Unauthorized");
    }
    bool adminOnly() const override {
        return true;
    }
    bool slaveOk() const override {
        return true;
    }
    bool supportsWriteConcern(const BSONObj& cmd) const override {
        return false;
    }
    bool errmsgRun(mongo::OperationContext* opCtx,
             const std::string& db,
             const BSONObj& cmdObj,
             std::string& errmsg,
             BSONObjBuilder& result) override;
} createBackupCmd;

bool CreateBackupCommand::errmsgRun(mongo::OperationContext* opCtx,
                              const std::string& db,
                              const BSONObj& cmdObj,
                              std::string& errmsg,
                              BSONObjBuilder& result) {
    namespace fs = boost::filesystem;

    const std::string& dest = cmdObj["backupDir"].String();
    fs::path destPath(dest);

    // Validate destination directory.
    try {
        if (!destPath.is_absolute()) {
            errmsg = "Destination path must be absolute";
            return false;
        }

        fs::create_directory(destPath);
    } catch (const fs::filesystem_error& ex) {
        errmsg = ex.what();
        return false;
    }

    // Flush all files first.
    auto se = getGlobalServiceContext()->getGlobalStorageEngine();
    se->flushAllFiles(opCtx, true);

    // Do the backup itself.
    const auto status = se->hotBackup(opCtx, dest);

    if (!status.isOK()) {
        errmsg = status.reason();
        return false;
    }

    return true;
}

}  // end of percona namespace.
