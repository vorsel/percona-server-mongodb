
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

#pragma once

#include <boost/optional.hpp>

#include "mongo/base/disallow_copying.h"
#include "mongo/db/concurrency/lock_manager_defs.h"
#include "mongo/util/time_support.h"

namespace mongo {

class OperationContext;

namespace repl {

/**
 * This object handles acquiring the RSTL for replication state transitions, as well as any actions
 * that need to happen in between enqueuing the RSTL request and waiting for it to be granted.
 */
class ReplicationStateTransitionLockGuard {
    MONGO_DISALLOW_COPYING(ReplicationStateTransitionLockGuard);

public:
    class EnqueueOnly {};

    /**
     * Acquires the RSTL in mode X.
     */
    ReplicationStateTransitionLockGuard(OperationContext* opCtx);

    /**
     * Enqueues RSTL in mode X but does not block on lock acquisition.
     * Must call waitForLockUntil() to complete locking process.
     */
    ReplicationStateTransitionLockGuard(OperationContext* opCtx, EnqueueOnly);

    ReplicationStateTransitionLockGuard(ReplicationStateTransitionLockGuard&&);
    ReplicationStateTransitionLockGuard& operator=(ReplicationStateTransitionLockGuard&&) = delete;

    ~ReplicationStateTransitionLockGuard();

    /**
     * Waits for RSTL to be granted.
     */
    void waitForLockUntil(Date_t deadline);

    /**
     * Release and reacquire the RSTL in mode X.
     */
    void release();
    void reacquire();

    bool isLocked() const {
        return _result == LOCK_OK;
    }

private:
    void _enqueueLock();
    void _unlock();

    OperationContext* const _opCtx;
    LockResult _result;
};

}  // namespace repl
}  // namespace mongo
