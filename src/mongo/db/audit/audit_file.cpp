/* -*- mode: C++; c-basic-offset: 4; indent-tabs-mode: nil -*- */
// vim: ft=cpp:expandtab:ts=8:sw=4:softtabstop=4:

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

#include <iostream>

#define MONGO_LOGV2_DEFAULT_COMPONENT ::mongo::logv2::LogComponent::kDefault
#include "mongo/logv2/log.h"

#include "audit_file.h"

namespace mongo {

namespace audit {

int AuditFile::fsyncReturningError() const {
    if (::fsync(_fd)) {
        int _errno = errno;
        LOGV2(29023, "In File::fsync(), ::fsync for '{name}' failed with {err_desc}",
                "name"_attr = _name,
                "err_desc"_attr = errnoWithDescription());
        return _errno;
    }
    return 0;
}

int AuditFile::writeReturningError(fileofs o, const char *data, unsigned len) {
    ssize_t bytesWritten = ::pwrite(_fd, data, len, o);
    if (bytesWritten != static_cast<ssize_t>(len)) {
        _bad = true;
        int _errno = errno;
        LOGV2(29024, "In File::write(), ::pwrite for '{name}' tried to write {len} bytes "
                "but only wrote {written} bytes, failing with {err_desc}",
                "name"_attr = _name,
                "len"_attr = len,
                "written"_attr = bytesWritten,
                "err_desc"_attr = errnoWithDescription());
        return _errno;
    }
    return 0;
}

}  // namespace audit
}  // namespace mongo

