/*======
This file is part of Percona Server for MongoDB.

Copyright (C) 2021-present Percona and/or its affiliates. All rights reserved.

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

#define MONGO_LOGV2_DEFAULT_COMPONENT ::mongo::logv2::LogComponent::kQuery

#include "mongo/platform/basic.h"

#include "mongo/db/pipeline/document_source_backup_cursor.h"
#include "mongo/logv2/log.h"

namespace mongo {

using boost::intrusive_ptr;

// We only link this file into mongod so this stage doesn't exist in mongos
REGISTER_DOCUMENT_SOURCE(backupCursor,
                         LiteParsedDocumentSourceDefault::parse,
                         DocumentSourceBackupCursor::createFromBson,
                         AllowedWithApiStrict::kAlways);

const char* DocumentSourceBackupCursor::getSourceName() const {
    return kStageName.rawData();
}

Value DocumentSourceBackupCursor::serialize(
    boost::optional<ExplainOptions::Verbosity> explain) const {
    return Value(DOC(getSourceName() << 1));
}

DocumentSource::GetNextResult DocumentSourceBackupCursor::doGetNext() {
    if (_backupCursorState.preamble) {
        Document doc = _backupCursorState.preamble.get();
        _backupCursorState.preamble = boost::none;

        return doc;
    }

    if (_docIt == _backupBlocks.cend()) {
        constexpr std::size_t batchSize = 100;
        _backupBlocks =
            uassertStatusOK(_backupCursorState.streamingCursor->getNextBatch(batchSize));
        _docIt = _backupBlocks.cbegin();
        // Empty batch means streaming cursor is exhausted
        if (_backupBlocks.empty()) {
            return GetNextResult::makeEOF();
        }
    }

    // If length or offset is not 0 then output 4 fields,
    // otherwise output filename, fileSize only
    Document doc;
    if (_docIt->length != 0 || _docIt->offset != 0) {
        doc = Document{{"filename"_sd, _docIt->filename},
                       {"offset"_sd, static_cast<long long>(_docIt->offset)},
                       {"length"_sd, static_cast<long long>(_docIt->length)},
                       {"fileSize"_sd, static_cast<long long>(_docIt->fileSize)}};
    } else {
        doc = Document{{"filename"_sd, _docIt->filename},
                       {"fileSize"_sd, static_cast<long long>(_docIt->fileSize)}};
    }
    ++_docIt;

    return doc;
}

intrusive_ptr<DocumentSourceBackupCursor> DocumentSourceBackupCursor::create(
    const BSONObj& options, const intrusive_ptr<ExpressionContext>& expCtx) {
    intrusive_ptr<DocumentSourceBackupCursor> backupCursor(
        new DocumentSourceBackupCursor(options, expCtx));
    return backupCursor;
}

intrusive_ptr<DocumentSource> DocumentSourceBackupCursor::createFromBson(
    BSONElement elem, const intrusive_ptr<ExpressionContext>& pExpCtx) {
    // The anticipated usage of a backup cursor: open the backup cursor, consume the results, copy
    // data off disk, close the backup cursor. The backup cursor must be successfully closed for
    // the data copied to be valid. Hence, the caller needs a way to keep the cursor open after
    // consuming the results, as well as the ability to send "heartbeats" to prevent the client
    // cursor manager from timing out the backup cursor. A backup cursor does consume resources;
    // in the event the calling process crashes, the cursors should eventually be timed out.
    pExpCtx->tailableMode = TailableModeEnum::kTailable;

    uassert(ErrorCodes::FailedToParse,
            str::stream() << kStageName
                          << " value must be an object. Found: " << typeName(elem.type()),
            elem.type() == Object);

    return DocumentSourceBackupCursor::create(elem.Obj(), pExpCtx);
}

DocumentSourceBackupCursor::DocumentSourceBackupCursor(
    const BSONObj& options, const intrusive_ptr<ExpressionContext>& expCtx)
    : DocumentSource(kStageName, expCtx),
      _backupCursorState(
          pExpCtx->mongoProcessInterface->openBackupCursor(pExpCtx->opCtx, _backupOptions)),
      _backupBlocks(std::move(_backupCursorState.otherBackupBlocks)),
      _docIt(_backupBlocks.cbegin()) {}

DocumentSourceBackupCursor::~DocumentSourceBackupCursor() {
    try {
        pExpCtx->mongoProcessInterface->closeBackupCursor(pExpCtx->opCtx,
                                                          _backupCursorState.backupId);
    } catch (DBException& exc) {
        LOGV2_FATAL(29091,
                    "Error closing a backup cursor with Id {backupId}",
                    "Error closing a backup cursor.",
                    "backupId"_attr = _backupCursorState.backupId);
    }
}
}  // namespace mongo
