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

#define MONGO_LOG_DEFAULT_COMPONENT ::mongo::logger::LogComponent::kAccessControl

#include <fmt/format.h>
#include <ldap.h>
#include <sasl/sasl.h>

#include "mongo/db/auth/native_sasl_authentication_session.h"

#include <boost/scoped_ptr.hpp>
#include <boost/range/size.hpp>

#include "mongo/base/init.h"
#include "mongo/base/status.h"
#include "mongo/base/string_data.h"
#include "mongo/bson/util/bson_extract.h"
#include "mongo/client/sasl_client_authenticate.h"
#include "mongo/db/commands.h"
#include "mongo/db/auth/authorization_manager.h"
#include "mongo/db/auth/authorization_manager_global.h"
#include "mongo/db/auth/authorization_session.h"
#include "mongo/db/auth/sasl_options.h"
#include "mongo/db/auth/external/external_sasl_authentication_session.h"
#include "mongo/db/ldap_options.h"
#include "mongo/util/assert_util.h"
#include "mongo/util/log.h"
#include "mongo/util/mongoutils/str.h"
#include "mongo/util/net/sock.h"

namespace mongo {

    using boost::scoped_ptr;
    using namespace fmt::literals;

namespace {

    static SaslAuthenticationSession::SaslAuthenticationSessionFactoryFn createSaslBase;

    SaslAuthenticationSession* createExternalSaslAuthenticationSession(
        AuthorizationSession* authzSession,
        StringData db,
        StringData mechanism) {
        if (mechanism == "PLAIN" && db == saslDefaultDBName)
            if (!ldapGlobalParams.ldapServers->empty())
                return new OpenLDAPAuthenticationSession(authzSession);
            else
                return new ExternalSaslAuthenticationSession(authzSession);
        else
            return createSaslBase(authzSession, db, mechanism);
    }

    // External SASL session factory needs to be set AFTER the native one has been set.
    MONGO_INITIALIZER_GENERAL(ExternalSaslServerCore, ("NativeSaslServerCore"), ("PostSaslCommands"))
        (InitializerContext* context) {
        if (saslGlobalParams.hostName.empty())
            saslGlobalParams.hostName = getHostNameCached();
        if (saslGlobalParams.serviceName.empty())
            saslGlobalParams.serviceName = "mongodb";

        int result = sasl_server_init(NULL, saslDefaultServiceName);
        if (result != SASL_OK) {
            log() << "Failed Initializing External Auth Session" << std::endl;
            return ExternalSaslAuthenticationSession::getInitializationError(result);
        }

        log() << "Initialized External Auth Session" << std::endl;
        createSaslBase = SaslAuthenticationSession::create;
        SaslAuthenticationSession::create = createExternalSaslAuthenticationSession;
        return Status::OK();
    }

} //namespace

    ExternalSaslAuthenticationSession::ExternalSaslAuthenticationSession(
        AuthorizationSession* authzSession) :
        SaslAuthenticationSession(authzSession),
        _saslConnection(NULL),
        _mechanism("") {
        _results.result = SASL_FAIL;
        _results.output = NULL;
        _results.length = 0;
    }

    ExternalSaslAuthenticationSession::~ExternalSaslAuthenticationSession() {
        if (_saslConnection) {
            sasl_dispose(&_saslConnection);
        }
    }

    Status ExternalSaslAuthenticationSession::start(StringData authenticationDatabase,
                                                    StringData mechanism,
                                                    StringData serviceName,
                                                    StringData serviceHostname,
                                                    int64_t conversationId,
                                                    bool autoAuthorize) {
        if (_conversationId != 0) {
            return Status(ErrorCodes::AlreadyInitialized,
                          "Cannot call start() twice on same ExternalSaslAuthenticationSession.");
        }

        _authenticationDatabase = authenticationDatabase.toString();
        _mechanism = mechanism.toString();
        _serviceName = serviceName.toString();
        _serviceHostname = serviceHostname.toString();
        _conversationId = conversationId;
        _autoAuthorize = autoAuthorize;

        // NOTE: At this point we could ask libsasl2 if the given
        // mechanism is supported, though later it will report an
        // error for an unsupported mechanism during the first SASL
        // step.
        return this->initializeConnection();
    }

    Status ExternalSaslAuthenticationSession::step(StringData inputData, std::string* outputData) {
        if (_saslStep++ == 0) {
            this->processInitialClientPayload(inputData);
        } else {
            this->processNextClientPayload(inputData);
        }

        this->copyStepOutput(outputData);
        return this->getStepResult();
    }
    
    Status ExternalSaslAuthenticationSession::getStepResult() const {
        if (_results.resultsShowNoError()) {
            return Status::OK();
        }

        return Status(ErrorCodes::OperationFailed,
                      mongoutils::str::stream() <<
                      "SASL step did not complete: (" <<
                      sasl_errstring(_results.result, NULL, NULL) <<
                      ")");
    }

    std::string ExternalSaslAuthenticationSession::getPrincipalId() const {
        const char * username;
        int result = this->getUserName(&username);
        if (result == SASL_OK) {
            std::string principal(username);
            return principal;
        }
        
        return std::string("");
    }

    const char* ExternalSaslAuthenticationSession::getMechanism() const {
        return _mechanism.c_str();
    }

    Status ExternalSaslAuthenticationSession::initializeConnection() {
        int result = sasl_server_new(saslDefaultServiceName,
                                     prettyHostName().c_str(), // Fully Qualified Domain Name (FQDN), NULL => gethostname()
                                     NULL, // User Realm string, NULL forces default value: FQDN.
                                     NULL, // Local IP address
                                     NULL, // Remote IP address
                                     NULL, // Callbacks specific to this connection.
                                     0,    // Security flags.
                                     &_saslConnection); // Connection object output parameter.
        if (result != SASL_OK) {
            return ExternalSaslAuthenticationSession::getInitializationError(result);
        }

        return Status::OK();
    }

    Status ExternalSaslAuthenticationSession::getInitializationError(int result) {
        return Status(ErrorCodes::OperationFailed,
                      mongoutils::str::stream() <<
                      "Could not initialize sasl server session (" <<
                      sasl_errstring(result, NULL, NULL) <<
                      ")");
    }

    void ExternalSaslAuthenticationSession::processInitialClientPayload(const StringData& payload) {
        _results.initialize_results();
        _results.result = sasl_server_start(_saslConnection,
                                           _mechanism.c_str(),
                                           payload.rawData(),
                                           static_cast<unsigned>(payload.size()),
                                           &_results.output,
                                           &_results.length);
        this->updateDoneStatus();
    }

    void ExternalSaslAuthenticationSession::processNextClientPayload(const StringData& payload) {
        _results.initialize_results();
        _results.result = sasl_server_step(_saslConnection,
                                          payload.rawData(),
                                          static_cast<unsigned>(payload.size()),
                                          &_results.output,
                                          &_results.length);
        this->updateDoneStatus();
    }

    void ExternalSaslAuthenticationSession::copyStepOutput(std::string *output) const {
        if (_results.resultsShowNoError()) {
            output->assign(_results.output, _results.length);
        }
    }

    void ExternalSaslAuthenticationSession::updateDoneStatus() {
        if (_results.resultsAreOK()) {
            _done = true;
        }
    }

    int ExternalSaslAuthenticationSession::getUserName(const char ** username) const {
        return sasl_getprop(_saslConnection, SASL_USERNAME, (const void**)username);
    }


extern "C" {

struct interactionParameters {
    const char* realm;
    const char* dn;
    const char* pw;
    const char* userid;
};

static int interaction(unsigned flags, sasl_interact_t *interact, void *defaults) {
    interactionParameters *params = (interactionParameters*)defaults;
    const char *dflt = interact->defresult;

    switch (interact->id) {
    case SASL_CB_GETREALM:
        dflt = params->realm;
        break;
    case SASL_CB_AUTHNAME:
        dflt = params->dn;
        break;
    case SASL_CB_PASS:
        dflt = params->pw;
        break;
    case SASL_CB_USER:
        dflt = params->userid;
        break;
    }

    if (dflt && !*dflt)
        dflt = NULL;

    if (flags != LDAP_SASL_INTERACTIVE &&
        (dflt || interact->id == SASL_CB_USER)) {
        goto use_default;
    }

    if( flags == LDAP_SASL_QUIET ) {
        /* don't prompt */
        return LDAP_OTHER;
    }


use_default:
    interact->result = (dflt && *dflt) ? dflt : "";
    interact->len = std::strlen( (char*)interact->result );

    return LDAP_SUCCESS;
}

static int interactProc(LDAP *ld, unsigned flags, void *defaults, void *in) {
    sasl_interact_t *interact = (sasl_interact_t*)in;

    if (ld == NULL)
        return LDAP_PARAM_ERROR;

    while (interact->id != SASL_CB_LIST_END) {
        int rc = interaction( flags, interact, defaults );
        if (rc)
            return rc;
        interact++;
    }
    
    return LDAP_SUCCESS;
}

} // extern "C"


OpenLDAPAuthenticationSession::OpenLDAPAuthenticationSession(
    AuthorizationSession* authzSession) :
    SaslAuthenticationSession(authzSession) {}

OpenLDAPAuthenticationSession::~OpenLDAPAuthenticationSession() {
    ldap_memfree(_principal);
    if (_ld) {
        ldap_unbind_ext(_ld, nullptr, nullptr);
        _ld = nullptr;
    }
}


Status OpenLDAPAuthenticationSession::start(StringData authenticationDatabase,
                                              StringData mechanism,
                                              StringData serviceName,
                                              StringData serviceHostname,
                                              int64_t conversationId,
                                              bool autoAuthorize) {
    if (_conversationId != 0) {
        return Status(ErrorCodes::AlreadyInitialized,
                      "Cannot call start() twice on same OpenLDAPAuthenticationSession.");
    }

    _authenticationDatabase = authenticationDatabase.toString();
    _mechanism = mechanism.toString();
    _serviceName = serviceName.toString();
    _serviceHostname = serviceHostname.toString();
    _conversationId = conversationId;
    _autoAuthorize = autoAuthorize;

    return Status::OK();
}

Status OpenLDAPAuthenticationSession::step(StringData inputData, std::string* outputData) {
    if (_saslStep++ == 0) {
        auto uri = "ldap://{}/"_format(ldapGlobalParams.ldapServers.get());
        int res = ldap_initialize(&_ld, uri.c_str());
        if (res != LDAP_SUCCESS) {
            return Status(ErrorCodes::LDAPLibraryError,
                          "Cannot initialize LDAP structure for {}; LDAP error: {}"_format(
                              uri, ldap_err2string(res)));
        }
        const int ldap_version = LDAP_VERSION3;
        res = ldap_set_option(_ld, LDAP_OPT_PROTOCOL_VERSION, &ldap_version);
        if (res != LDAP_OPT_SUCCESS) {
            return Status(ErrorCodes::LDAPLibraryError,
                          "Cannot set LDAP version option; LDAP error: {}"_format(
                              ldap_err2string(res)));
        }
        const char* userid = inputData.rawData();
        const char* dn = userid + std::strlen(userid) + 1; // authentication id
        const char* pw = dn + std::strlen(dn) + 1; // password
        if (ldapGlobalParams.ldapBindMethod == "simple") {
            // ldap_simple_bind_s was deprecated in favor of ldap_sasl_bind_s
            berval cred;
            cred.bv_val = (char*)pw;
            cred.bv_len = std::strlen(pw);
            res = ldap_sasl_bind_s(_ld, dn, LDAP_SASL_SIMPLE, &cred, nullptr, nullptr, nullptr);
            if (res != LDAP_SUCCESS) {
                return Status(ErrorCodes::LDAPLibraryError,
                              "Failed to authenticate '{}' using simple bind; LDAP error: {}"_format(
                                  dn, ldap_err2string(res)));
            }
        }
        else if (ldapGlobalParams.ldapBindMethod == "sasl") {
            interactionParameters params;
            params.userid = userid;
            params.dn = dn;
            params.pw = pw;
            params.realm = nullptr;
            res = ldap_sasl_interactive_bind_s(
                    _ld,
                    dn,
                    ldapGlobalParams.ldapBindSaslMechanisms.c_str(),
                    nullptr,
                    nullptr,
                    LDAP_SASL_QUIET,
                    interactProc,
                    &params);
            if (res != LDAP_SUCCESS) {
                return Status(ErrorCodes::LDAPLibraryError,
                              "Failed to authenticate '{}' using sasl bind; LDAP error: {}"_format(
                                  dn, ldap_err2string(res)));
            }
        }
        else {
            return Status(ErrorCodes::OperationFailed,
                          "Unknown bind method: {}"_format(ldapGlobalParams.ldapBindMethod));
        }
        _done = true;
        return Status::OK();
    }
    // This authentication session supports single step
    return Status(ErrorCodes::InternalError,
                  "An invalid second step was called against the OpenLDAP authentication session");

}

std::string OpenLDAPAuthenticationSession::getPrincipalId() const {
    if (_principal
        || (_ld && LDAP_OPT_SUCCESS == ldap_get_option(_ld, LDAP_OPT_X_SASL_USERNAME, &_principal))) {
        return _principal;
    }

    return "";
}

const char* OpenLDAPAuthenticationSession::getMechanism() const {
    return _mechanism.c_str();
}

}  // namespace mongo
