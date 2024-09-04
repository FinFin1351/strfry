#include "RelayServer.h"
#include "QueryScheduler.h"

void RelayServer::runIngester(ThreadPool<MsgIngester>::Thread &thr) {
    secp256k1_context *secpCtx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    Decompressor decomp;

    while(1) {
        auto newMsgs = thr.inbox.pop_all();

        auto txn = env.txn_ro();

        std::vector<MsgWriter> writerMsgs;

        for (auto &newMsg : newMsgs) {
            if (auto msg = std::get_if<MsgIngester::ClientMessage>(&newMsg.msg)) {
                try {
                    if (msg->payload.starts_with('[')) {
                        auto payload = tao::json::from_string(msg->payload);

                        if (cfg().relay__logging__dumpInAll) LI << "[" << msg->connId << "] dumpInAll: " << msg->payload; 

                        auto &arr = jsonGetArray(payload, "message is not an array");
                        if (arr.size() < 2) throw herr("too few array elements");

                        auto &cmd = jsonGetString(arr[0], "first element not a command like REQ");

                        if (cmd == "EVENT") {
                            if (cfg().relay__logging__dumpInEvents) LI << "[" << msg->connId << "] dumpInEvent: " << msg->payload; 

                            try {
                                ingesterProcessEvent(txn, msg->connId, msg->ipAddr, secpCtx, arr[1], writerMsgs);
                            } catch (std::exception &e) {
                                sendOKResponse(msg->connId, arr[1].is_object() && arr[1].at("id").is_string() ? arr[1].at("id").get_string() : "?",
                                               false, std::string("invalid: ") + e.what());
                                if (cfg().relay__logging__invalidEvents) LI << "Rejected invalid event: " << e.what();
                            }
                        } else if (cmd == "EVENTS") {
                            try {
                                ingesterProcessEvents(txn, msg->connId, msg->ipAddr, secpCtx, arr[1], writerMsgs);
                            } catch (std::exception &e) {
                                sendOKResponse(msg->connId, arr[1].at("id").get_string(), false, std::string("invalid: ") + e.what());
                                if (cfg().relay__logging__invalidEvents) LI << "Rejected invalid EVENTS: " << e.what();
                            }
                        } else if (cmd == "REQ") {
                            if (cfg().relay__logging__dumpInReqs) LI << "[" << msg->connId << "] dumpInReq: " << msg->payload; 

                            try {
                                ingesterProcessReq(txn, msg->connId, arr);
                            } catch (std::exception &e) {
                                sendNoticeError(msg->connId, std::string("bad req: ") + e.what());
                            }
                        } else if (cmd == "CLOSE") {
                            if (cfg().relay__logging__dumpInReqs) LI << "[" << msg->connId << "] dumpInReq: " << msg->payload; 

                            try {
                                ingesterProcessClose(txn, msg->connId, arr);
                            } catch (std::exception &e) {
                                sendNoticeError(msg->connId, std::string("bad close: ") + e.what());
                            }
                        } else if (cmd.starts_with("NEG-")) {
                            if (!cfg().relay__negentropy__enabled) throw herr("negentropy disabled");

                            try {
                                ingesterProcessNegentropy(txn, decomp, msg->connId, arr);
                            } catch (std::exception &e) {
                                sendNoticeError(msg->connId, std::string("negentropy error: ") + e.what());
                            }
                        }  else if (cmd == "COUNT") {
                            if (cfg().relay__logging__dumpInReqs) LI << "[" << msg->connId << "] dumpInCount: " << msg->payload; 
                            try {
                                ingesterProcessCount(txn, msg->connId, arr);
                            } catch (std::exception &e) {
                                sendNoticeError(msg->connId, std::string("bad count: ") + e.what());
                            }
                        } else {
                            throw herr("unknown cmd");
                        }
                    } else if (msg->payload == "\n") {
                        // Do nothing.
                        // This is for when someone is just sending newlines on websocat for debugging purposes.
                    } else {
                        throw herr("unparseable message");
                    }
                } catch (std::exception &e) {
                    sendNoticeError(msg->connId, std::string("bad msg: ") + e.what());
                }
            } else if (auto msg = std::get_if<MsgIngester::CloseConn>(&newMsg.msg)) {
                auto connId = msg->connId;
                tpWriter.dispatch(connId, MsgWriter{MsgWriter::CloseConn{connId}});
                tpReqWorker.dispatch(connId, MsgReqWorker{MsgReqWorker::CloseConn{connId}});
                tpNegentropy.dispatch(connId, MsgNegentropy{MsgNegentropy::CloseConn{connId}});
            }
        }

        if (writerMsgs.size()) {
            tpWriter.dispatchMulti(0, writerMsgs);
        }
    }
}

void RelayServer::ingesterProcessEvent(lmdb::txn &txn, uint64_t connId, std::string ipAddr, secp256k1_context *secpCtx, const tao::json::value &origJson, std::vector<MsgWriter> &output) {
    std::string packedStr, jsonStr;

    parseAndVerifyEvent(origJson, secpCtx, true, true, packedStr, jsonStr);

    PackedEventView packed(packedStr);

    {
        bool foundProtected = false;

        packed.foreachTag([&](char tagName, std::string_view tagVal){
            if (tagName == '-') {
                foundProtected = true;
                return false;
            }
            return true;
        });

        if (foundProtected) {
            LI << "Protected event, skipping";
            sendOKResponse(connId, to_hex(packed.id()), false, "blocked: event marked as protected");
            return;
        }
    }

    {
        auto existing = lookupEventById(txn, packed.id());
        if (existing) {
            LI << "Duplicate event, skipping";
            sendOKResponse(connId, to_hex(packed.id()), true, "duplicate: have this event");
            return;
        }
    }

    output.emplace_back(MsgWriter{MsgWriter::AddEvent{connId, std::move(ipAddr), std::move(packedStr), std::move(jsonStr)}});
}

void RelayServer::ingesterProcessEvents(lmdb::txn &txn, uint64_t connId, std::string ipAddr, secp256k1_context *secpCtx, const tao::json::value &eventsArray, std::vector<MsgWriter> &output) {
    if (!eventsArray.is_array()) {
        throw herr("EVENTS payload is not an array");
    }

    for (const auto &eventJson : eventsArray.get_array()) {
        try {
            ingesterProcessEvent(txn, connId, ipAddr, secpCtx, eventJson, output);
        } catch (std::exception &e) {
            sendNoticeError(connId, std::string("EVENT processing error: ") + e.what());
            if (cfg().relay__logging__invalidEvents) {
                LI << "Error processing EVENT in EVENTS batch: " << e.what();
            }
        }
    }

    sendOKResponse(connId, "", true, "batch processed");
}

void RelayServer::ingesterProcessReq(lmdb::txn &txn, uint64_t connId, const tao::json::value &arr) {
    if (arr.get_array().size() < 2 + 1) throw herr("arr too small");
    if (arr.get_array().size() > 2 + 20) throw herr("arr too big");

    Subscription sub(connId, jsonGetString(arr[1], "REQ subscription id was not a string"), NostrFilterGroup(arr));

    tpReqWorker.dispatch(connId, MsgReqWorker{MsgReqWorker::NewSub{std::move(sub)}});
}

void RelayServer::ingesterProcessCount(lmdb::txn &txn, uint64_t connId, const tao::json::value &arr) {
    if (arr.get_array().size() < 2 + 1) throw herr("arr too small");
    if (arr.get_array().size() > 2 + 20) throw herr("arr too big");

    uint64_t maxLimit = UINT64_MAX;
    Subscription sub(connId, arr[1].get_string(), NostrFilterGroup(arr, maxLimit));

    QueryScheduler queries;
    size_t eventCount = 0;

    queries.onEvent = [&](lmdb::txn &txn, const auto &sub, uint64_t levId, std::string_view eventPayload) {
        eventCount++;
    };

    if (!queries.addSub(txn, std::move(sub))) {
        sendNoticeError(connId, std::string("too many concurrent REQs"));
        return;
    }

    queries.process(txn);

    tao::json::value response = {{"count", eventCount}};
    std::string response_str = tao::json::to_string(response);
    sendOKResponse(connId, arr[1].get_string(), true, response_str);
}

void RelayServer::ingesterProcessClose(lmdb::txn &txn, uint64_t connId, const tao::json::value &arr) {
    if (arr.get_array().size() != 2) throw herr("arr too small/big");

    tpReqWorker.dispatch(connId, MsgReqWorker{MsgReqWorker::RemoveSub{connId, SubId(jsonGetString(arr[1], "CLOSE subscription id was not a string"))}});
}

void RelayServer::ingesterProcessNegentropy(lmdb::txn &txn, Decompressor &decomp, uint64_t connId, const tao::json::value &arr) {
    const auto &subscriptionStr = jsonGetString(arr[1], "NEG-OPEN subscription id was not a string");

    if (arr.at(0) == "NEG-OPEN") {
        if (arr.get_array().size() < 4) throw herr("negentropy query missing elements");

        auto maxFilterLimit = cfg().relay__negentropy__maxSyncEvents + 1;

        auto filterJson = arr.at(2);

        NostrFilterGroup filter = NostrFilterGroup::unwrapped(filterJson, maxFilterLimit);
        Subscription sub(connId, subscriptionStr, std::move(filter));

        if (filterJson.is_object()) {
            filterJson.get_object().erase("since");
            filterJson.get_object().erase("until");
        }
        std::string filterStr = tao::json::to_string(filterJson);

        std::string negPayload = from_hex(jsonGetString(arr.at(3), "negentropy payload not a string"));

        tpNegentropy.dispatch(connId, MsgNegentropy{MsgNegentropy::NegOpen{std::move(sub), std::move(filterStr), std::move(negPayload)}});
    } else if (arr.at(0) == "NEG-MSG") {
        std::string negPayload = from_hex(jsonGetString(arr.at(2), "negentropy payload not a string"));
        tpNegentropy.dispatch(connId, MsgNegentropy{MsgNegentropy::NegMsg{connId, SubId(subscriptionStr), std::move(negPayload)}});
    } else if (arr.at(0) == "NEG-CLOSE") {
        tpNegentropy.dispatch(connId, MsgNegentropy{MsgNegentropy::NegClose{connId, SubId(subscriptionStr)}});
    } else {
        throw herr("unknown command");
    }
}
