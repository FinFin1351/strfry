#include <thread>
#include <chrono>

#include <uWebSockets/src/uWS.h>

#include "golpe.h"

#include "events.h"

class WSConnection : NonCopyable {
    std::string url;

    uWS::Hub hub;
    uWS::Group<uWS::CLIENT> *hubGroup = nullptr;
    uS::Async *hubTrigger = nullptr;

    uWS::WebSocket<uWS::CLIENT> *currWs = nullptr;


  public:

    WSConnection(const std::string &url) : url(url) {}

    std::function<void()> onConnect;
    std::function<void(std::string_view, uWS::OpCode, size_t)> onMessage;
    std::function<void()> onTrigger;
    std::function<void()> onDisconnect;
    std::function<void()> onError;
    bool reconnect = true;
    std::atomic<bool> shutdown = false;
    uint64_t reconnectDelayMilliseconds = 5'000;
    std::string remoteAddr;

    ~WSConnection() {
        if (hubGroup || hubTrigger || currWs) LW << "WSConnection destroyed before close";
    }

    void close() {
        shutdown = true;
        trigger();
    }

    // Should only be called from the websocket thread (ie within an onConnect or onMessage callback)
    void send(std::string_view msg, uWS::OpCode op = uWS::OpCode::TEXT, size_t *compressedSize = nullptr) {
        if (currWs) {
            currWs->send(msg.data(), msg.size(), op, nullptr, nullptr, true, compressedSize);
        } else {
            LI << "Tried to send message, but websocket is disconnected";
        }
    }

    // Can be called from any thread, invokes onTrigger in websocket thread context
    void trigger() {
        if (hubTrigger) hubTrigger->send();
    }

    void run() {
        hubGroup = hub.createGroup<uWS::CLIENT>(uWS::PERMESSAGE_DEFLATE | uWS::SLIDING_DEFLATE_WINDOW);

        auto doConnect = [&](uint64_t delay = 0){
            if (delay) std::this_thread::sleep_for(std::chrono::milliseconds(delay));
            if (shutdown) return;
            LI << "Attempting to connect to " << url;
            hub.connect(url, nullptr, {}, 5000, hubGroup);
        };


        hubGroup->onConnection([&](uWS::WebSocket<uWS::CLIENT> *ws, uWS::HttpRequest req) {
            if (shutdown) return;

            if (currWs) {
                currWs->terminate();
                currWs = nullptr;
            }

            remoteAddr = ws->getAddress().address;
            LI << "Connected to " << url << " (" << remoteAddr << ")";

            {
                int optval = 1;
                if (setsockopt(ws->getFd(), SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(optval))) {
                    LW << "Failed to enable TCP keepalive: " << strerror(errno);
                }
            }

            currWs = ws;

            if (!onConnect) return;
            try {
                onConnect();
            } catch (std::exception &e) {
                LW << "onConnect failure: " << e.what();
            }
        });

        hubGroup->onDisconnection([&](uWS::WebSocket<uWS::CLIENT> *ws, int code, char *message, size_t length) {
            LI << "Disconnected from " << url << " : " << code << "/" << (message ? std::string_view(message, length) : "-");

            if (shutdown) return;

            if (ws == currWs) {
                currWs = nullptr;

                if (onDisconnect) onDisconnect();
                if (reconnect) doConnect(reconnectDelayMilliseconds);
            } else {
                LI << "Got disconnect for unexpected connection?";
            }
        });

        hubGroup->onError([&](void *) {
            LI << "Websocket connection error";

            if (onError) onError();
            if (reconnect) doConnect(reconnectDelayMilliseconds);
        });

        hubGroup->onMessage2([&](uWS::WebSocket<uWS::CLIENT> *ws, char *message, size_t length, uWS::OpCode opCode, size_t compressedSize) {
            onMessageReceived(ws, message, length, opCode, compressedSize);
        });

        std::function<void()> asyncCb = [&]{
            if (shutdown) {
                terminate();
                return;
            }

            if (!onTrigger) return;

            try {
                onTrigger();
            } catch (std::exception &e) {
                LW << "onTrigger failure: " << e.what();
            }
        };

        hubTrigger = new uS::Async(hub.getLoop());
        hubTrigger->setData(&asyncCb);

        hubTrigger->start([](uS::Async *a){
            auto *r = static_cast<std::function<void()> *>(a->getData());
            (*r)();
        });


        doConnect();

        hub.run();
    }


  private:

    bool authRequired = false;  // Indicates if authentication is required
    bool authCompleted = false; // Indicates if authentication is completed
    std::mutex authMutex;       // Mutex for thread safety
    std::condition_variable authCondVar; // Condition variable for authentication state

    // Internal message handler
    void onMessageReceived(uWS::WebSocket<uWS::CLIENT> *ws, char *message, size_t length, uWS::OpCode opCode, size_t compressedSize) {
        std::string_view msg(message, length);
        auto origJson = tao::json::from_string(msg);

        if (origJson.is_array()) {
            auto &msgArray = origJson.get_array();
            if (!msgArray.empty()) {
                auto &msgTypeValue = msgArray[0];
                if (msgTypeValue.is_string()) {
                    std::string msgType = msgTypeValue.get_string();
                    if (msgType == "AUTH") {
                        // AUTH message received, start authentication
                        authRequired = true;
                        if (msgArray.size() >= 2 && msgArray[1].is_string()) {
                            std::string challenge = msgArray[1].get_string();
                            performAuthentication(challenge);
                        }
                        return; // AUTH message handled, no need to pass to onMessage
                    } else if (msgType == "OK" && authRequired && !authCompleted) {
                        // Handle OK message related to AUTH
                        if (msgArray.size() >= 4) {
                            std::string eventId = msgArray[1].get_string();
                            bool success = msgArray[2].get_boolean();
                            std::string message = msgArray[3].get_string();

                            {
                                std::lock_guard<std::mutex> lock(authMutex);
                                authCompleted = true;
                            }
                            authCondVar.notify_one();

                            if (success) {
                                LI << "Authentication succeeded: " << message;
                            } else {
                                LW << "Authentication failed: " << message;
                                // Optionally close the connection or take other action
                                close();
                            }
                        }
                        return; // OK message handled, no need to pass to onMessage
                    }
                }
            }
        }

        // If authentication is completed or not required, forward the message to onMessage
        {
            std::lock_guard<std::mutex> lock(authMutex);
            if (!authRequired || authCompleted) {
                // Authentication is complete or not required, forward message to user-defined onMessage
                if (onMessage) {
                    try {
                        onMessage(msg, opCode, compressedSize);
                    } catch (std::exception &e) {
                        LW << "onMessage exception: " << e.what();
                    }
                }
            }
        }
    }

    void performAuthentication(const std::string &challenge) {
        try {

            // Construct the AUTH event using the function from events.h
            tao::json::value authEvent = constructAuthEvent(challenge);

            // Create the AUTH message
            tao::json::value authMsg = tao::json::value::array({ "AUTH", authEvent });

            // Send the AUTH message over WebSocket
            send(tao::json::to_string(authMsg));

        } catch (const std::exception &e) {
            LW << "Failed to perform authentication: " << e.what();
            // Handle the failure (e.g., close the connection if necessary)
            close();
        }
    }

    void terminate() {
        if (hubGroup) {
            hubGroup->close();
            hubGroup = nullptr;
        }

        if (hubTrigger) {
            hubTrigger->close();
            hubTrigger = nullptr;
        }

        if (currWs) {
            currWs->terminate();
            currWs = nullptr;
        }
    }
};
