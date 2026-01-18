#ifndef LOGGER_HPP
#define LOGGER_HPP

#include <string>
#include <vector>
#include <memory>
#include <mutex>

struct Event {
    int id;
    std::string device;
    std::string message;
};

class SecurityLogger {
public:
    void logEvent(std::unique_ptr<Event> event);
private:
    std::vector<std::unique_ptr<Event>> events_;
    std::mutex mtx_;
};

#endif // LOGGER_HPP