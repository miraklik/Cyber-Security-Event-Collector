#include<iostream>
#include<vector>
#include "Logger.hpp"

void SecurityLogger::logEvent(std::unique_ptr<Event> event) {
    std::lock_guard<std::mutex> lock(mtx_);
    std::cout << "[LOG] Device: " << event->device << " | Msg: " << event->message << std::endl;
    events_.push_back(std::move(event));
}