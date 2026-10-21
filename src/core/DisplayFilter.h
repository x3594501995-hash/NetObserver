#pragma once

#include "core/PacketTypes.h"

#include <memory>
#include <string>

namespace netobserver {

class DisplayFilter {
public:
    struct Node;

    DisplayFilter();
    DisplayFilter(const DisplayFilter&) = delete;
    DisplayFilter& operator=(const DisplayFilter&) = delete;
    DisplayFilter(DisplayFilter&&) noexcept = default;
    DisplayFilter& operator=(DisplayFilter&&) noexcept = default;
    ~DisplayFilter();

    bool compile(const std::string& expression, std::string& error);
    bool matches(const ParsedPacket& packet) const;
    bool empty() const noexcept;

private:
    std::shared_ptr<Node> root_;
};

} // namespace netobserver

