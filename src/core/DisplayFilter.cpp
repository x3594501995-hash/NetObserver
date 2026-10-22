#include "core/DisplayFilter.h"

#include <algorithm>
#include <cctype>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace netobserver {
namespace {

enum class TokenType {
    Word,
    LeftParen,
    RightParen,
    Equal,
    NotEqual,
    Greater,
    GreaterEqual,
    Less,
    LessEqual,
    End,
};

struct Token {
    TokenType type = TokenType::End;
    std::string text;
    std::size_t position = 0;
};

std::string lower(std::string value)
{
    std::transform(
        value.begin(),
        value.end(),
        value.begin(),
        [](unsigned char character) {
            return static_cast<char>(std::tolower(character));
        });
    return value;
}

std::vector<Token> tokenize(const std::string& expression)
{
    std::vector<Token> tokens;
    std::size_t index = 0;

    while (index < expression.size()) {
        const unsigned char character =
            static_cast<unsigned char>(expression[index]);
        if (std::isspace(character)) {
            ++index;
            continue;
        }

        const std::size_t position = index;
        if (expression[index] == '(') {
            tokens.push_back({TokenType::LeftParen, "(", position});
            ++index;
            continue;
        }
        if (expression[index] == ')') {
            tokens.push_back({TokenType::RightParen, ")", position});
            ++index;
            continue;
        }
        if (expression[index] == '=' &&
            index + 1 < expression.size() &&
            expression[index + 1] == '=') {
            tokens.push_back({TokenType::Equal, "==", position});
            index += 2;
            continue;
        }
        if (expression[index] == '!' &&
            index + 1 < expression.size() &&
            expression[index + 1] == '=') {
            tokens.push_back({TokenType::NotEqual, "!=", position});
            index += 2;
            continue;
        }
        if (expression[index] == '>' &&
            index + 1 < expression.size() &&
            expression[index + 1] == '=') {
            tokens.push_back({TokenType::GreaterEqual, ">=", position});
            index += 2;
            continue;
        }
        if (expression[index] == '<' &&
            index + 1 < expression.size() &&
            expression[index + 1] == '=') {
            tokens.push_back({TokenType::LessEqual, "<=", position});
            index += 2;
            continue;
        }
        if (expression[index] == '>') {
            tokens.push_back({TokenType::Greater, ">", position});
            ++index;
            continue;
        }
        if (expression[index] == '<') {
            tokens.push_back({TokenType::Less, "<", position});
            ++index;
            continue;
        }

        while (index < expression.size()) {
            const char current = expression[index];
            if (std::isspace(static_cast<unsigned char>(current)) ||
                current == '(' || current == ')' ||
                current == '=' || current == '!' ||
                current == '>' || current == '<') {
                break;
            }
            ++index;
        }

        if (index == position)
            throw std::runtime_error("无法识别的过滤符号");

        tokens.push_back({
            TokenType::Word,
            expression.substr(position, index - position),
            position,
        });
    }

    tokens.push_back({TokenType::End, "", expression.size()});
    return tokens;
}

bool compareNumber(long long left, TokenType operation, long long right)
{
    switch (operation) {
    case TokenType::Equal:
        return left == right;
    case TokenType::NotEqual:
        return left != right;
    case TokenType::Greater:
        return left > right;
    case TokenType::GreaterEqual:
        return left >= right;
    case TokenType::Less:
        return left < right;
    case TokenType::LessEqual:
        return left <= right;
    default:
        return false;
    }
}

bool compareText(
    const std::string& left,
    TokenType operation,
    const std::string& right)
{
    const bool equal = lower(left) == lower(right);
    if (operation == TokenType::Equal)
        return equal;
    if (operation == TokenType::NotEqual)
        return !equal;
    return false;
}

bool hasPort(const ParsedPacket& packet, std::uint16_t port)
{
    return packet.hasPorts &&
        (packet.sourcePort == port || packet.destinationPort == port);
}

bool isProtocol(const ParsedPacket& packet, const std::string& value)
{
    const std::string protocol = lower(value);
    if (protocol == "ip" || protocol == "ipv4")
        return packet.hasIpv4;
    if (protocol == "ipv6")
        return packet.hasIpv6;
    if (protocol == "http")
        return packet.applicationProtocol == "HTTP";
    if (protocol == "dns")
        return packet.applicationProtocol == "DNS";
    return lower(packet.protocol) == protocol;
}

} // namespace

struct DisplayFilter::Node {
    enum class Type {
        Any,
        Protocol,
        Compare,
        And,
        Or,
        Not,
    };

    Type type = Type::Any;
    std::string field;
    TokenType operation = TokenType::Equal;
    std::string value;
    std::shared_ptr<Node> left;
    std::shared_ptr<Node> right;
};

namespace {

class Parser {
public:
    explicit Parser(std::vector<Token> tokens)
        : tokens_(std::move(tokens))
    {
    }

    std::shared_ptr<DisplayFilter::Node> parse()
    {
        if (current().type == TokenType::End)
            return nullptr;
        auto root = parseOr();
        if (current().type != TokenType::End)
            fail("过滤表达式末尾存在多余内容");
        return root;
    }

private:
    const Token& current() const
    {
        return tokens_[index_];
    }

    bool acceptWord(const char* word)
    {
        if (current().type == TokenType::Word &&
            lower(current().text) == word) {
            ++index_;
            return true;
        }
        return false;
    }

    std::shared_ptr<DisplayFilter::Node> parseOr()
    {
        auto left = parseAnd();
        while (acceptWord("or")) {
            auto right = parseAnd();
            auto node = std::make_shared<DisplayFilter::Node>();
            node->type = DisplayFilter::Node::Type::Or;
            node->left = std::move(left);
            node->right = std::move(right);
            left = std::move(node);
        }
        return left;
    }

    std::shared_ptr<DisplayFilter::Node> parseAnd()
    {
        auto left = parseUnary();
        while (acceptWord("and")) {
            auto right = parseUnary();
            auto node = std::make_shared<DisplayFilter::Node>();
            node->type = DisplayFilter::Node::Type::And;
            node->left = std::move(left);
            node->right = std::move(right);
            left = std::move(node);
        }
        return left;
    }

    std::shared_ptr<DisplayFilter::Node> parseUnary()
    {
        if (acceptWord("not")) {
            auto node = std::make_shared<DisplayFilter::Node>();
            node->type = DisplayFilter::Node::Type::Not;
            node->left = parseUnary();
            return node;
        }
        return parsePrimary();
    }

    std::shared_ptr<DisplayFilter::Node> parsePrimary()
    {
        if (current().type == TokenType::LeftParen) {
            ++index_;
            auto node = parseOr();
            if (current().type != TokenType::RightParen)
                fail("缺少右括号");
            ++index_;
            return node;
        }
        return parseAtomic();
    }

    std::shared_ptr<DisplayFilter::Node> parseAtomic()
    {
        if (current().type != TokenType::Word)
            fail("此处需要一个协议或字段");

        std::string field = lower(current().text);
        ++index_;

        auto node = std::make_shared<DisplayFilter::Node>();
        bool shorthand = false;
        if ((field == "tcp" || field == "udp") &&
            current().type == TokenType::Word &&
            lower(current().text) == "port") {
            ++index_;
            if (current().type != TokenType::Word)
                fail("port 后缺少端口号");
            field += ".port";
            node->type = DisplayFilter::Node::Type::Compare;
            node->field = field;
            node->operation = TokenType::Equal;
            node->value = current().text;
            ++index_;
            shorthand = true;
        } else if (field == "port" && current().type == TokenType::Word) {
            node->type = DisplayFilter::Node::Type::Compare;
            node->field = field;
            node->operation = TokenType::Equal;
            node->value = current().text;
            ++index_;
            shorthand = true;
        } else if (field == "host" && current().type == TokenType::Word) {
            field = "ip.addr";
            node->type = DisplayFilter::Node::Type::Compare;
            node->field = field;
            node->operation = TokenType::Equal;
            node->value = current().text;
            ++index_;
            shorthand = true;
        } else if (
            (field == "src" || field == "dst") &&
            current().type == TokenType::Word &&
            lower(current().text) == "host") {
            field = field == "src" ? "ip.src" : "ip.dst";
            ++index_;
            if (current().type != TokenType::Word)
                fail("host 后缺少地址");
            node->type = DisplayFilter::Node::Type::Compare;
            node->field = field;
            node->operation = TokenType::Equal;
            node->value = current().text;
            ++index_;
            shorthand = true;
        }

        if (!shorthand &&
            current().type != TokenType::Equal &&
            current().type != TokenType::NotEqual &&
            current().type != TokenType::Greater &&
            current().type != TokenType::GreaterEqual &&
            current().type != TokenType::Less &&
            current().type != TokenType::LessEqual) {
            node->type = DisplayFilter::Node::Type::Protocol;
            node->value = field;

            static const std::vector<std::string> supported = {
                "tcp", "udp", "icmp", "arp", "igmp", "ipv4",
                "ip", "ipv6", "icmpv6", "http", "dns",
            };
            if (std::find(supported.begin(), supported.end(), field) ==
                supported.end()) {
                fail("不支持的协议或字段: " + field);
            }
            return node;
        }

        if (!shorthand) {
            node->type = DisplayFilter::Node::Type::Compare;
            node->field = field;
            node->operation = current().type;
            ++index_;

            if (current().type != TokenType::Word)
                fail("比较运算符后缺少值");
            node->value = current().text;
            ++index_;
        }

        static const std::vector<std::string> supportedFields = {
            "ip.addr", "ip.src", "ip.dst", "tcp.port", "udp.port",
            "ipv6.addr", "ipv6.src", "ipv6.dst", "port", "frame.len",
            "protocol", "dns.id", "dns.qry.name",
            "http.request.method", "http.request.uri", "http.host",
            "http.response.code",
        };
        if (std::find(supportedFields.begin(), supportedFields.end(), field) ==
            supportedFields.end()) {
            fail("不支持的比较字段: " + field);
        }

        const bool equalityOnly =
            field == "ip.addr" || field == "ip.src" || field == "ip.dst" ||
            field == "ipv6.addr" || field == "ipv6.src" ||
            field == "ipv6.dst" || field == "port" ||
            field == "tcp.port" || field == "udp.port" ||
            field == "protocol" || field == "dns.qry.name" ||
            field == "http.request.method" ||
            field == "http.request.uri" || field == "http.host";
        if (equalityOnly &&
            node->operation != TokenType::Equal &&
            node->operation != TokenType::NotEqual) {
            fail("该字段只支持 == 或 != 比较");
        }

        const bool numericField =
            field == "frame.len" ||
            field == "dns.id" ||
            field == "http.response.code" ||
            field == "port" ||
            field == "tcp.port" ||
            field == "udp.port";
        if (numericField) {
            long long numeric = 0;
            try {
                std::size_t consumed = 0;
                numeric = std::stoll(node->value, &consumed);
                if (consumed != node->value.size())
                    throw std::invalid_argument("suffix");
            } catch (...) {
                fail("数值字段的值必须是非负整数");
            }
            if (field == "frame.len" && numeric < 0)
                fail("frame.len 不能为负数");
            if ((field == "dns.id" || field == "port" ||
                 field == "tcp.port" || field == "udp.port") &&
                (numeric < 0 || numeric > 65535)) {
                fail("端口或 DNS ID 必须在 0 到 65535 之间");
            }
            if (field == "http.response.code" &&
                (numeric < 0 || numeric > 9999)) {
                fail("HTTP 状态码必须在 0 到 9999 之间");
            }
        }
        return node;
    }

    [[noreturn]] void fail(const std::string& message) const
    {
        throw std::runtime_error(
            message + "（位置 " + std::to_string(current().position) + "）");
    }

    std::vector<Token> tokens_;
    std::size_t index_ = 0;
};

bool evaluate(const DisplayFilter::Node* node, const ParsedPacket& packet)
{
    if (!node)
        return true;

    switch (node->type) {
    case DisplayFilter::Node::Type::Any:
        return true;
    case DisplayFilter::Node::Type::Protocol:
        return isProtocol(packet, node->value);
    case DisplayFilter::Node::Type::And:
        return evaluate(node->left.get(), packet) &&
            evaluate(node->right.get(), packet);
    case DisplayFilter::Node::Type::Or:
        return evaluate(node->left.get(), packet) ||
            evaluate(node->right.get(), packet);
    case DisplayFilter::Node::Type::Not:
        return !evaluate(node->left.get(), packet);
    case DisplayFilter::Node::Type::Compare:
        break;
    }

    if (node->field == "ip.addr") {
        const bool equal =
            packet.sourceIp == node->value ||
            packet.destinationIp == node->value;
        return node->operation == TokenType::NotEqual ? !equal : equal;
    }
    if (node->field == "ipv6.addr") {
        if (!packet.hasIpv6)
            return node->operation == TokenType::NotEqual;
        const bool equal =
            packet.sourceIp == node->value ||
            packet.destinationIp == node->value;
        return node->operation == TokenType::NotEqual ? !equal : equal;
    }
    if (node->field == "ipv6.src") {
        return packet.hasIpv6 &&
            compareText(packet.sourceIp, node->operation, node->value);
    }
    if (node->field == "ipv6.dst") {
        return packet.hasIpv6 &&
            compareText(packet.destinationIp, node->operation, node->value);
    }
    if (node->field == "ip.src")
        return compareText(packet.sourceIp, node->operation, node->value);
    if (node->field == "ip.dst")
        return compareText(packet.destinationIp, node->operation, node->value);
    if (node->field == "port") {
        try {
            const auto port = static_cast<std::uint16_t>(
                std::stoul(node->value));
            const bool equal = hasPort(packet, port);
            return node->operation == TokenType::NotEqual ? !equal : equal;
        } catch (...) {
            return false;
        }
    }
    if (node->field == "tcp.port" || node->field == "udp.port") {
        if (lower(packet.protocol) !=
            (node->field == "tcp.port" ? "tcp" : "udp")) {
            return node->operation == TokenType::NotEqual;
        }
        try {
            const auto port = static_cast<std::uint16_t>(
                std::stoul(node->value));
            const bool equal = hasPort(packet, port);
            return node->operation == TokenType::NotEqual ? !equal : equal;
        } catch (...) {
            return false;
        }
    }
    if (node->field == "frame.len") {
        return compareNumber(
            packet.capturedLength,
            node->operation,
            std::stoll(node->value));
    }
    if (node->field == "dns.id") {
        return compareNumber(
            packet.dnsTransactionId,
            node->operation,
            std::stoll(node->value));
    }
    if (node->field == "dns.qry.name") {
        return compareText(packet.dnsQueryName, node->operation, node->value);
    }
    if (node->field == "http.request.method") {
        return compareText(packet.httpMethod, node->operation, node->value);
    }
    if (node->field == "http.request.uri") {
        return compareText(packet.httpUri, node->operation, node->value);
    }
    if (node->field == "http.host") {
        return compareText(packet.httpHost, node->operation, node->value);
    }
    if (node->field == "http.response.code") {
        return compareNumber(
            packet.httpStatusCode,
            node->operation,
            std::stoll(node->value));
    }
    if (node->field == "protocol")
        return compareText(packet.protocol, node->operation, node->value);
    return false;
}

} // namespace

DisplayFilter::DisplayFilter() = default;
DisplayFilter::~DisplayFilter() = default;

bool DisplayFilter::compile(
    const std::string& expression,
    std::string& error)
{
    error.clear();
    root_.reset();
    try {
        Parser parser(tokenize(expression));
        root_ = parser.parse();
        return true;
    } catch (const std::exception& exception) {
        error = exception.what();
        return false;
    }
}

bool DisplayFilter::matches(const ParsedPacket& packet) const
{
    return evaluate(root_.get(), packet);
}

bool DisplayFilter::empty() const noexcept
{
    return !root_;
}

} // namespace netobserver
