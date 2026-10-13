// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/interpreter.h>
#include <script/script.h>
#include <script/script_error.h>
#include <script/valtype_stack.h>
#include <script/varops.h>
#include <test/data/tapscript_v2_restored_ops.json.h>
#include <test/data/tapscript_v2_varops.json.h>
#include <test/util/json.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <iostream>
#include <optional>
#include <ranges>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include <boost/test/unit_test.hpp>

#include <univalue.h>

BOOST_FIXTURE_TEST_SUITE(tapscript_v2_json_tests, BasicTestingSetup)

static void PrintStackElement(std::string_view label, const std::vector<unsigned char>& element)
{
    static constexpr size_t MAX_PRINTED_BYTES{32};
    const size_t printed_bytes{std::min(element.size(), MAX_PRINTED_BYTES)};
    std::cerr << label << HexStr(std::span{element}.first(printed_bytes));
    if (printed_bytes < element.size()) {
        std::cerr << "... (" << element.size() << " bytes total)";
    }
}

static void PrintStackComparison(
    const std::string& test_name,
    const std::vector<std::vector<unsigned char>>& actual_stack,
    const std::vector<std::vector<unsigned char>>& expected_stack)
{
    std::cerr << "Test '" << test_name << "' failed final stack check. Final stack:\n";
    for (size_t i = 0; i < std::max(actual_stack.size(), expected_stack.size()); ++i) {
        std::cerr << "  [" << i << "] ";
        if (i < expected_stack.size()) {
            PrintStackElement("Expected: ", expected_stack[i]);
        } else {
            std::cerr << "Expected: No element";
        }

        std::cerr << ", ";
        if (i < actual_stack.size()) {
            PrintStackElement("Actual: ", actual_stack[i]);
        } else {
            std::cerr << "Actual: No element";
        }
        std::cerr << '\n';
    }
}

static std::vector<unsigned char> ParseExpandedHex(std::string_view input)
{
    if (input.starts_with("0x") || input.starts_with("0X")) input.remove_prefix(2);

    std::vector<unsigned char> result;
    while (!input.empty()) {
        const size_t open_brace{input.find('{')};
        const std::string_view literal{input.substr(0, open_brace)};
        if (!literal.empty()) {
            if (!IsHex(literal)) throw std::invalid_argument("Invalid hex string");
            const std::vector<unsigned char> bytes{::ParseHex(literal)};
            result.insert(result.end(), bytes.begin(), bytes.end());
        }

        if (open_brace == std::string_view::npos) break;
        const size_t close_brace{input.find('}', open_brace + 1)};
        if (close_brace == std::string_view::npos) throw std::invalid_argument("Unclosed brace in hex string");
        if (result.empty()) throw std::invalid_argument("No previous byte to repeat");

        const std::optional<uint64_t> count{ToIntegral<uint64_t>(input.substr(open_brace + 1, close_brace - open_brace - 1))};
        if (!count || *count == 0) throw std::invalid_argument("Invalid repeat count");
        if (*count - 1 > result.max_size() - result.size()) throw std::length_error("Expanded hex string too large");
        const unsigned char repeated_byte{result.back()};
        result.insert(result.end(), static_cast<size_t>(*count - 1), repeated_byte);
        input.remove_prefix(close_brace + 1);
    }
    return result;
}

static std::optional<opcodetype> FindOpcode(std::string_view name)
{
    for (unsigned int code{0}; code <= 0xff; ++code) {
        const opcodetype opcode{static_cast<opcodetype>(code)};
        const std::string canonical{GetOpName(opcode)};
        const std::string_view canonical_view{canonical};
        if (canonical_view == "OP_UNKNOWN") continue;
        if (canonical_view == name || (canonical_view.starts_with("OP_") && canonical_view.substr(3) == name)) return opcode;
    }
    return std::nullopt;
}

static std::vector<unsigned char> ParseHexOrOpcode(const std::string& input)
{
    if (const std::optional<opcodetype> opcode{FindOpcode(input)}) return {static_cast<unsigned char>(*opcode)};
    return ParseExpandedHex(input);
}

static std::vector<std::vector<unsigned char>> ParseStack(const UniValue& values)
{
    std::vector<std::vector<unsigned char>> stack;
    stack.reserve(values.size());
    for (const UniValue& value : values.getValues()) {
        stack.push_back(ParseExpandedHex(value.get_str()));
    }
    return stack;
}

static constexpr std::array<std::string_view, 6> ALLOWED_SUCCESS_TEST_FIELDS{
    "description",
    "final stack",
    "initial stack",
    "name",
    "opcodes",
    "varops cost",
};

static void CheckSuccessTestFields(const UniValue& test)
{
    for (const std::string& key : test.getKeys()) {
        if (std::ranges::find(ALLOWED_SUCCESS_TEST_FIELDS, key) == ALLOWED_SUCCESS_TEST_FIELDS.end()) {
            throw std::invalid_argument("Unknown success-vector field: " + key);
        }
    }
}

static void RunJsonSuccessTests(const UniValue& tests, const std::string& suite_name)
{
    for (const UniValue& category : tests.getValues()) {
        const std::string category_name{category["category"].get_str()};
        for (const UniValue& test : category["tests"].getValues()) {
            const std::string test_name{test["name"].get_str()};
            const std::string full_test_name{suite_name + "::" + test_name};

            BOOST_TEST_CONTEXT("category " << category_name << ", test " << full_test_name) {
                try {
                    CheckSuccessTestFields(test);

                    if (!test.exists("opcodes") || !test.exists("final stack") || !test.exists("varops cost")) {
                        throw std::invalid_argument("Missing required success-vector field");
                    }

                    CScript script;
                    for (const UniValue& opcode_input : test["opcodes"].getValues()) {
                        const std::vector<unsigned char> parsed{ParseHexOrOpcode(opcode_input.get_str())};
                        script.insert(script.end(), parsed.begin(), parsed.end());
                    }

                    const std::vector<std::vector<unsigned char>> initial_stack{
                        test.exists("initial stack") ? ParseStack(test["initial stack"])
                                                     : std::vector<std::vector<unsigned char>>{}};
                    const std::vector<std::vector<unsigned char>> expected_stack{ParseStack(test["final stack"])};
                    const uint64_t expected_cost{test["varops cost"].getInt<uint64_t>()};

                    ScriptExecutionData execdata;
                    ScriptError error{SCRIPT_ERR_UNKNOWN_ERROR};
                    BaseSignatureChecker checker;
                    constexpr uint64_t budget{250'000'000};
                    varops::Budget varops_budget{budget};
                    ValtypeStack stack{initial_stack};

                    const bool success{EvalTapscriptV2(stack, script, 0, checker, execdata, varops_budget, &error)};
                    BOOST_CHECK_MESSAGE(success,
                                        "Test '" << full_test_name << "' failed with " << ScriptErrorString(error));
                    if (success) {
                        BOOST_CHECK_EQUAL(error, SCRIPT_ERR_OK);
                        if (stack.GetStack() != expected_stack) {
                            PrintStackComparison(full_test_name, stack.GetStack(), expected_stack);
                        }
                        BOOST_CHECK_MESSAGE(stack.GetStack() == expected_stack,
                                            "Test '" << full_test_name << "' failed final stack check");
                        const uint64_t consumed{budget - *varops_budget.Remaining()};
                        BOOST_CHECK_MESSAGE(consumed == expected_cost,
                                            "Test '" << full_test_name << "' consumed " << consumed
                                                     << " varops units, expected " << expected_cost);
                    }
                } catch (const std::exception& e) {
                    std::cerr << "Exception in test '" << full_test_name << "': " << e.what() << std::endl;
                    throw;
                }
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(tapscript_v2_varops_json_tests)
{
    RunJsonSuccessTests(read_json(json_tests::tapscript_v2_varops), "tapscript_v2_varops");
}

BOOST_AUTO_TEST_CASE(tapscript_v2_restored_ops_json_tests)
{
    RunJsonSuccessTests(read_json(json_tests::tapscript_v2_restored_ops), "tapscript_v2_restored_ops");
}

BOOST_AUTO_TEST_SUITE_END()
