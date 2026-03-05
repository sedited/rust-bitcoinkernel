// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SCRIPT_DEBUG_H
#define BITCOIN_SCRIPT_DEBUG_H

#include <script/script.h>

#include <functional>
#include <span>
#include <vector>

using DebugScriptCallback = std::function<void(std::span<const std::vector<unsigned char>>, const CScript&, uint32_t, std::span<const std::vector<unsigned char>>, bool, uint8_t, int, uint8_t)>;

void DebugScript(std::span<const std::vector<unsigned char>> stack, const CScript& script, uint32_t opcode_pos, std::span<const std::vector<unsigned char>> altstack, bool fExec, uint8_t opcode, int nOpCount, uint8_t sigversion);

void RegisterDebugScriptCallback(DebugScriptCallback func);

#ifdef ENABLE_SCRIPT_DEBUG
#define DEBUG_SCRIPT(stack, script, opcode_pos, altstack, fExec, opcode, nOpCount, sigversion) \
    DebugScript(stack, script, opcode_pos, altstack, fExec, opcode, nOpCount, sigversion);
#else
#define DEBUG_SCRIPT(stack, script, opcode_pos, altstack, fExec, opcode, nOpCount, sigversion)
#endif // ENABLE_SCRIPT_DEBUG

#endif // BITCOIN_SCRIPT_DEBUG_H
