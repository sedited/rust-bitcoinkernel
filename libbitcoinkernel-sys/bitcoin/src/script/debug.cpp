// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/debug.h>

#include <mutex>
#include <span>
#include <vector>

static std::mutex g_script_debug_mutex;
static DebugScriptCallback g_script_debug_callback{nullptr};

void DebugScript(std::span<const std::vector<unsigned char>> stack, const CScript& script, uint32_t opcode_pos, std::span<const std::vector<unsigned char>> altstack, bool fExec)
{
    std::lock_guard<std::mutex> lock(g_script_debug_mutex);
    if (g_script_debug_callback) g_script_debug_callback(stack, script, opcode_pos, altstack, fExec);
}

void RegisterDebugScriptCallback(DebugScriptCallback func)
{
    std::lock_guard<std::mutex> lock(g_script_debug_mutex);
    g_script_debug_callback = func;
}
