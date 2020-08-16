// Copyright (C) 2020 Can Boluk
// 
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
//
#pragma once
#include <map>
#include <vector>
#include <optional>
#include <variant>
#include <vtil/amd64>
#include <vtil/vtil>
#include "vm_state.hpp"
#include "deobfuscator.hpp"
#include "../emulator/emulator.hpp"
#include "../emulator/rwx_allocator.hpp"
#include "rkey.hpp"

namespace vmp
{
	// Reduces the given virtualized instruction handler to the base 
	// (AKA Deobfuscation + I/O based Register tracing)
	//
	void reduce_chunk( vm_state* vstate, instruction_stream& is, const std::vector<std::pair<rkey_block*, rkey_value>>& parameters, bool has_next = true );

	// Deduces the virtual register key from the given instruction stream
	//
	void update_vrk( vm_state* state, const instruction_stream& is );

	// Deduces the virtual instruction stream direction from the given instruction stream
	//
	void update_vip_direction( vm_state* state, const instruction_stream& is );

	// Finds the self-reference point from the given instruction stream if relevant
	//
	std::optional<uint64_t> find_self_ref( vm_state* state, const instruction_stream& is, int index = 0 );

	// Parses VMENTER subroutine and extracts the vm information, entry point of the
	// virtualized routine, rolling key 0 value, and describes the push order of registers.
	// - Pushing reloc at last is left to the caller.
	//
	std::pair<std::vector<vtil::operand>, vtil::vip_t> parse_vmenter( vm_state* vstate, uint32_t rva_ep );

	// Parses the VMEXIT subroutine and extracts the order registers are pop'd from the stack.
	//
	std::vector<vtil::operand> parse_vmexit( vm_state* vstate, const instruction_stream& is );

	// Parses swapping vm of context/registers, returns newly extracted rkey blocks
	//
	std::vector<rkey_block> parse_vmswap( vm_state* vstate, instruction_stream& is, instruction_stream& prefix_out );
};