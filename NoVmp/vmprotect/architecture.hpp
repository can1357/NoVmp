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
#include <set>
#include <optional>
#include "vm_state.hpp"
#include "deobfuscator.hpp"

namespace vmp::arch
{
	using namespace vtil::logger;

	using opcode_id = std::string;
	static constexpr char PANY = 0xAA;

	// In order of common-ness
	static const std::vector<char> possible_variants = { 8, 4, 2, 1 };
	static char abbrv_param_size( char size )
	{
		switch ( size )
		{
			case 8:		return 'Q';
			case 4:		return 'D';
			case 2:		return 'W';
			case 1:		return 'B';
		}
		unreachable();
	}
	
	static char resolve_abbrv_param_size( char abbrv )
	{
		switch ( abbrv )
		{
			case 'Q':	return 8;
			case 'D':	return 4;
			case 'W':	return 2;
			case 'B':	return 1;
		}
		unreachable();
	}

	// Instruction description
	//
	constexpr int32_t unknown_delta = 0x10000000;
	struct instruction
	{
		// Describe the operation this instruction does
		//
		opcode_id op;
		instruction_stream stream = {};

		// Describe its parameters
		//
		std::vector<uint64_t> parameters = {};
		std::vector<char> parameter_sizes = {};

		// Summarize stack operations
		//
		int32_t stack_delta = 0;
		std::set<int32_t> stack_reads = {};
		std::set<int32_t> stack_writes = {};

		// Summarize context operations
		//
		std::set<uint8_t> context_reads = {};
		std::set<uint8_t> context_writes = {};
	};

	instruction classify( vm_state* vstate, const instruction_stream& is );
};