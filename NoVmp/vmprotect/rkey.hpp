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
#include "../emulator/emulator.hpp"
#include "../emulator/rwx_allocator.hpp"
#include "vm_state.hpp"
#include "deobfuscator.hpp"

namespace vmp
{
	// Extracts the next rolling key decryption block  within the given instruction stream
	// - On failure returns -1 as the iterator index
	static std::pair<int, rkey_block> extract_next_rkey_block( vm_state* state,
															   const instruction_stream& is,
															   int index = 0 )
	{
		rkey_block out;

		// Extend the register we received originally (EAX->RAX and so on)
		//
		out.rolling_key_register = vtil::amd64::registers.extend( state->reg_vrk );

		// Define our filters
		//
		auto prologue_filter = [ & ] ( const vtil::amd64::instruction& ins )
		{
			// Type #1
			// [ xor rbp, r8 ]
			//
			return ins.is( X86_INS_XOR, { X86_OP_REG, X86_OP_REG } ) &&
				   vtil::amd64::registers.extend( ins.operands[ 1 ].reg ) == out.rolling_key_register;
		};
		auto epilogue_filter = [ & ] ( const vtil::amd64::instruction& ins )
		{
			// Type #1
			// [ xor r8, rbp ]
			//
			if ( ins.is( X86_INS_XOR, { X86_OP_REG, X86_OP_REG } ) )
			{
				return
					vtil::amd64::registers.extend( ins.operands[ 0 ].reg ) == out.rolling_key_register &&
					ins.operands[ 1 ].reg == out.output_register;
			}
			// Type #2
			// [ push r8					]
			// [ xor  dword ptr [rsp], edi	]
			// [ pop  r8					]
			//
			else if ( ins.is( X86_INS_XOR, { X86_OP_MEM, X86_OP_REG } ) )
			{
				return
					ins.operands[ 0 ].mem.base == X86_REG_RSP &&
					ins.operands[ 0 ].mem.disp == 0 &&
					ins.operands[ 0 ].mem.index == X86_REG_INVALID &&
					ins.operands[ 0 ].mem.scale == 1 &&
					ins.operands[ 1 ].reg == out.output_register;
			}
			return false;
		};

		// Find the next prologue, report failure if we fail to do so
		//
		int prologue_index = is.next( prologue_filter, index );
		if ( prologue_index == -1 ) return { -1, {} };

		// Fill out the block details
		//
		out.block_start = { prologue_index, is[ prologue_index ].address };
		out.output_size = is[ prologue_index ].operands[ 0 ].size;
		out.output_register = is[ prologue_index ].operands[ 0 ].reg;

		// Find the next epilogue, increment the iterator and try the next prologue if we fail to do so
		//
		int epilogue_index = is.next( epilogue_filter, prologue_index + 1 );
		if ( epilogue_index == -1 ) return extract_next_rkey_block( state, is, prologue_index + 1 );
		out.block_end = { epilogue_index, is[ epilogue_index ].address };

		// Trace register usage accross the block
		//
		auto [block_stream, block_dependencies] = is.trace(
			out.output_register,
			epilogue_index - 1,
			prologue_index + 1
		);

		// If the decryption block we discovered has dependencies, then it is not valid, try the next prologue
		//
		if ( !block_dependencies.empty() ) return extract_next_rkey_block( state, is, prologue_index + 1 );

		// Write the emulation information and return the block
		//
		out.decrypt = [ =, block_stream = block_stream ] ( void* src, rkey_t key ) -> std::pair<rkey_value, rkey_t>
		{
			rkey_value value;
			value.u64 = 0;
			value.size = out.output_size;
			memcpy( &value.u64, src, value.size );

			// Emulate prologue manually
			//
			switch ( value.size )
			{
				case 1: value.u8 ^= key; break;
				case 2: value.u16 ^= key; break;
				case 4: value.u32 ^= key; break;
				case 8: value.u64 ^= key; break;
			}

			// Emulate the block entirely
			//
			std::vector raw_stream = block_stream.to_raw();
			std::vector<uint8_t, mem::rwx_allocator<uint8_t>> exec_stream = { raw_stream.begin(), raw_stream.end() };
			exec_stream.push_back( 0xC3 );

			emulator emu = {};
			emu.set( state->reg_vrk, key );
			emu.set( out.output_register, value.u64 );
			emu.invoke( exec_stream.data() );
			value.u64 = emu.get( out.output_register );

			// Emulate epilogue manually
			//
			switch ( value.size )
			{
				case 1: key ^= value.u8; break;
				case 2: key ^= value.u16; break;
				case 4: key ^= value.u32; break;
				case 8: key ^= value.u64; break;
			}
			return { value, key };
		};
		return { epilogue_index + 1, out };
	}

	// Extracts all of the rolling key decryption blocks within the given instruction stream
	//
	static std::vector<rkey_block> extract_rkey_blocks( vm_state* vstate,
														const instruction_stream& is )
	{
		// Iterate entire instruction stream:
		//
		std::vector<rkey_block> out;
		for ( int iterator = 0; iterator != -1 && iterator < is.stream.size(); )
		{
			// Try to extract the next block
			//
			auto [it_next, block] = extract_next_rkey_block( vstate, is, iterator );

			// Break the loop if failed to find the block
			//
			if ( it_next == -1 ) break;

			// Else push on the output list and continue iteration
			//
			out.push_back( block );
			iterator = it_next;
		}
		return out;
	}
};