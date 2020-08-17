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
#include <functional>
#include <stdint.h>
#include <set>
#include <linuxpe>
#include <vtil/amd64>
#include <vtil/vtil>
#include "deobfuscator.hpp"
#include "image_desc.hpp"

namespace vmp
{
	using rkey_t = uint64_t;

	struct rkey_value
	{
		// Value of the constant.
		//
		union
		{
			uint64_t u64;
			uint32_t u32;
			uint16_t u16;
			uint8_t u8;

			int64_t i64;
			int32_t i32;
			int16_t i16;
			int8_t i8;
		};

		// Size of this parameter.
		//
		uint32_t size;

		// Some helpers to extend from original size.
		//
		int64_t get_signed()
		{
			switch ( size )
			{
				case 8:		return i64;
				case 4:		return i32;
				case 2:		return i16;
				case 1:		return i8;
				default:	unreachable();
			}
		}

		uint64_t get()
		{
			switch ( size )
			{
				case 8:		return u64;
				case 4:		return u32;
				case 2:		return u16;
				case 1:		return u8;
				default:	unreachable();
			}
		}
	};

	struct rkey_block
	{
		// After the parameter is decrypted it's written into this register
		//
		x86_reg output_register = X86_REG_INVALID;

		// Register of the associated rolling key
		//
		x86_reg rolling_key_register = X86_REG_INVALID;

		// Boundaries of the block within the input stream
		//
		std::pair<int, uint64_t> block_start;
		std::pair<int, uint64_t> block_end;

		// Size of the data
		//
		size_t output_size = ~0ull;

		// Auto-resolved decryption function and the simulation context associated with it
		//
		std::function<std::pair<rkey_value, rkey_t>( void* src, rkey_t k0 )> decrypt;
	};

	struct vm_state
	{
		// The associated image
		//
		image_desc* img = nullptr;

		// RVA of the current handler
		//
		uint32_t current_handler_rva = 0;

		// RVA of the current point in virtual instruction stream
		//
		vtil::vip_t vip = 0;

		// Register that holds the virtual instruction pointer
		//
		x86_reg reg_vip = X86_REG_INVALID;

		// Register that holds the virtual stack pointer
		//
		x86_reg reg_vsp = X86_REG_INVALID;

		// Register that holds the virtual machine rolling key
		//
		x86_reg reg_vrk = X86_REG_INVALID;

		// Direction of the virtual machine instruction stream
		//
		int8_t dir_vip = 0;

		// Rolling key
		//
		rkey_t rolling_key = 0;

		// Unrolls all instructions for the current handler
		//
		instruction_stream unroll()
		{
			return deobfuscate( img, current_handler_rva );
		}

		// Peeks at the virtual instruction stream without forwarding it
		//
		uint8_t* peek_vip( size_t num_bytes = 0 )
		{
			// If inverse stream, we substract the number of bytes being read first
			if ( dir_vip == -1 )
				return img->rva_to_ptr<uint8_t>( vip - num_bytes );

			// Otherwise we use the current RVA
			else if ( dir_vip == +1 )
				return img->rva_to_ptr<uint8_t>( vip );

			// Cannot execute this operation when direction is unknown
			unreachable();
			return nullptr;
		}

		// References the N bytes from the virtual instruction stream and skips them
		//
		uint8_t* read_vip( size_t num_bytes )
		{
			// Peek at the stream
			uint8_t* ret = peek_vip( num_bytes );

			// If invalid, throw
			if ( !ret ) throw std::runtime_error( "Invalid VIP." );

			// Skip the bytes
			vip += num_bytes * dir_vip;

			// Return the output
			return ret;
		}

		// Reads encrypted value from the instruction stream
		//
		rkey_value decrypt_vip( rkey_block& block, size_t num_bytes = -1 )
		{
			// Assert the sanity of the expected i/o size given the decryption block
			if ( num_bytes == -1 )
				num_bytes = block.output_size;
			else
				fassert( num_bytes == block.output_size );

			// Decrypt next 4 bytes in the instruction stream
			auto [value, rolling_key1] = block.decrypt( read_vip( num_bytes ), rolling_key );

			// Update the rolling key
			rolling_key = rolling_key1;

			// Return the value
			return value;
		}

		// Skips to next instruction (when no self-reference point is given) [Serial instructions]
		// Last decrypted parameter should be passed
		//
		void next( rkey_value delta_rva_v )
		{
			// Offset decryption blocks are always 4 bytes, int32_t
			fassert( delta_rva_v.size == 4 );

			// Calculate the new handler RVA based on the decrypted offset and the self reference point
			current_handler_rva += delta_rva_v.i32;
		}

		// Skips to next instruction (when self-reference point is provided) [VMENTER, VMMUTATE, Branching instructions]
		//
		void next( rkey_block& off_dec_block, uint32_t new_vip, uint32_t self_ref_rva )
		{
			// Offset decryption blocks are always 4 bytes, int32_t
			fassert( off_dec_block.output_size == 4 );

			// Set VIP RVA as is
			vip = new_vip;

			// Calculate the new rolling key
			rolling_key = new_vip + img->get_real_image_base();

			// Calculate the new handler RVA based on the decrypted offset and the self reference point
			current_handler_rva = self_ref_rva + decrypt_vip( off_dec_block, 4 ).i32;
		}
	};
};