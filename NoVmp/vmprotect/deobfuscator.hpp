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
#include <map>
#include <algorithm>
#include <linuxpe>
#include <vtil/amd64>
#include "image_desc.hpp"

namespace vmp
{
	using namespace vtil::logger;

	using fn_instruction_filter = std::function<bool( const vtil::amd64::instruction& )>;

	struct instruction_stream
	{
		std::vector<std::pair<int, vtil::amd64::instruction>> stream = {};
		instruction_stream() {};

		// std::vector wrappers, stripping the index
		//
		auto& operator[]( size_t n ) const { return stream[ n ].second; }
		size_t size() const { return stream.size(); }

		// Dumps all of the instructions in the stream to a byte array
		//
		std::vector<uint8_t> to_raw()
		{
			// Normalize the stream
			//
			normalize();

			// Linearly decode into a byte array and return
			//
			std::vector<uint8_t> raw_stream;
			for ( auto& p : stream )
				raw_stream.insert( raw_stream.end(), p.second.bytes.begin(), p.second.bytes.end() );
			return raw_stream;
		}
		std::vector<uint8_t> to_raw() const
		{
			return instruction_stream( *this ).to_raw();
		}

		// Merges two instruction streams together
		//
		instruction_stream operator+( const instruction_stream& i2 ) const
		{
			// Merge both instruction streams, remove duplicates.
			//
			instruction_stream out;
			std::map<int, bool> pushed;
			for ( auto& is : { stream, i2.stream } )
			{
				for ( auto& pair : is )
				{
					if ( !pushed[ pair.first ] )
					{
						pushed[ pair.first ] = true;
						out.stream.push_back( pair );
					}
				}
			}

			// Return after sorting by instruction index into the stream
			//
			return out.normalize();
		}

		// Normalizes the instruction stream
		//
		instruction_stream& normalize()
		{
			// Sort according to the original order
			std::sort( stream.begin(), stream.end(), [ ] ( auto& p1, auto& p2 )
			{
				return p1.first <= p2.first;
			} );
			return *this;
		}

		// Traces the register's usage history throughout the instruction stream
		//
		template<bool dump = false>
		std::pair<instruction_stream, std::vector<x86_reg>> trace( x86_reg ireg, int end, int begin = 0 ) const
		{
			std::map<x86_reg, bool> dependencies;
			instruction_stream substream;

			// Trace the instruction upto the beginning of the control flow
			//
			for ( int i = end; i >= begin; i-- )
			{
				auto& ins = stream[ i ].second;

				// Check whether the register is read / written to by this instruction
				//
				uint64_t read = false;
				uint64_t write = false;
				std::vector<x86_reg> access_list;

				for ( int j = 0; j < ins.operands.size(); j++ )
				{
					if ( ins.operands[ j ].type == X86_OP_REG )
					{
						auto reg = ins.operands[ j ].reg;
						if ( vtil::amd64::registers.extend( reg ) != vtil::amd64::registers.extend( ireg ) )
						{
							access_list.push_back( reg );
							continue;
						}
						read |= ins.operands[ j ].access & CS_AC_READ;
						write |= ins.operands[ j ].access & CS_AC_WRITE;
					}
					else if ( ins.operands[ j ].type == X86_OP_MEM )
					{
						for ( auto reg : {
								ins.operands[ j ].mem.base,
								ins.operands[ j ].mem.index } )
						{
							if ( vtil::amd64::registers.extend( reg ) != vtil::amd64::registers.extend( ireg ) )
							{
								access_list.push_back( reg );
								continue;
							}
							read |= ins.operands[ j ].access & CS_AC_READ;
							// Can't read as its writing to memory if WRITE is marked
						}
					}
				}

				// If this instruction writes to this register, log it
				//
				if ( write )
				{
					for ( auto reg : access_list ) dependencies[ reg ] = true;
					substream.stream.push_back( stream[ i ] );

					if constexpr ( dump )
					{
						log<CON_RED>( " %c%c   [[ %p: %s\t%s\n",
										  read ? 'R' : ' ',
										  write ? 'W' : ' ',
										  ins.address, ins.mnemonic.data(), ins.operand_string.data() );
					}
				}

				// If the instruction writes to this register WITHOUT reading it
				// no need to trace any further, return.
				if ( write && !read ) break;
			}

			// Convert to std::vector<>
			std::vector<x86_reg> dependencies_r;
			for ( auto& p : dependencies )
				if ( p.first != X86_REG_INVALID )
					dependencies_r.push_back( p.first );

			// Print dependencies
			if constexpr ( dump )
			{
				log<CON_PRP>( " Depends on: [ " );
				for ( auto reg : dependencies_r )
					log<CON_PRP>( "%s ", vtil::amd64::name( reg ) );
				log<CON_PRP>( "]\n" );
			}

			return { substream.normalize(), dependencies_r };
		}

		// Finds the next/prev matching instruction
		//
		int next( uint32_t instruction_id,
				  const std::vector<x86_op_type>& operands,
				  int from = 0 ) const
		{
			for ( int i = from; i < stream.size(); i++ )
				if ( stream[ i ].second.is( instruction_id, operands ) ) return i;
			return -1;
		}

		int next( const fn_instruction_filter& filter,
				  int from = 0 ) const
		{
			for ( int i = from; i < stream.size(); i++ )
				if ( filter( stream[ i ].second ) ) return i;
			return -1;
		}

		int next( uint32_t instruction_id,
				  const std::vector<x86_op_type>& operands,
				  const fn_instruction_filter& filter,
				  int from = 0 ) const
		{
			for ( int i = from; i < stream.size(); i++ )
				if ( stream[ i ].second.is( instruction_id, operands ) && filter( stream[ i ].second ) ) return i;
			return -1;
		}

		int prev( uint32_t instruction_id, const std::vector<x86_op_type>& operands, int from = -1 ) const
		{
			if ( from == -1 ) from = stream.size() - 1;

			for ( int i = from; i >= 0; i-- )
				if ( stream[ i ].second.is( instruction_id, operands ) ) return i;
			return -1;
		}

		int prev( const fn_instruction_filter& filter,
				  int from = -1 ) const
		{
			if ( from == -1 ) from = stream.size() - 1;

			for ( int i = from; i >= 0; i-- )
				if ( filter( stream[ i ].second ) ) return i;
			return -1;
		}

		int prev( uint32_t instruction_id,
				  const std::vector<x86_op_type>& operands,
				  const fn_instruction_filter& filter,
				  int from = -1 ) const
		{
			if ( from == -1 ) from = stream.size() - 1;

			for ( int i = from; i >= 0; i-- )
				if ( stream[ i ].second.is( instruction_id, operands ) && filter( stream[ i ].second ) ) return i;
			return -1;
		}

		// Deletes first N instructions
		//
		void erase( int n )
		{
			while ( n-- ) stream.erase( stream.begin() );
		}

		// Dumps the given instruction sequence
		//
		std::string to_string() const
		{
			std::string out;
			for ( auto& p : stream )
				out += p.second.to_string() + "\n";
			return out;
		}
	};

	// Unrolls the entire instruction stream as far as possiblibly predictable statically
	//
	static instruction_stream deobfuscate( image_desc* img, uint32_t rva_rip )
	{
		static std::mutex cache_mutex;
		static std::map<uint32_t, instruction_stream> cache;

		std::lock_guard g( cache_mutex );
		auto& output = cache[ rva_rip ];
		if ( output.stream.size() ) return output;

		// For each instruction at the given VA:
		//
		int instruction_idx = 0;
		while ( true )
		{

			// Disassemble the instruction
			//
			std::vector i1 = vtil::amd64::disasm( img->rva_to_ptr( rva_rip ), rva_rip );
			fassert( !i1.empty() );
			vtil::amd64::instruction& instruction = i1[ 0 ];
			output.stream.push_back( { ++instruction_idx, instruction } );

			// Check if control flow deviates
			//
			if ( instruction.is( X86_INS_CALL, { X86_OP_IMM } ) )
				rva_rip = instruction.operands[ 0 ].imm;
			else if ( instruction.is( X86_INS_JMP, { X86_OP_IMM } ) )
				rva_rip = instruction.operands[ 0 ].imm, output.stream.pop_back();
			else if ( instruction.id == X86_INS_JMP || instruction.id == X86_INS_RET )
				break;
			else
				rva_rip += instruction.bytes.size();
		}
		if ( output.stream.empty() ) vtil::logger::error( "Failed to unroll control-flow." );
		return output;
	}
};