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
#include <vtil/amd64>
#include <vtil/arch>
#include <vtil/compiler>
#include <vtil/io>
#include <tuple>
#include <string>

#define COMPILER_VERBOSE_GENERATION 1

// This implements a very very broken "demo" compiler made for some tests,
// this will be rewritten using Intel XED and proper register allocation
// whenever I have time but I'm releasing it anyways along with NoVmp.
//
namespace vtil
{
	// Maximum amount of instruction we add to the block trying to free registers.
	//
	static constexpr float maximum_block_expansion = 1.20f; // +20%
	
	// Magic VIP values used by the compiler to determine self-inserted instructions.
	//
	static constexpr vip_t mvip_virtualizer =       0xBABE00000100CAFE;
	static constexpr vip_t mvip_arch_normalizer =   0xBABE00000200CAFE;
	static constexpr vip_t mvip_tmp_hint =          0xBABE00000300CAFE;
	static constexpr vip_t mvip_return_hint =       0xBABE00000400CAFE;
	static constexpr vip_t mvip_moveout_hint =      0xBABE00000500CAFE;

	static bool is_i32( int64_t i64 ) { return math::sign_extend( i64, 32 ) == i64; }
	static bool is_u32( uint64_t u64 ) { return math::zero_extend( u64, 32 ) == u64; }

	// Holds current routine information.
	//
	struct routine_state
	{
		uint32_t rva;

		// State of the stack frame.
		//
		size_t next_frame_offset = 0;
		register_desc frame_register = {};
		std::map<register_desc, size_t> frame_mapping;
		
		// Produced MASM code:
		//
		std::string document = "routine_base:";
		std::set<vip_t> compiled;

		template<typename... params>
		void assemble( const char* fmt, params&&... ps )
		{
			bool validate = fmt[ 0 ] != '!';
			if ( !validate ) fmt++;

			std::string instruction = format::str( fmt, std::forward<params>( ps )... ) + "\n";
			document += "\t" + instruction;
#if COMPILER_VERBOSE_GENERATION
			logger::log<logger::CON_YLW>( "%s", "\t" + instruction );
#endif
			if ( validate && amd64::assemble( instruction, rva ).empty() )
				logger::error( "Failed assembling: %s\n", instruction );
		}
		std::string ref_label( vip_t vip )
		{
			return format::str( "block_%llx", vip );
		}
		void add_label( vip_t vip )
		{
			document += ref_label( vip ) + ":\n";
		}
		std::string ref_rva( uint64_t rva_other, bool rip_rel_def = true )
		{
			if ( rip_rel_def )
				return format::hex( rva_other );
			else
				return format::str( "rip + routine_base - 0x%x + 0x%p", rva, rva_other );
		}

		std::string deref( const il_iterator& it )
		{
			auto [base, offset] = it->memory_location();

			fassert( is_i32( offset ) );
			fassert( base.bit_count == 64 );

			std::string address;
			if ( base.is_physical() )
			{
				address = format::str( "[%s %s]", base.is_stack_pointer() ? "rsp" : amd64::name( base.combined_id ), format::offset(
					base.is_stack_pointer() ? offset - it->sp_offset : offset
				) );
			}
			else
			{
				fassert( base.is_image_base() );
				address = format::str( "[%s]", ref_rva( offset, false ) );
			}

			switch ( it->access_size() )
			{
				case 8:	 return "byte ptr " + address;
				case 16: return "word ptr " + address;
				case 32: return "dword ptr " + address;
				case 64: return "qword ptr " + address;
				default: unreachable();
			}
		}

		std::string ref_lhs( const operand& op )
		{
			fassert( !op.is_immediate() );

			auto& reg = op.reg();
			fassert( !reg.is_special() );
			fassert( reg.is_physical() );

			// TODO: Remove me, this is a horrible hack.
			//
			if ( reg.bit_count == 1 )
			{
				fassert( reg.bit_offset == 0 );
				return amd64::name( amd64::registers.remap( reg.combined_id, 0, 1 ) );
			}

			fassert( !( reg.bit_offset & 7 ) && !( reg.bit_count & 7 ) );
			auto mapped = amd64::registers.remap( reg.combined_id, reg.bit_offset / 8, reg.bit_count / 8 );
			return amd64::name( mapped );
		}
		std::string ref_rhs( const operand& op )
		{
			if ( op.is_immediate() )
				return format::hex( op.imm().i64 );

			// TODO:
			if ( op.reg().is_undefined() )
				return "0";
			return ref_lhs( op );
		}
	};

	static std::optional<register_desc> allocate_register( const il_iterator& it, routine_state* state, const std::function<bool( const register_desc& )>& filter = {} )
	{
		int64_t idx = 0;
		for ( auto rit = amd64::preserve_all_convention.param_registers.begin();
			  rit != amd64::preserve_all_convention.param_registers.end();
			  rit++, idx++ )
		{
			// Skip if special.
			//
			if ( rit->is_flags() || rit->is_stack_pointer() || rit->overlaps( state->frame_register ) )
				continue;

			// Skip if filter condition not met.
			//
			if ( filter && !filter( *rit ) )
				continue;

			// If value is not used:
			//
			symbolic::variable var = { it, *rit };
			if ( !var.accessed_by( it ) && !optimizer::aux::is_used( var, true, nullptr ) )
				return *rit;
		}
		return std::nullopt;
	}

	// Lazy register allocator.
	//
	struct lazy_register_allocator : optimizer::pass_interface<>
	{
		std::shared_mutex mtx;
		routine_state* state;
		lazy_register_allocator( routine_state* state ) : state( state ) {}

		size_t pass( basic_block* blk, bool xblock = false )
		{
			size_t counter = 0;
			std::map<size_t, std::pair<size_t, il_iterator>> local_use_map;
			for ( auto it = blk->begin(); !it.is_end(); it++ )
			{
				// Skip if volatile and not imm-kicked register.
				//
				if ( it->is_volatile() && it->vip != mvip_moveout_hint )
					continue;

				// For each operand written:
				//
				for ( auto [op, type] : it->enum_operands() )
				{
					// Skip if not temporary.
					//
					if ( !op.is_register() || !op.reg().is_local() )
						continue;

					// If not write, just increment counter and skip.
					//
					if ( type != operand_type::write )
					{
						auto& [counter, first_user] = local_use_map[ op.reg().combined_id ];
						counter++;
						fassert( first_user.is_valid() );
						continue;
					}

					// Increment use counter and write as the parent if first access.
					//
					auto& [counter, first_user] = local_use_map[ op.reg().combined_id ];
					if ( counter++ == 0 )
						first_user = it;
				}
			}

			// Convert into a list ordered by usage.
			//
			std::vector<std::tuple<size_t, size_t, il_iterator>> local_reg_list;
			for ( auto& [k, v] : local_use_map )
				local_reg_list.emplace_back( k, v.first, v.second );
			std::sort( local_reg_list.begin(), local_reg_list.end(), [ ] ( auto& a, auto& b ) { return std::get<1>( a ) > std::get<1>( b ); } );

			// For each entry:
			//
			std::vector<std::pair<il_iterator, register_desc>> pins;
			for ( auto& [combined_id, use_count, it] : local_reg_list )
			{
				// Iterate every register.
				//
				mtx.lock_shared();
				std::optional<register_desc> allocated_register = allocate_register( it, state, [ & ] ( const register_desc& reg )
				{
					return optimizer::aux::is_alive( { it, reg }, blk->end(), xblock, nullptr );
				} );
				mtx.unlock_shared();

				// If a register was allocated:
				//
				if ( allocated_register )
				{
					std::unique_lock lock{ mtx };

					// Eliminate partial dependency.
					//
					pins.emplace_back( it, *allocated_register );
					auto ins = +blk->insert( it, { &ins::vpinw, { *allocated_register } } );
					ins->vip = mvip_tmp_hint;

					// Rename each use.
					//
					for ( auto i = it; !i.is_end(); i++ )
					{
						for ( auto& op : ( +i )->operands )
						{
							if ( op.is_register() && op.reg().is_local() && op.reg().combined_id == combined_id )
							{
								op.reg().flags = allocated_register->flags;
								op.reg().combined_id = allocated_register->combined_id;
							}
						}
					}
				}
			}
			return counter;
		}
	};
	struct arch_normalization_pass : optimizer::pass_interface<true>
	{
		std::shared_mutex mtx;
		size_t pass( basic_block* blk, bool xblock = false )
		{
			for ( auto it = blk->begin(); !it.is_end(); it++ )
			{
				// Skip if inserted by us.
				//
				if ( it->vip == mvip_arch_normalizer ||
					 it->vip == mvip_moveout_hint )
					continue;

				// Skip if volatile or has no operands.
				//
				if ( it->is_volatile() )
					continue;

				// TODO: &&base:
				//

				// Begin label.
				//
				blk->label_begin( mvip_arch_normalizer );
				const auto trash_register = [ & ] ( x86_reg res )
				{
					// Make sure instruction does not reference this register.
					// TODO: Handle
					fassert( !symbolic::variable{ it, operand{ res }.reg() }.written_by( it ) );

					// Insert a VPINW.
					//
					auto hint_trash = blk->insert( std::next( it ), { &ins::vpinw, { operand{ res } } } );
					( +hint_trash )->vip = mvip_tmp_hint;
				};
				const auto force_operand = [ & ] ( int idx, x86_reg res )
				{
					// If instruction is already using this register, make it volatile and return.
					//
					operand& op = ( +it )->operands[ idx ];
					if ( op.is_register() && op.reg().is_physical() && op.reg().combined_id == res )
					{
						( +it )->make_volatile();
						return;
					}

					// Make sure instruction does not reference this register.
					// TODO: Handle
					fassert( !symbolic::variable{ it, operand{res}.reg() }.accessed_by( it ) );

					// Allocate a temporary to hold the previous value of the register.
					//
					auto tmp = blk->tmp( op.bit_count() );
					register_desc new_op = { register_physical, ( uint64_t ) res, op.bit_count() };

					blk->insert( it, { &ins::mov, { tmp, new_op } } );              // #0: tmp = op
					blk->insert( it, { &ins::mov, { new_op, op } } );               // #1: op = <old>
					blk->insert( std::next( it ), { &ins::mov, { new_op, tmp } } ); // #3: op = tmp
					if( op.is_register() )
						blk->insert( std::next( it ), { &ins::mov, { op, new_op } } );  // #2: <old> = op

					// Make the instruction volatile and swap the operand.
					//
					( +it )->make_volatile();
					( +it )->vip = mvip_moveout_hint;
					op = new_op;
				};

				// If any operands reference $flags, force mov first.
				//
				if ( auto access = symbolic::variable{ it, REG_FLAGS }.accessed_by( it ); access && !it->base->is_branching_real() && *it->base != ins::mov )
				{
					// TODO: This is entirely bulshit.
					//
					auto tmp = blk->tmp( 64 );
					if ( access.read )
						blk->insert( it, { &ins::mov, { tmp, REG_FLAGS } } );
					if ( access.write )
					blk->insert( std::next( it ), { &ins::mov, { REG_FLAGS, tmp } } );

					for ( auto [op, t] : ( +it )->enum_operands() )
					{
						if ( op.is_register() && op.reg().is_flags() )
						{
							op.reg().flags = tmp.flags;
							op.reg().combined_id = tmp.combined_id;
						}
					}
					( +it )->make_volatile();
					( +it )->vip = mvip_moveout_hint;
				}

				// RETN handling:
				//
				if ( it->base == &ins::vexit && it->operands[ 0 ].is_register() )
				{
					fassert( blk->next.size() == 0 );

					tracer ctrace = {};

					auto retn_to = ctrace( { it, it->operands[ 0 ].reg() } );
					auto sp_top = ctrace( { it, REG_SP } ) + it->sp_offset - 8;

					if ( retn_to->is_variable() &&
						 retn_to->uid.get<symbolic::variable>().is_memory() &&
						 retn_to->uid.get<symbolic::variable>().mem().decay()->equals( sp_top ) )
					{
						// Replace with dummy constant, set vip hint, make volatile.
						//
						( +it )->operands[ 0 ] = make_imm( 0xDEADBEEFull );
						( +it )->vip = mvip_return_hint;
						( +it )->make_volatile();

						// Pin the stack pointer.
						//
						auto pin = blk->insert( it, { &ins::vpinr, { REG_SP } } );
						(+pin)->sp_offset = it->sp_offset - 8;

						// Run DCE and stack pinning.
						//
						optimizer::dead_code_elimination_pass{}( blk );
						optimizer::stack_pinning_pass{}( blk );
					}
				}

				// For each single bit register, assert top 7 bits are not used since
				// compiler will encode them as a byte.
				// - TODO: Fix for user instead.
				//
				for ( auto [op, type] : it->enum_operands() )
				{
					if ( type >= operand_type::write && op.reg().bit_count == 1 )
					{
						register_desc hi_byte = {
							op.reg().flags,
							op.reg().combined_id,
							7,
							op.reg().bit_offset + 1
						};

						// TODO: Not sure if this works...
						//
						if ( optimizer::aux::is_used( { it, hi_byte }, true, nullptr ) )
						{
							hi_byte.bit_offset--;
							hi_byte.bit_count++;
							auto tmp = blk->tmp( 8 );
							blk->insert( it,                   { &ins::mov,      { tmp, hi_byte } } );
							blk->insert( it,                   { &ins::band,     { tmp, make_imm<uint8_t>( 0xFE ) } } );
							blk->insert( std::next( it ),      { &ins::bor,      { hi_byte, tmp } } );
						}
					}
				}

				// If IFS, force conditiona value into temporary register.
				//
				if ( it->base == &ins::ifs )
					force_operand( 2, X86_REG_R12 ); // TODO: Do this properly...

				// If mul derivative, enforce operation to be larger than a byte
				// since some registers cannot be encoded.
				//
				if ( it->base == &ins::imul || it->base == &ins::mul ||
					 it->base == &ins::imulhi || it->base == &ins::mulhi )
				{
					// Convert byte to word minimum.
					//
					for ( auto& op : ( +it )->operands )
					{
						// TODO: What if other operand uses high 8 ??????
						//

						// If not register or if above byte continue.
						//
						if ( !op.is_register() || op.reg().bit_count != 8 )
							continue;

						// Insert a hint to top bits being clobbered.
						//
						register_desc reghi = op.reg();
						reghi.bit_offset += 8;
						auto hi_clbr = blk->insert( std::next( it ), { &ins::vpinw, { reghi } } );
						(+hi_clbr)->make_volatile();
						(+hi_clbr)->vip = mvip_tmp_hint;

						// Change into word-size.
						//
						op.reg().bit_count += 8;

						// Fix immediates.
						//
						for ( auto& imm : ( +it )->operands )
							if ( imm.is_immediate() && imm.imm().bit_count < op.reg().bit_count )
								imm.imm().bit_count = op.reg().bit_count;

						// If top bits were actually used after this operation:
						//
						if ( optimizer::aux::is_used( { hi_clbr, reghi }, xblock, nullptr ) )
						{
							// Allocate a temporary value to hold the previous value.
							//
							auto tmp = blk->tmp( 32 );
							blk->insert( it, { &ins::mov, { tmp, reghi } } );
							blk->insert( std::next( hi_clbr ), { &ins::mov, { reghi, tmp } } );
						}
					}
				}

				// Handle forced registers by architecture:
				//
				if ( it->base == &ins::imul || it->base == &ins::mul )
				{
					// MUL  r/m* [?DX:?AX <- ?AX * r/m*]
					// IMUL r/m* [?DX:?AX <- ?AX * r/m*]

					force_operand( 0, X86_REG_RAX );
					if ( it->operands[ 1 ].is_immediate() )
						force_operand( 1, X86_REG_RDX );
					else
						trash_register( X86_REG_RDX );
				}
				if ( it->base == &ins::imulhi || it->base == &ins::mulhi )
				{
					// MUL  ?DX* [?DX:?AX <- ?AX * r/m*]
					// IMUL ?DX* [?DX:?AX <- ?AX * r/m*]
					force_operand( 0, X86_REG_RDX );
					force_operand( 1, X86_REG_RAX );
				}
				if ( it->base == &ins::bshr || it->base == &ins::bshl ||
					 it->base == &ins::bror || it->base == &ins::brol )
				{
					if ( !it->operands[ 1 ].is_immediate() )
						force_operand( 1, X86_REG_RCX );
				}
				if ( it->base == &ins::idiv || it->base == &ins::div )
				{
					// TODO
					unreachable();
				}
				if ( it->base == &ins::irem || it->base == &ins::rem )
				{
					// TODO
					unreachable();
				}

				// Handle 32-bit operation clearing high 32-bits of registers.
				//
				for ( auto [op, type] : it->enum_operands() )
				{
					// If instruction writes to bottom 32 bits of a physical register:
					//
					if ( type >= operand_type::write && 
						 op.reg().is_physical() &&
						 op.reg().bit_count == 32 && 
						 op.reg().bit_offset == 0 )
					{
						register_desc reghi = op.reg();
						reghi.bit_offset = 32;

						// Insert a hint to top bits are cleared.
						//
						auto hi_zero = blk->insert( std::next( it ), { &ins::mov, { reghi, make_imm( 0u ) } } );
						(+hi_zero)->make_volatile();
						(+hi_zero)->vip = mvip_tmp_hint;

						// If top bits were actually used after this operation:
						//
						if( optimizer::aux::is_used( { hi_zero, reghi }, xblock, nullptr ) )
						{
							// Allocate a temporary value to hold the previous value.
							//

							// TODO: Not sure if this works...
							//
							auto tmp = blk->tmp( 64 );
							blk->insert( it,                   { &ins::mov,      { tmp, op.reg() } } );
							blk->insert( it,                   { &ins::band,     { tmp, make_imm( 0xFFFFFFFF00000000ull ) } } );
							blk->insert( std::next( hi_zero ), { &ins::bor,      { op.reg(), tmp } } );
						}
					}
				}

				// Disallow Imm64 except of MOV & branches:
				//
				if ( *it->base != ins::mov && !it->base->is_branching() )
				{
					if ( it->base == &ins::str || it->base == &ins::ldd )
					{
						// If 64-bit offset:
						//
						auto [base, off] = ( +it )->memory_location();
						if ( !is_i32( off ) )
						{
							// Add up base and offset in a temporary:
							//
							auto tmp = blk->tmp( 64 );
							fassert( !base.is_stack_pointer() );
							blk->insert( it, { &ins::mov, { tmp, make_imm(off) } } );
							blk->insert( it, { &ins::add, { tmp, base } } );
							base = tmp;
							off = { 0 };

							// Make current instruction volatile to block mov propagation.
							//
							( +it )->vip = mvip_moveout_hint;
							( +it )->make_volatile();
						}
					}
					else
					{
						for ( auto [op, idx] : zip( ( +it )->operands, iindices ) )
						{
							// Skip if it is a register / valid imm32.
							//
							if ( !op.is_immediate() || ( op.imm().bit_count <= 32 || is_i32( op.imm().i64 ) ) )
								continue;

							// Force into a temporary.
							//
							auto tmp = blk->tmp( 64 );
							blk->insert( it, { &ins::mov, { tmp, op } } );
							op = tmp;

							// Make current instruction volatile to block mov propagation.
							//
							( +it )->vip = mvip_moveout_hint;
							( +it )->make_volatile();
						}
					}
				}

				// End the label.
				//
				blk->label_end();
			}
			return 0;
		}
	};
	struct final_register_virtualization_pass: optimizer::pass_interface<>
	{
		std::mutex mtx;
		size_t offset_0;
		routine_state* state;
		register_desc reserved_frame_register;
		final_register_virtualization_pass( routine_state* state, register_desc reserved_frame_register )
			: state( state ), offset_0( state->next_frame_offset ), reserved_frame_register( reserved_frame_register ) {}

		size_t pass( basic_block* blk, bool xblock = false )
		{
			// Eliminate temporaries:
			//
			std::map<size_t, int64_t> local_map;
			for ( auto it = blk->begin(); !it.is_end(); it++ )
			{
				if ( it->is_volatile() && it->vip != mvip_moveout_hint )
					continue;

				// Expand memory accesss.
				//
				for ( auto [op, type] : it->enum_operands() )
				{
					// If accessing local unmapped register / previous frame register:
					//
					if ( op.is_register() && ( op.reg().is_local() || op.reg().overlaps( reserved_frame_register ) ) )
					{
						int64_t frame_offset;
						
						// If frame register, it is pushed before frame starts so use fixed offset.
						//
						if ( op.reg().overlaps( reserved_frame_register ) )
						{
							frame_offset = -8;
						}
						// If temporary, determine offset in the scratch area.
						//
						else
						{
							auto lm_it = local_map.find( op.reg().combined_id );
							if ( lm_it == local_map.end() )
								frame_offset = local_map[ op.reg().combined_id ] = local_map.size() * 8 + state->next_frame_offset;
							else
								frame_offset = lm_it->second;
						}

						// Adjust frame offset to have a negative direction.
						//
						frame_offset = -frame_offset - 8;

						// Allocate a temporary register:
						//
						std::lock_guard g{ mtx };
						std::optional<register_desc> allocated_register = allocate_register( it, state );
						fassert( !allocated_register );
						fassert( allocated_register.has_value() );

						// Replace uses of register within the instruction and determine R/W.
						//
						bool read = false;
						bool write = false;
						register_desc reg = op.reg();
						register_desc new_reg = *allocated_register;
						new_reg.bit_count = 8;

						for ( auto [op2, type] : ( +it )->enum_operands() )
						{
							if ( op2.is_register() && op2.reg().overlaps( reg ) )
							{
								op2.reg().flags = allocated_register->flags;
								op2.reg().combined_id = allocated_register->combined_id;
								read |= type != operand_type::write;
								write |= type >= operand_type::write;
								new_reg.bit_count = std::max( new_reg.bit_count, op2.reg().bit_count + op2.reg().bit_offset );
							}
						}

						// If read from, add a load before.
						//
						if ( read )
						{
							blk->insert( it, { &ins::ldd, { new_reg, state->frame_register, make_imm( frame_offset ) } } );
						}
						// If written to, add a store after.
						//
						if ( write )
						{
							blk->insert( std::next( it ), { &ins::str, { state->frame_register, make_imm( frame_offset ), new_reg  } } );
						}
					}
				}
			}
		
			// Update the routine frame.
			//
			std::lock_guard g{ mtx };
			state->next_frame_offset = std::max( 
				state->next_frame_offset,
				offset_0 + local_map.size() * 8
			);
			return 0;
		}
	};

	// Virtualizes the usage of the register throughout the routine given the stack frame.
	//
	static void virtualize_register( routine* rtn, routine_state* state, const register_desc& reg )
	{
		fassert( !reg.is_stack_pointer() );
		fassert( reg.bit_offset == 0 );

		// Pick the frame offset and assign the register to it.
		//
		int64_t frame_offset = state->next_frame_offset;
		state->next_frame_offset += 8;
		state->frame_mapping[ reg ] = frame_offset;

		// Adjust frame offset to have a negative direction.
		//
		frame_offset = -frame_offset - 8;

		// If physical register, insert a str frame, offset, register at the beginning of the routine.
		//
		auto it = rtn->entry_point->begin();
		if ( reg.is_physical() )
		{
			rtn->entry_point->insert( it, 
			{
				&ins::str,
				{ state->frame_register, make_imm( frame_offset ), reg }
			} );
		}

		// For each block:
		//
		for ( auto& [vip, block] : rtn->explored_blocks )
		{
			// Begin the label.
			//
			block->label_begin( mvip_virtualizer );

			// For each instruction:
			//
			for ( auto it = block->begin(); !it.is_end(); it++ )
			{
				if ( it->vip == mvip_virtualizer )
					continue;

				// If entry point, skip the first instruction.
				//
				if ( block == rtn->entry_point && it.is_begin() )
					continue;
				
				// If instruction does not access target skip.
				//
				auto details = symbolic::variable{ it, reg }.accessed_by( it );
				if ( !details ) 
					continue;

				// If at vexit, restore the value.
				//
				if ( it->base == &ins::vexit )
				{
					if ( details.read )
					{
						auto ix = it.block->insert( it, {
							&ins::ldd,
							{ reg, state->frame_register, make_imm( frame_offset - 8 ) }
						});
					}
				}
				else
				{
					if ( it->base->is_branching_real() || it->is_volatile() )
					{
						// If instruction writes to this register, add a str after.
						//
						if ( details.write )
						{
							if ( it->base->is_branching_real() )
							{
								for ( auto& next : it.block->next )
								{
									next->insert( next->begin(),
									{
										&ins::str,
										{ state->frame_register, make_imm( frame_offset ), reg }
									} );
									
									next->insert( std::next( next->begin() ),
									{ 
										&ins::vpinw, { reg } 
									} );
								}
							}
							else
							{
								it = it.block->insert( std::next( it ),
								{
									&ins::str,
									{ state->frame_register, make_imm( frame_offset ), reg }
								} );
								it = it.block->insert( std::next( it ),
								{
									&ins::vpinw, { reg } 
								} );
							}
						}
						// If instruction reads from this register, add a load before.
						//
						if ( details.read )
						{
							it.block->insert( it, {
								&ins::ldd,
								{ reg, state->frame_register, make_imm( frame_offset ) }
							});
						}
					}
					else
					{
						// Allocate a temporary register.
						//
						auto tmp = it.block->tmp( reg.bit_count );

						// Replace all references to it.
						//
						for( auto [op, type] : ( +it )->enum_operands() )
						{
							if ( op.is_register() && op.reg().overlaps( reg ) )
							{
								tmp.bit_count = std::max( op.reg().bit_count, tmp.bit_count );
								op.reg().flags = tmp.flags;
								op.reg().combined_id = tmp.combined_id;
							}
						}

						// TODO: Remove me, this is a horrible hack.
						//
						if ( tmp.bit_count < 8 ) tmp.bit_count = 8;
						
						// If instruction reads from this register, add a load before.
						//
						if ( details.read || details.write )
						{
							it.block->insert( it, {
								&ins::ldd,
								{ tmp, state->frame_register, make_imm( frame_offset ) }
							});
						}
						// If instruction writes to this register, add a store after.
						//
						if ( details.write )
						{
							it = it.block->insert( std::next( it ),
							{
								&ins::str,
								{ state->frame_register, make_imm( frame_offset ), tmp }
							} );
						}
					}
				}
			}

			// End the label.
			//
			block->label_end();
		}
	}





	static void compile( basic_block* block, routine_state* state );

	// TODO:
	// - $SP usage in general is not working "well".
	// - Fix RBP.
	// - Handle flags @ arch handler too.
	//
	using fn_instruction_compiler_t = std::function<void( const il_iterator& it, routine_state* state )>;
	static const std::map<instruction_desc, fn_instruction_compiler_t> handler_table = 
	{
		// Data movement.
		//
		{
			ins::str,
			[ ] ( const il_iterator& it, routine_state* state )
			{
				std::string op = state->ref_rhs( it->operands[ 2 ] );
				state->assemble( "!mov %s, %s", state->deref( it ), op );
			}
		},
		{
			ins::ldd,
			[ ] ( const il_iterator& it, routine_state* state )
			{
				std::string op = state->ref_lhs( it->operands[ 0 ] );
				state->assemble( "!mov %s, %s", op, state->deref( it ) );
			}
		},
		{
			ins::mov,
			[ ] ( const il_iterator& it, routine_state* state )
			{
				auto dst = it->operands[ 0 ];
				auto src = it->operands[ 1 ];

				// Auto shrink.
				//
				if ( src.bit_count() > dst.bit_count() )
				{
					if ( src.is_register() ) 
						src.reg().bit_count = dst.bit_count();
				}

				// Handle specials:
				// -- &&base
				if ( src.is_register() && src.reg().is_image_base() )
				{
					fassert( dst.bit_count() == 64 );
					state->assemble( "!lea %s, [%s]", state->ref_lhs( dst ), state->ref_rva( 0, false ) );
				}
				// -- $flags
				else if ( src.is_register() && src.reg().is_flags() )
				{
					state->assemble( "pushfq" );
					state->assemble( "mov %s, [rsp]", state->ref_lhs( dst ) );
					state->assemble( "add rsp, 8" );
				}
				else if ( dst.reg().is_flags() )
				{
					state->assemble( "pushfq" );
					state->assemble( "mov [rsp], %s", state->ref_rhs( src ) );
					state->assemble( "popfq" );
				}
				// -- $sp
				else if ( dst.reg().is_stack_pointer() )
				{
					fassert( dst.bit_count() == 64 );

					if ( src.is_register() && src.reg().is_stack_pointer() )
					{
						if( it->sp_offset != 0 )
							state->assemble( "lea rsp, [rsp %s]", format::offset( it->sp_offset ) );
						// else nop.
						return;
					}
					else
					{
						state->assemble( "mov %s, %s", state->ref_lhs( dst ), state->ref_rhs( src ) );
					}
				}
				else if ( src.is_register() && src.reg().is_stack_pointer() )
				{
					fassert( dst.bit_count() == 64 );

					if ( it->sp_offset != 0 )
						state->assemble( "lea %s, [rsp %s]", state->ref_lhs( dst ), format::offset( it->sp_offset ) );
					else
						state->assemble( "mov %s, rsp", state->ref_lhs( dst ) );
				}
				else
				{
					if ( dst.bit_count() > src.bit_count() && !src.is_immediate() )
					{
						if ( src.bit_count() == 32 && dst.bit_count() >= 32 )
						{
							dst.reg().bit_count = 32;
							state->assemble( "mov %s, %s", state->ref_lhs( dst ), state->ref_rhs( src ) );
						}
						else
						{
							if ( src.bit_count() < 32 && dst.bit_count() >= 32 )
								dst.reg().bit_count = 32;
							state->assemble( "movzx %s, %s", state->ref_lhs( dst ), state->ref_rhs( src ) );
						}
					}
					else
					{
						fassert( src.is_immediate() || dst.bit_count() == src.bit_count() );
						state->assemble( "mov %s, %s", state->ref_lhs( dst ), state->ref_rhs( src ) );
					}
				}
			}
		},
		{
			ins::movsx,
			[ ] ( const il_iterator& it, routine_state* state )
			{
				auto dst = it->operands[ 0 ];
				auto& src = it->operands[ 1 ];
				state->assemble( "movsx %s, %s", state->ref_lhs( dst ), state->ref_rhs( src ) );
			}
		},
		// Arithmetic / Bitwise.
		//
		{
			ins::neg,
			[ ] ( const il_iterator& it, routine_state* state )
			{
				state->assemble( "neg %s", state->ref_lhs( it->operands[ 0 ] ) );
			}
		},
		{
			ins::bnot,
			[ ] ( const il_iterator& it, routine_state* state )
			{
				state->assemble( "not %s", state->ref_lhs( it->operands[ 0 ] ) );
			}
		},
		{
			ins::add,
			[ ] ( const il_iterator& it, routine_state* state )
			{
				state->assemble( "add %s, %s", state->ref_lhs( it->operands[ 0 ] ), state->ref_rhs( it->operands[ 1 ] ) );
			}
		},
		{
			ins::sub,
			[ ] ( const il_iterator& it, routine_state* state )
			{
				state->assemble( "sub %s, %s", state->ref_lhs( it->operands[ 0 ] ), state->ref_rhs( it->operands[ 1 ] ) );
			}
		},
		{
			ins::popcnt,
			[ ] ( const il_iterator& it, routine_state* state )
			{
				state->assemble( "popcnt %s, %s", state->ref_lhs( it->operands[ 0 ] ), state->ref_rhs( it->operands[ 0 ] ) );
			}
		},
		// TODO: BSF BSR
		{
			ins::bxor,
			[ ] ( const il_iterator& it, routine_state* state )
			{
				state->assemble( "xor %s, %s", state->ref_lhs( it->operands[ 0 ] ), state->ref_rhs( it->operands[ 1 ] ) );
			}
		},
		{
			ins::bor,
			[ ] ( const il_iterator& it, routine_state* state )
			{
				state->assemble( "or %s, %s", state->ref_lhs( it->operands[ 0 ] ), state->ref_rhs( it->operands[ 1 ] ) );
			}
		},
		{
			ins::band,
			[ ] ( const il_iterator& it, routine_state* state )
			{
				state->assemble( "and %s, %s", state->ref_lhs( it->operands[ 0 ] ), state->ref_rhs( it->operands[ 1 ] ) );
			}
		},
		{
			ins::bshl,
			[ ] ( const il_iterator& it, routine_state* state )
			{
				operand cnt = it->operands[ 1 ];
				
				fassert( cnt.bit_count() >= 8 );
				if ( cnt.is_immediate() ) cnt.imm().u64 &= 0xFF;
				else cnt.reg().bit_count = 8;

				state->assemble( "shl %s, %s", state->ref_lhs( it->operands[ 0 ] ), state->ref_rhs( cnt ) );
			}
		},
		{
			ins::bshr,
			[ ] ( const il_iterator& it, routine_state* state )
			{
				operand cnt = it->operands[ 1 ];

				fassert( cnt.bit_count() >= 8 );
				if ( cnt.is_immediate() ) cnt.imm().u64 &= 0xFF;
				else cnt.reg().bit_count = 8;

				state->assemble( "shr %s, %s", state->ref_lhs( it->operands[ 0 ] ), state->ref_rhs( cnt ) );
			}
		},
		{
			ins::brol,
			[ ] ( const il_iterator& it, routine_state* state )
			{
				operand cnt = it->operands[ 1 ];

				fassert( cnt.bit_count() >= 8 );
				if ( cnt.is_immediate() ) cnt.imm().u64 &= 0xFF;
				else cnt.reg().bit_count = 8;

				state->assemble( "rol %s, %s", state->ref_lhs( it->operands[ 0 ] ), state->ref_rhs( cnt ) );
			}
		},
		{
			ins::bror,
			[ ] ( const il_iterator& it, routine_state* state )
			{
				operand cnt = it->operands[ 1 ];

				fassert( cnt.bit_count() >= 8 );
				if ( cnt.is_immediate() ) cnt.imm().u64 &= 0xFF;
				else cnt.reg().bit_count = 8;

				state->assemble( "ror %s, %s", state->ref_lhs( it->operands[ 0 ] ), state->ref_rhs( cnt ) );
			}
		},
		{
			ins::mulhi,
			[ ] ( const il_iterator& it, routine_state* state )
			{
				fassert( it->access_size() != 8 );
				fassert( it->operands[ 0 ].reg().overlaps( operand{ X86_REG_RDX }.reg() ) );
				if ( !it->operands[ 1 ].is_immediate() )
					fassert( it->operands[ 1 ].reg().overlaps( operand{ X86_REG_RAX }.reg() ) );
				state->assemble( "mul %s", state->ref_lhs( it->operands[ 0 ] ) );
			}
		},
		{
			ins::imulhi,
			[ ] ( const il_iterator& it, routine_state* state )
			{
				fassert( it->access_size() != 8 );
				fassert( it->operands[ 0 ].reg().overlaps( operand{ X86_REG_RDX }.reg() ) );
				if ( !it->operands[ 1 ].is_immediate() )
					fassert( it->operands[ 1 ].reg().overlaps( operand{ X86_REG_RAX }.reg() ) );
				state->assemble( "imul %s", state->ref_lhs( it->operands[ 0 ] ) );
			}
		},
		{
			ins::mul,
			[ ] ( const il_iterator& it, routine_state* state )
			{
				fassert( it->access_size() != 8 );
				fassert( it->operands[ 0 ].reg().overlaps( operand{ X86_REG_RAX }.reg() ) );
				state->assemble( "mul %s", state->ref_lhs( it->operands[ 1 ] ) );
			}
		},
		{
			ins::imul,
			[ ] ( const il_iterator& it, routine_state* state )
			{
				fassert( it->access_size() != 8 );
				fassert( it->operands[ 0 ].reg().overlaps( operand{ X86_REG_RAX }.reg() ) );
				state->assemble( "imul %s", state->ref_lhs( it->operands[ 1 ] ) );
			}
		},
		// Control flow.
		//
		{
			ins::vxcall,
			[ ] ( const il_iterator& it, routine_state* state )
			{
				// TODO: What to do if this triggers?
				//
				fassert( !symbolic::variable{ it, state->frame_register }.written_by( it ) );

				// If immmediate:
				//
				if ( it->operands[ 0 ].is_immediate() )
				{
					state->assemble( "!call %s", state->ref_rva( it->operands[ 0 ].imm().u64 ) );
				}
				else
				{
					state->assemble( "call %s", state->ref_lhs( it->operands[ 0 ] ) );
				}

				// If next block is compiled already, insert a jump:
				//
				fassert( it.block->next.size() == 1 );
				if ( state->compiled.contains( it.block->next[ 0 ]->entry_vip ) )
					state->assemble( "!jmp %s", state->ref_label( it.block->next[ 0 ]->entry_vip ) );
				// Otherwise just invoke the compiler, there's an implicit jump.
				//
				else
					compile( it.block->next[ 0 ], state );
			}
		},
		{
			ins::vexit,
			[ ] ( const il_iterator& it, routine_state* state )
			{
				// Destroy stack frame.
				//
				state->assemble( "mov rsp, rbp" );
				state->assemble( "pop rbp" );

				// If hinted to be return:
				//
				if ( it->vip == mvip_return_hint )
				{
					state->assemble( "ret" );
				}
				// If immmediate:
				//
				else if ( it->operands[ 0 ].is_immediate() )
				{
					state->assemble( "!jmp %s", state->ref_rva( it->operands[ 0 ].imm().u64 ) );
				}
				// If register:
				//
				else
				{
					state->assemble( "jmp %s", state->ref_lhs( it->operands[ 0 ] ) );
				}
			}
		},
		{
			ins::jmp,
			[ ] ( const il_iterator& it, routine_state* state )
			{
				// Destination must be an immediate.
				// -- TODO: this changes with jump tables
				//
				fassert( it->operands[ 0 ].is_immediate() );

				// If next block is compiled already, insert a jump:
				//
				fassert( it.block->next.size() == 1 );
				if ( state->compiled.contains( it.block->next[ 0 ]->entry_vip ) )
					state->assemble( "!jmp %s", state->ref_label( it.block->next[ 0 ]->entry_vip ) );
				// Otherwise just invoke the compiler, there's an implicit jump.
				//
				else
					compile( it.block->next[ 0 ], state );
			}
		},
		{
			ins::js,
			[ ] ( const il_iterator& it, routine_state* state )
			{
				// Destinations must be immediates.
				//
				auto& dst_1 = it->operands[ 1 ];
				auto& dst_2 = it->operands[ 2 ];
				fassert( dst_1.is_immediate() && dst_2.is_immediate() );

				// Check if blocks are compiled already.
				//
				if ( !state->compiled.contains( dst_2.imm().u64 ) )
				{
					// Insert a conditional jump to [set=1], invoke the compiler for [set=0].
					//
					std::string cc = state->ref_rhs( it->operands[ 0 ] );
					state->assemble( "test %s, %s", cc, cc );
					state->assemble( "!jnz %s", state->ref_label( dst_1.imm().u64 ) );
					compile( it.block->owner->explored_blocks[ dst_2.imm().u64 ], state );
				}
				else if ( !state->compiled.contains( dst_1.imm().u64 ) )
				{
					// Insert a conditional jump to [set=0], invoke the compiler for [set=1].
					//
					std::string cc = state->ref_rhs( it->operands[ 0 ] );
					state->assemble( "test %s, %s", cc, cc );
					state->assemble( "!jz %s", state->ref_label( dst_1.imm().u64 ) );
					compile( it.block->owner->explored_blocks[ dst_2.imm().u64 ], state );
				}
				else
				{
					// Insert a conditional jump to [set=1] and an unconditional jump for [set=0].
					//
					std::string cc = state->ref_rhs( it->operands[ 0 ] );
					state->assemble( "test %s, %s", cc, cc );
					state->assemble( "!jnz %s", state->ref_label( dst_1.imm().u64 ) );
					state->assemble( "!jmp %s", state->ref_label( dst_2.imm().u64 ) );
				}

				// Make sure all blocks are compiled.
				//
				for ( basic_block* destination : it.block->next )
					compile( destination, state );
			}
		},
		// Conditionals.
		//
		#define MAP_CONDITIONAL( instruction, opcode, ropcode )																		\
		{																													  		\
			ins:: instruction,																								  		\
			[ ] ( const il_iterator& it, routine_state* state )																  		\
			{																														\
				if ( it->operands[ 1 ].is_immediate() )																				\
				{																													\
					state->assemble( "cmp %s, %s", state->ref_lhs( it->operands[ 2 ] ), state->ref_rhs( it->operands[ 1 ] ) );		\
					state->assemble( #ropcode " %s", state->ref_lhs( it->operands[ 0 ] ) );											\
				}																													\
				else																												\
				{																													\
					state->assemble( "cmp %s, %s", state->ref_lhs( it->operands[ 1 ] ), state->ref_rhs( it->operands[ 2 ] ) );		\
					state->assemble( #opcode " %s", state->ref_lhs( it->operands[ 0 ] ) );											\
				}																													\
			}																												  		\
		},
		MAP_CONDITIONAL( tg, setg, setle )
		MAP_CONDITIONAL( tge, setge, setl )
		MAP_CONDITIONAL( te, sete, setne )
		MAP_CONDITIONAL( tne, setne, sete )
		MAP_CONDITIONAL( tle, setle, setg )
		MAP_CONDITIONAL( tl, setl, setge )
		MAP_CONDITIONAL( tug, seta, setbe )
		MAP_CONDITIONAL( tuge, setae, setb )
		MAP_CONDITIONAL( tule, setbe, seta )
		MAP_CONDITIONAL( tul, setb, setae )
		#undef MAP_CONDITIONAL
		{
			ins::ifs,
			[ ] ( const il_iterator& it, routine_state* state )
			{
				std::string dst = state->ref_lhs( it->operands[ 0 ] );
				std::string cc = state->ref_rhs( it->operands[ 1 ] );
				std::string res = state->ref_rhs( it->operands[ 2 ] );
				fassert( it->operands[ 2 ].is_register() );

				state->assemble( "xor %s, %s", dst, dst );
				state->assemble( "test %s, %s", cc, cc );
				state->assemble( "cmovnz %s, %s", dst, res );
			}
		},
		// Special instructions:
		//
		{
			ins::nop,
			[ ] ( const il_iterator& it, routine_state* state )
			{
				state->assemble( "nop" );
			}
		},
		{ ins::vpinr,  [ ] ( const il_iterator& it, routine_state* state ){} },
		{ ins::vpinw,  [ ] ( const il_iterator& it, routine_state* state ){} },
		{ ins::vpinrm, [ ] ( const il_iterator& it, routine_state* state ){} },
		{ ins::vpinwm, [ ] ( const il_iterator& it, routine_state* state ){} },
	};		    





	static void compile( basic_block* block, routine_state* state )
	{
		// Prevent infinite recursion.
		//
		if ( !state->compiled.emplace( block->entry_vip ).second ) 
			return;
		
		// Begin the assembly.
		//
		state->add_label( block->entry_vip );

		// If we're at the entry point, begin stack frame.
		//
		if ( block == block->owner->entry_point )
		{
			// Miaslign the frame size to compensate for rbp.
			//
			state->next_frame_offset += 0xF;
			state->next_frame_offset &= ~0xF;
			state->next_frame_offset += 8;

			state->assemble( "push rbp" );
			state->assemble( "mov rbp, rsp" );
			state->assemble( "sub rsp, 0x%llx", state->next_frame_offset );
		}

		// Compile each instruction:
		//
		int64_t sp_offset = 0;
		for ( auto it = block->begin(); !it.is_end(); it++ )
		{
			// Handle VEMIT.
			//
			std::vector<uint8_t> bytes;
			while ( it->base == &ins::vemit && !it.is_end() )
			{
				uint8_t* bs = ( uint8_t* ) &it->operands[ 0 ].imm().u64;
				bytes.insert( bytes.end(), bs, bs + it->operands[ 0 ].size() );
				it = std::next( it );
			}
			if ( bytes.size() )
			{
				auto dasm = amd64::disasm( bytes.data(), it->vip == invalid_vip ? 0 : it->vip, bytes.size() );
				for ( auto& ins : dasm )
					state->assemble( "%s %s", ins.mnemonic, ins.operand_string );
			}
			if ( it.is_end() ) break;

			// Handle changes in stack offset.
			//
			if ( sp_offset > it->sp_offset )
				state->assemble( "sub rsp, %s", format::hex( sp_offset - it->sp_offset ) );
			else if ( sp_offset < it->sp_offset )
				state->assemble( "add rsp, %s", format::hex( it->sp_offset - sp_offset ) );
			sp_offset = it->sp_reset ? 0 : it->sp_offset;

#if COMPILER_VERBOSE_GENERATION
			debug::dump( *it );
#endif
			auto handler = handler_table.find( *it->base );
			if ( handler == handler_table.end() )
				logger::error( "Unrecognized instruction '%s'\n", it->base->name );
			handler->second( it, state );
		}
	}

	static std::vector<uint8_t> compile( routine* rtn_in, uint32_t rva )
	{
		using namespace logger;

		using propagation_collective = optimizer::exhaust_pass<
			optimizer::apply_each<optimizer::local_pass, 
				optimizer::combine_pass<
					optimizer::stack_propagation_pass,
					optimizer::exhaust_pass<
						optimizer::mov_propagation_pass,
						optimizer::register_renaming_pass,
						optimizer::dead_code_elimination_pass
					>,
					optimizer::dead_code_elimination_pass,
					optimizer::stack_pinning_pass
				>
			>
		>;

		// Allocate frame information.
		//
		routine_state state = {
			.rva = rva,
			.frame_register = rtn_in->routine_convention.frame_register
		};

		// Clone the routine, we do not optimize on the caller's copy.
		//
		std::unique_ptr<routine> rtn( rtn_in->clone() );

		// Pass through symbolic rewrite pass to eliminate bitwise access
		// and invoke the general propagation pass afterwards
		//
		optimizer::isymbolic_rewrite_pass{ true, { 8, 16, 32, 64 } }( rtn.get() );

		// Virtualize all (non-local) virtual registers and reserve frame register.
		//
		auto reserved_frame_register = rtn->alloc( 64 );
		rtn->for_each( [ & ] ( auto blk )
		{
			// If frame register, move to the reserved instance.
			//
			for ( auto it = blk->begin(); !it.is_end(); it++ )
			{
				for ( auto [op, type] : ( +it )->enum_operands() )
				{
					if ( op.is_register() && op.reg().overlaps( state.frame_register ) )
					{
						op.reg().flags = reserved_frame_register.flags;
						op.reg().combined_id = reserved_frame_register.combined_id;
						continue;
					}
				}
			}
			// Virtualize [vr* & sr*] registers:
			//
			for ( auto it = blk->begin(); !it.is_end(); it++ )
			{
				for ( auto [op, type] : it->enum_operands() )
				{
					if ( op.is_register() && op.reg().is_virtual() && !op.reg().is_local() && !op.reg().is_special() )
						virtualize_register( rtn.get(), &state, op.reg() );
				}
			}
		} );
		//virtualize_register( rtn.get(), &state, REG_FLAGS );

		// Pass through local optimizer.
		//
		propagation_collective{}( rtn.get() );

		// Define a helper to free up a number of registers upon request.
		//
		std::vector registers = amd64::preserve_all_convention.param_registers;
		auto virtualize_n = [ & ] ( size_t cnt )
		{
			size_t pop_cnt = 0;
			while ( registers.size() && pop_cnt < cnt )
			{
				auto rit = std::prev( registers.end() );
				register_desc reg = *rit;
				registers.erase( rit );
				if ( reg.is_stack_pointer() || reg.is_flags() || reg.overlaps( state.frame_register ) )
					continue;
				virtualize_register( rtn.get(), &state, reg );
				log( "-- Virtualized real references to register '%s'\n", reg );
				pop_cnt++;
			}
			return pop_cnt;
		};

		// Define a helper to analyse the routine as is.
		//
		const auto routine_stats = [ ] ( std::unique_ptr<routine>& rtn ) -> auto
		{
			std::set<register_desc> virtual_regs;
			size_t max_tmp_count = 0;
			size_t ins_cnt = 0;
			rtn->for_each( [ & ] ( auto blk )
			{
				// Add to instruction counter.
				//
				ins_cnt += blk->size();

				// For each instruction and their operands:
				//
				size_t tmp_reg_count = 0;
				for ( auto it = blk->begin(); !it.is_end(); it++ )
				{
					for ( auto [op, type] : it->enum_operands() )
					{
						// Skip if not register.
						//
						if ( !op.is_register() )
							continue;

						// Resize to full size and push up the sets.
						//
						register_desc reg = op.reg();
						reg.bit_count = 64;
						reg.bit_offset = 0;

						// If local register, increment temporary counter.
						//
						if ( reg.is_local() )
							tmp_reg_count++;
						if ( reg.is_virtual() && !reg.is_special() )
							virtual_regs.insert( reg );
					}
				}
				max_tmp_count = std::max( max_tmp_count, tmp_reg_count );
			} );

			// Return frame size and the number of instructions.
			//
			return std::pair{ ins_cnt, virtual_regs.size() * 8 + max_tmp_count * 8 };
		};

		// Virtualize 2 registers pre-emptively.
		//
		virtualize_n( 2 );

		// Analyse the routine and save the original block's instruction count.
		//
		auto [ins_cnt, frame_size] = routine_stats( rtn );
		size_t orig_ins_cnt = ins_cnt;

		// Backup the routine.
		//
		std::unique_ptr<routine> backup( rtn->clone() );

		// Register allocation pass:
		//
		for( int step = 0;; step++ )
		{
			log<CON_YLW>( "Register allocation step %d...\n", step );

			// Pass through the register allocator and the common
			// propagation passes that should be executed post-allocation.
			//
			lazy_register_allocator{ &state }( rtn.get() );
			propagation_collective{}( rtn.get() );

			// Remove the hints we've added.
			//
			for ( auto& [vip, blk] : rtn->explored_blocks )
			{
				for ( auto it = blk->begin(); !it.is_end(); )
				{
					if ( it->vip == mvip_tmp_hint ) it = blk->erase( it );
					else ++it;
				}
			}

			// Calculate and print the current stats.
			//
			auto [new_ins_cnt, new_frame_size] = routine_stats( rtn );
			log<CON_CYN>( "Frame size:         0x%x bytes.\n", new_frame_size );
			log<CON_CYN>( "Instruction count:  %d\n\n", new_ins_cnt );

			// If we've reached the limit, use old routine.
			//
			if ( new_ins_cnt > ( orig_ins_cnt * maximum_block_expansion ) || new_frame_size >= frame_size )
			{
				log<CON_RED>( "Halting register virtualization as it did not improve the result.\n" );
				rtn = std::move( backup );
				new_ins_cnt = ins_cnt;
				new_frame_size = frame_size;
			}
			// If we can still optimize further:
			//
			else if( !registers.empty() && new_frame_size != 0 )
			{
				// Update backup.
				//
				backup.reset( rtn->clone() );
				frame_size = new_frame_size;
				ins_cnt = new_ins_cnt;

				// Virtualize 2 more registers.
				//
				virtualize_n( 2 );

				// Continue the pass.
				//
				continue;
			}

			// Print the final stats.
			//
			log( "\n" );
			log<CON_GRN>( "Frame size:         0x%x bytes.\n", new_frame_size );
			log<CON_GRN>( "Instruction count:  %d\n", new_ins_cnt );
			for ( auto& [reg, offset] : state.frame_mapping )
				log<CON_PRP>( " -- %s + 0x%-3x := %s\n", state.frame_register, offset, reg );
			for ( int64_t offset = state.next_frame_offset; offset < new_frame_size; offset+= 8 )
				log<CON_BLU>( " -- %s + 0x%-3x := Reserved as scratch space\n", state.frame_register, offset );

			// Pass through the arch-normalization pass, handle registers again.
			//
			arch_normalization_pass{}( rtn.get() );
			propagation_collective{}( rtn.get() );
			lazy_register_allocator{ &state }( rtn.get() );
			propagation_collective{}( rtn.get() );

			// Remove the hints we've added and replace vpinrq $sp with mov $sp, $sp, effectively fragmenting stack.
			//
			for ( auto& [vip, blk] : rtn->explored_blocks )
			{
				for ( auto it = blk->begin(); !it.is_end(); )
				{
					// If temporary hint, delete, else continue.
					//
					if ( it->vip == mvip_tmp_hint ) it = blk->erase( it );
					else ++it;
				}
			}

			// Pass through the final virtualization pass.
			
			// TODO: Fix me, these passes spawn local registers...
			//
			//final_register_virtualization_pass{ &state }( rtn.get() );
			//optimizer::dead_code_elimination_pass{}( rtn.get() );
			//optimizer::stack_pinning_pass{}( rtn.get() );
			optimizer::stack_pinning_pass{}( rtn.get() );
			final_register_virtualization_pass{ &state, reserved_frame_register }( rtn.get() );
			optimizer::dead_code_elimination_pass{}( rtn.get() );

			// Replace vpinrq $sp with mov $sp, $sp, effectively fragmenting stack.
			//
			/*for ( auto& [vip, blk] : rtn->explored_blocks )
			{
				int64_t sp = 0;
				for ( auto it = blk->begin(); !it.is_end(); ++it )
				{
					if ( it->sp_offset != sp )
					{
						it->sp_reset = true;
						auto it2 = std::next( it );
						blk->shift_sp( -it->sp_offset, false, it2 );
						for ( ; !it2.is_end(); it2++ )
							it2->sp_index++;
					}
				}
			}*/

			// Begin compilation from entry-point.
			//
			compile( rtn->entry_point, &state );

			// TODO implement hint("VMProtectBegin"); stuff == cool
			//		implement a way to detect assembler errors since its a big deal
			//
#if COMPILER_VERBOSE_GENERATION
			log( "%s\n", state.document );
#endif
			return amd64::assemble( state.document, rva );
		}
		unreachable();
	}
};