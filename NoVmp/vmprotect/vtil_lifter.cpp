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
#include "vtil_lifter.hpp"
#include <vector>
#include "rkey.hpp"
#include "subroutines.hpp"
#include "deobfuscator.hpp"
#include "architecture.hpp"
#include "il2vtil.hpp"

#define DISCOVERY_VERBOSE_OUTPUT 0

namespace vmp
{
	vtil::basic_block* lift_il( vtil::basic_block* block, vm_state* vstate )
	{
		const auto fix_constant_pool = [ & ] ()
		{
			// Fix stack access to avoid trace cost.
			//
			vtil::optimizer::stack_pinning_pass{}( block );
			vtil::optimizer::istack_ref_substitution_pass{}( block );

			// Reloc base is always at the top of virtual stack upon block begin,
			// create the base-address offset evaluator using it.
			//
			vtil::symbolic::pointer reloc_base =
				vtil::symbolic::variable{ block->begin(), vtil::REG_SP }.to_expression();
			auto eval = [ & ] ( const vtil::symbolic::unique_identifier& uid )
				-> std::optional<uint64_t>
			{
				auto& var = uid.get<vtil::symbolic::variable>();
				if ( var.is_register() && var.reg().is_image_base() )
					return 0;
				if ( var.is_memory() && ( var.mem().base - reloc_base ) == 0 )
					return ( uint64_t ) -( int64_t ) vstate->img->get_real_image_base();
				return std::nullopt;
			};

			// For each LDD:
			//
			vtil::cached_tracer tracer{};
			for ( auto it = block->begin(); it != block->end(); it++ )
			{
				if ( it->base != &vtil::ins::ldd )
					continue;
				auto [base, off] = it->memory_location();
				if ( base.is_stack_pointer() )
					continue;
        
				// If it evaluates to constant delta from base:
				//
				if ( auto res = tracer( { it, base } )->evaluate( eval ); res.is_known() )
				{
					uint64_t rva = *res.get() + off;
					if ( !vstate->img->has_relocs ) rva -= vstate->img->get_real_image_base();

					// If in a read-only section:
					//
					if ( auto section = vstate->img->rva_to_section( rva ) )
					{
						if ( !section->characteristics.mem_write )
						{
							// Replace with MOV.
							//
							uint64_t value = 0;

							memcpy(
								&value,
								vstate->img->rva_to_ptr( rva ),
								it->access_size() / 8
							);

							( +it )->base = &vtil::ins::mov;
							( +it )->operands = { it->operands[ 0 ], vtil::operand{ value, it->access_size() } };
						}
					}
				}
			}
		};


		// If virtual instruction pointer is not set:
		//
		if ( !vstate->vip )
		{
			// Parse VMENTER:
			//
			auto [entry_stack, entry_vip] = parse_vmenter( vstate, vstate->current_handler_rva );
			auto blk_caller = block;
			entry_vip += ( vstate->dir_vip < 0 ? -1 : 0 );

			// Begin block if none passed.
			//
			if ( !block )
			{
				block = vtil::basic_block::begin( entry_vip );
			}
			// Otherwise, fork the block.
			//
			else
			{
				auto new_block = block->fork( entry_vip );
				// If returned nullptr, it's already explored, skip.
				//
				if ( !new_block )
				{
					std::lock_guard g( block->owner->mutex );
					block = block->owner->explored_blocks[ entry_vip ];
					fassert( block );
					// TODO: Trace possible exits once more ?.
					//
					return block;
				}
				block = new_block;
			}

			// Insert push instructions.
			//
			for ( auto& op : entry_stack )
				block->push( op );

			// Push relocation offset.
			//
			auto treloc = block->tmp( 64 );
			block->mov( treloc, vtil::REG_IMGBASE )
				 ->sub( treloc, vstate->img->get_real_image_base() )
				 ->push( treloc );
		}
		else
		{
			// If passed block is nullptr, it's already explored, skip.
			//
			if ( !block ) return nullptr;
		}

		while ( 1 )
		{
			if ( !vstate->img->rva_to_section( vstate->current_handler_rva ) )
			{
				// TODO: Whoooops.
				//
				vtil::debug::dump( block->prev[ 0 ] );
				throw std::runtime_error( "Whoooops invalid virtual jump." );
			}

			// Unroll the stream
			//
			instruction_stream is = vstate->unroll();

			// Resolve self-referencing point and decryption blocks
			//
			std::optional self_ref_point = find_self_ref( vstate, is );
			std::vector rkblocks = extract_rkey_blocks( vstate, is );

			// If handler has a self referencing point (X: LEA r64, [X]), handle VM swap
			// 
			instruction_stream prefixss;
			if ( self_ref_point.has_value() )
			{
				// Parse the new VM state
				//
				rkblocks = parse_vmswap( vstate, is, prefixss );
			}

			// If instruction has no decryption blocks, handle VM exit / external call
			//
			if ( rkblocks.empty() )
			{
				const auto is_rva_in_vmp_scn = [ & ] ( uint32_t rva )
				{
					auto section = vstate->img->rva_to_section( rva );
					if ( !section ) return false;

					if ( vstate->img->rva_to_section( rva ) ==
						 vstate->img->rva_to_section( vstate->current_handler_rva ) )
						return true;

					for ( const auto& prefix : section_prefixes )
						if ( !memcmp( prefix.data(), &section->name.short_name[0], prefix.size() ) )
							return true;

					return false;
				};

				// Parse VMEXIT to resolve the order registers are popped
				//
				std::vector exit_stack = parse_vmexit( vstate, is );

				// Simulate the VPOP for each register being popped in the routine
				//
				for ( auto& op : exit_stack )
					block->pop( op );

				// Pop target from stack.
				//
				vtil::operand jmp_dest = block->tmp( 64 );
				block->pop( jmp_dest );

				// Insert vexit to the location.
				//
				block->vexit( jmp_dest );

				// Remove constant obfuscation.
				//
				if ( vstate->img->strip_constant_obfuscation )
					fix_constant_pool();

				// Pass the current block through optimization.
				//
				//block->owner->local_opt_count += vtil::optimizer::apply_all( block ); // OPTIMIZER
				jmp_dest = block->back().operands[ 0 ];

				// Determine current stack offset.
				//
				vtil::tracer tracer;
				auto stack_0 = vtil::symbolic::variable{ block->owner->entry_point->begin(), vtil::REG_SP }.to_expression();
				auto stack_1 = tracer.rtrace_p( { std::prev( block->end() ), vtil::REG_SP } ) + block->sp_offset;
				auto offset = stack_1 - stack_0;
#if DISCOVERY_VERBOSE_OUTPUT
				log( "sp offset => %s\n", offset.to_string() );
#endif

				// If stack offset is non-const or [Offset < 0]:
				//
				if ( !offset.is_constant() || *offset.get<true>() < 0 )
				{
					// Try to read from the top of the stack.
					//
					auto continue_from = ( tracer.rtrace_p( { std::prev( block->end() ),
										   { tracer( { std::prev( block->end() ), vtil::REG_SP } ) + block->sp_offset, 64 } } ) -
										   (vstate->img->has_relocs ? vtil::symbolic::variable{ {}, vtil::REG_IMGBASE }.to_expression() : vtil::symbolic::expression{ vstate->img->get_real_image_base() })).simplify( true );
#if DISCOVERY_VERBOSE_OUTPUT
					log( "continue => %s\n", continue_from.to_string() );
#endif
					// If constant and is in VMP section:
					//
					if ( continue_from.is_constant() && is_rva_in_vmp_scn( *continue_from.get() ) )
					{
						// If return address points to a PUSH IMM32, aka VMENTER.
						//
						auto disasm = deobfuscate( vstate->img, *continue_from.get() );
						if ( disasm.size() && disasm[ 0 ].is( X86_INS_PUSH, { X86_OP_IMM } ) )
						{
							// Convert into vxcall and indicate that push is implicit by
							// shifting the stack pointer.
							//
							block->wback().base = &vtil::ins::vxcall;
							block->wback().vip = vstate->vip;
							block->shift_sp( 8, false, block->end() );

							/* TODO:
							// Check if it's alloca_probe inserted by the compiler, in which case we can ignore
							// and should be preserving RAX
							//
							if ( ret_rva )
							{
								// Try to identify ALLOCA probe
								//
								instruction_stream is = unroll_stream( vstate->img, ret_rva );
								if ( is.size() &&
									 is[ 0 ].is( X86_INS_SUB, { X86_OP_REG, X86_OP_IMM } ) &&
									 is[ 0 ].operands[ 1 ].imm == 0x10 )
								{
									// Try to evaluate EAX into a constant
									//
									mlil::symbol_map sym_rax;
									expression_old::instance exp_rax = mlf->trace( mlil::operand{ X86_REG_RAX }, &sym_rax ).value;
									std::optional<uint64_t> val_rax;
									if ( exp_rax )
									{
										if ( auto res = expression_old::simplify( exp_rax )->evaluate() )
											val_rax = res.value().u64;
									}

									// If rax does indeed evaluate to a constant value
									//
									if ( val_rax.has_value() )
									{
										// Skip the VXCALL that would be appended to the stream and go straight to the parsing of VMENTER
										//
										for ( x86_reg reg : parse_vmenter( vstate, xret_rva ) )
										{
											// Declare RAX preserved
											//
											if ( reg == X86_REG_RAX )
											{
												mlf->mov( mlil::operand{ X86_REG_RAX }, mlil::make_const( val_rax.value() ) );
												mlf->push( mlil::make_const( val_rax.value() ) );
											}
											else
											{
												mlf->push( mlil::operand( reg ) );
											}
										}

										// Continue parsing as usual
										//
										io::log<CON_RED>( "Processed vmexit-vmenter chain [_alloca_probe()]...\n" );
										continue;
									}
								}
							}
							*/

							// Continue lifting from the linked virtual machine.
							//
							vm_state state = { vstate->img, *continue_from.get() };
							lift_il( block, &state );
							break;
						}
					}
				}

				// Reached real exit, determine destination.
				//
				auto exit_destination = jmp_dest.is_immediate()
					? vtil::symbolic::expression{ jmp_dest.imm().u64, jmp_dest.bit_count() }
					: (tracer.rtrace_p({ std::prev(block->end()), jmp_dest.reg() }) - (vstate->img->has_relocs ? vtil::symbolic::variable{ {}, vtil::REG_IMGBASE }.to_expression() : vtil::symbolic::expression{ vstate->img->get_real_image_base() })).simplify(true);
#if DISCOVERY_VERBOSE_OUTPUT
				log( "exit => %s\n", exit_destination.to_string() );
#endif

				// If constant and is in VMP section:
				//
				if ( exit_destination.is_constant() && is_rva_in_vmp_scn( *exit_destination.get() ) )
				{
					// Pop the VMEXIT.
					//
					block->pop_back();

					// Extract the non-virtualized chunk before VMENTER.
					//
					auto is = deobfuscate( vstate->img, *exit_destination.get() );

					instruction_stream non_virt_chunk = {};
					while ( true )
					{
						if ( is.size() <= 1 )
						{
							block->vexit( *exit_destination.get() );
							return block;
						}

						if ( is[ 0 ].is( X86_INS_PUSH, { X86_OP_IMM } ) &&
							 is[ 1 ].is( X86_INS_CALL, { X86_OP_IMM } ) )
							break;
						else
							non_virt_chunk.stream.push_back( is.stream[ 0 ] );
						is.erase( 1 );
					}

					// Insert VPINR->VEMIT->VPINW stream.
					//
					for ( auto& [id, ins] : non_virt_chunk.stream )
					{
						if ( ins.is( X86_INS_PUSHFQ, {} ) )
						{
							block->pushf();
							continue;
						}
						else if ( ins.is( X86_INS_POPFQ, {} ) )
						{
							block->popf();
							continue;
						}

						for ( auto reg_read : ins.regs_read )
						{
							vtil::operand op = x86_reg( reg_read );
							if ( reg_read == X86_REG_RSP ) op = { vtil::REG_SP };
							if ( reg_read == X86_REG_EFLAGS ) op = { vtil::REG_FLAGS };
							block->vpinr( op );
						}

						for ( uint8_t byte : ins.bytes )
							block->vemit( byte );

						for ( auto reg_write : ins.regs_write )
						{
							vtil::operand op = x86_reg( reg_write );
							fassert( reg_write != X86_REG_RSP );
							if ( reg_write == X86_REG_EFLAGS ) op = { vtil::REG_FLAGS };
							block->vpinw( op );
						}
					}

					// Insert a dummy JMP.
					//
					block->jmp( vtil::invalid_vip );

					// Continue lifting from the linked virtual machine.
					//
					vm_state state = { vstate->img, is[ 0 ].address };
					auto block_next = lift_il( block, &state );
					
					// Replace the destination of the jump.
					//
					block->wback().operands[ 0 ] = { block_next->entry_vip, 64 };
					break;
				}

				// Break out of the lifter loop.
				//
				break;
			}

			// Assert we have valid decryption blocks
			//
			fassert( !rkblocks.empty() );
			fassert( rkblocks.back().output_size == 4 );

			// Decrypt all parameters for the instruction
			//
			vtil::vip_t vip_params = vstate->vip;
			std::vector<std::pair<rkey_block*, rkey_value>> parameters;
			for ( rkey_block& rkblock : rkblocks )
				parameters.push_back( { &rkblock, vstate->decrypt_vip( rkblock ) } );

			// Reduce the instruction handler chunk, classify the IL instruction associated
			//
			reduce_chunk( vstate, is, parameters );
			is.stream.insert( is.stream.begin(), prefixss.stream.begin(), prefixss.stream.end() );
			arch::instruction il_instruction = arch::classify( vstate, is );

			// If there was a self-reference point in the handler
			//
			if ( self_ref_point.has_value() )
			{
				// Handle nop:
				//
				if( il_instruction.op == "VNOP" )
				{
					// Insert jump to VIP+$.
					//
					vtil::vip_t dst = vip_params + ( vstate->dir_vip < 0 ? -1 : 0 );
					block->jmp( dst );

					// Remove constant obfuscation.
					//
					if ( vstate->img->strip_constant_obfuscation )
						fix_constant_pool();

					// Pass the current block through optimization.
					//
					//block->owner->local_opt_count += vtil::optimizer::apply_all( block ); // OPTIMIZER

					// Fork the current flow and parse as a seperate block.
					//
					vstate->next( rkblocks.back(), vip_params, self_ref_point.value() );
					lift_il( block->fork( dst ), vstate );
					return block;
				}
				else if ( il_instruction.op == "VJMP" )
				{
					// Pop target from stack.
					//
					auto jmp_dest = block->tmp( 64 );
					block->pop( jmp_dest );

					if ( vstate->dir_vip < 0 )
						block->sub( jmp_dest, 1 );

					// If relocs stripped, substract image base, uses absolute address.
					//
					if( !vstate->img->has_relocs )
						block->sub( jmp_dest, vstate->img->get_real_image_base() );
					
					// Insert jump to the location.
					//
					block->jmp( jmp_dest );

					// Remove constant obfuscation.
					//
					if ( vstate->img->strip_constant_obfuscation )
						fix_constant_pool();

					// Pass the current block through optimization.
					//
					block->owner->local_opt_count += vtil::optimizer::apply_all( block ); // OPTIMIZER

					// Allocate an array of resolved destinations.
					//
					vtil::/*cached_*/tracer tracer = {};
					std::vector<vtil::vip_t> destination_list;
					uint64_t image_base = vstate->img->has_relocs ? 0 : vstate->img->get_real_image_base();
					auto branch_info = vtil::optimizer::aux::analyze_branch( block, &tracer, { .pack = true } );
#if DISCOVERY_VERBOSE_OUTPUT
					log( "CC: %s\n", branch_info.cc );
					log( "VJMP => %s\n", branch_info.destinations );
#endif
					for ( auto& branch : branch_info.destinations )
					{
						// If not constant:
						//
						if ( !branch->is_constant() )
						{
							// Recursively trace the expression and remove any matches of REG_IMGBASE.
							//
							branch = tracer.rtrace_pexp( *branch );
							branch.transform( [image_base] ( vtil::symbolic::expression::delegate& ex )
								{
									if ( ex->is_variable() )
									{
										auto& var = ex->uid.get<vtil::symbolic::variable>();
										if ( var.is_register() && var.reg() == vtil::REG_IMGBASE )
											*+ex = { image_base, ex->size() };
									}
								} )
								.simplify( true );
						}

						// If not constant:
						//
						if ( !branch->is_constant() )
						{
							// TODO: Handle switch table patterns.
							//
							log( "VJMP =>\n" );
							for ( auto [branch, idx] : vtil::zip( branch_info.destinations, vtil::iindices ) )
							{
								log( "-- %d) %s\n", idx, branch );
								log( ">> %s\n", tracer.rtrace_exp( *branch ) );
							}
							log( "CC: %s\n", branch_info.cc );
							//vtil::optimizer::aux::analyze_branch( block, &tracer, false );
							throw std::runtime_error( "Whoooops hit switch case..." );
						}

						destination_list.push_back( *branch->get<vtil::vip_t>() );
					}

					// Declare branch helper.
					//
					const auto explorer = [ & ] ( vtil::vip_t dst )
					{
#if DISCOVERY_VERBOSE_OUTPUT
						log<CON_GRN>( "Exploring branch => %p\n", dst );
#endif
						vm_state vstate_dup = *vstate;
						vstate_dup.vip = dst + ( vstate->dir_vip < 0 ? +1 : 0 );
						vstate_dup.next( rkblocks.back(), vstate_dup.vip, self_ref_point.value() );
						lift_il( block->fork( dst ), &vstate_dup );
					};

					//
					// TODO: Fix me.
					// There are still some concurrency issues in this code base so 
					// not using multi-threading for now, optimization is not done here
					// so we don't lose much speed anyways.
					//
					for ( auto& l : destination_list )
						explorer( l );

					/*// Allocate a thread for each additional destination.
					//
					std::vector<std::thread> thread_pool;
					fassert( destination_list.size() >= 1 );
					for ( auto dst : vtil::make_range( destination_list.begin() + 1, destination_list.end() ) )
						thread_pool.emplace_back( explorer, dst );

					// Invoke current helper and wait for each thread, then break out of the loop.
					//
					explorer( destination_list.front() );
					for ( auto& thread : thread_pool )
						thread.join();*/
					break;
				}
				unreachable();
			}

			// Translate from VMP Arch to VTIL and continue processing
			//
			block->label_begin( vip_params );
			translate( block, il_instruction );
			block->label_end();

			// Skip to next instruction and continue parsing the flow linearly
			//
			vstate->next( parameters.back().second );
		}
		return block;
	}
};