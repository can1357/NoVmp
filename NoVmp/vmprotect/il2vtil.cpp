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
#include "il2vtil.hpp"
#include <vtil/amd64>
#include <vtil/arch>
#include <functional>
#include <vector>
#include "architecture.hpp"

namespace vmp
{
	struct converter
	{
		arch::opcode_id base_op;
		void( *converter_fn )( vtil::basic_block*, const arch::instruction&, uint8_t );

		bool convert( vtil::basic_block* fl, const arch::instruction& ins, bool write_src = true )
		{
			// Check if opcode matches the base opcode id
			// and extract the variants from the name
			//
			if ( ins.op.size() != base_op.size() ) return false;

			std::vector<uint8_t> variants = {};
			for ( int i = 0; i < ins.op.size(); i++ )
			{
				if ( ins.op[ i ] == base_op[ i ] ) continue;
				if ( base_op[ i ] != '*' ) return {};
				variants.push_back( arch::resolve_abbrv_param_size( ins.op[ i ] ) );
			}
			fassert( variants.size() <= 1 );
			variants.resize( 1 );

			// Redirect to the converter
			//
			size_t p = fl->size();
			converter_fn( fl, ins, variants[ 0 ] );
			return true;
		}
	};
	
	// Add per/bit flag addressing and vtil::UNDEFINED register.
	// - Ugly yeah but don't want to tailor the repo with arch-dependent code.
	//
	static constexpr vtil::register_desc FLAG_CF = vtil::REG_FLAGS.select( 1, 0 );
	static constexpr vtil::register_desc FLAG_PF = vtil::REG_FLAGS.select( 1, 2 );
	static constexpr vtil::register_desc FLAG_AF = vtil::REG_FLAGS.select( 1, 4 );
	static constexpr vtil::register_desc FLAG_ZF = vtil::REG_FLAGS.select( 1, 6 );
	static constexpr vtil::register_desc FLAG_SF = vtil::REG_FLAGS.select( 1, 7 );
	static constexpr vtil::register_desc FLAG_DF = vtil::REG_FLAGS.select( 1, 10 );
	static constexpr vtil::register_desc FLAG_OF = vtil::REG_FLAGS.select( 1, 11 );

	static constexpr vtil::register_desc make_virtual_register( uint8_t context_offset, uint8_t size )
	{
		fassert( ( ( context_offset & 7 ) + size ) <= 8 && size );

		return {
			vtil::register_virtual,
			( size_t ) context_offset / 8,
			size * 8,
			( context_offset % 8 ) * 8
		};
	}

	static std::vector<converter> converters =
	{
		{
			"VPOPV*",
			[ ] ( vtil::basic_block* fl, const arch::instruction& ins, uint8_t v )
			{
				auto& p = ins.parameters;
				fl
					// pop vrN
					->pop( make_virtual_register( p[ 0 ], v ) );
			}
		},

		{
			"VPOPD*",
			[ ] ( vtil::basic_block* fl, const arch::instruction& ins, uint8_t v )
			{
				auto& p = ins.parameters;
				fl
					// add rsp, *
					->shift_sp( v );
			}
		},

		{
			"VPUSHC*",
			[ ] ( vtil::basic_block* fl, const arch::instruction& ins, uint8_t v )
			{
				auto& p = ins.parameters;
				fl
					// push Imm<N>
					->push( vtil::operand( p[ 0 ], v * 8 ) );
			}
		},

		{
			"VPUSHV*",
			[ ] ( vtil::basic_block* fl, const arch::instruction& ins, uint8_t v )
			{
				auto& p = ins.parameters;
				fl
					// push vrN
					->push( make_virtual_register( p[ 0 ], v ) );

			}
		},
		{
			"VPUSHR*",
			[ ] ( vtil::basic_block* fl, const arch::instruction& ins, uint8_t v )
			{
				auto& p = ins.parameters;

				if ( v == 8 )
				{
					fl->push( vtil::REG_SP );
				}
				else
				{
					auto t0 = fl->tmp( v * 8 );
					fl->mov( t0, vtil::REG_SP );
					fl->push( t0 );
				}
			}
		},

		{
			"VADDU*",
			[ ] ( vtil::basic_block* fl, const arch::instruction& ins, uint8_t v )
			{
				auto& p = ins.parameters;
				auto [t0, t1, t2] = fl->tmp( v * 8, v * 8, v * 8 );
				auto [b0, b1, b2, b3] = fl->tmp( 1, 1, 1, 1 );

				fl
					// t0 := [rsp]
					// t1 := [rsp+*]
					->pop( t0 )
					->pop( t1 )

					// t1 += t0
					->mov( t2, t1 )
					->add( t1, t0 )

					// Update flags.
					// SF = r < 0
					->tl( FLAG_SF, t1, 0 )
					// ZF = r == 0
					->te( FLAG_ZF, t1, 0 )
					// CF = r < a
					->tul( FLAG_CF, t1, t2 )
					// b0 = (a < 0) == (b < 0)
					->tl( b2, t2, 0 )
					->tl( b3, t0, 0 )
					->te( b0, b2, b3 )
					// b1 = (a < 0) != (r < 0)
					->tl( b2, t2, 0 )
					->tl( b3, t1, 0 )
					->tne( b1, b2, b3 )
					// OF = B0 & B1
					->mov( FLAG_OF, b0 )
					->band( FLAG_OF, b1 )

					// [rsp] := flags
					// [rsp+8] := t1
					->push( t1 )
					->pushf();
			}
		},
		{
			"VDIVU*",
			[ ] ( vtil::basic_block* fl, const arch::instruction& ins, uint8_t v )
			{
				auto& p = ins.parameters;
				auto [a0, a1, d, c] = fl->tmp( v * 8, v * 8, v * 8, v * 8 );

				fl
					// t0 := [rsp]
					// t1 := [rsp+*]
					// t2 := [rsp+2*]
					->pop( d ) // d
					->pop( a0 ) // a
					->pop( c ) // c
					->mov( a1, a0 )

					// div 
					->div( a0, d, c )
					->rem( a1, d, c )

					// [rsp] := flags
					// [rsp+8] := t0
					// [rsp+8+*] := t1
					->push( a0 )
					->push( a1 )
					->pushf();
			}
		},
		{
			"VMULU*",
			[ ] ( vtil::basic_block* fl, const arch::instruction& ins, uint8_t v )
			{
				auto& p = ins.parameters;
				auto [a0, a1, d] = fl->tmp( v * 8, v * 8, v * 8 );

				fl
					// t0 := [rsp]
					// t1 := [rsp+*]
					->pop( d ) // d
					->pop( a0 ) // a
					->mov( a1, a0 )

					// mul
					->mul( a0, d )
					->mulhi( a1, d )
					//->upflg( vtil::REG_FLAGS ) TODO

					// [rsp] := flags
					// [rsp+8] := t0
					// [rsp+8+*] := t1
					->push( a0 )
					->push( a1 )
					->pushf();
			}
		},
		{
			"VIDIVU*",
			[ ] ( vtil::basic_block* fl, const arch::instruction& ins, uint8_t v )
			{
				auto& p = ins.parameters;
				auto [a0, a1, d, c] = fl->tmp( v * 8, v * 8, v * 8, v * 8 );

				fl
					// t0 := [rsp]
					// t1 := [rsp+*]
					// t2 := [rsp+2*]
					->pop( d ) // d
					->pop( a0 ) // a
					->pop( c ) // c
					->mov( a1, a0 )

					// idiv 
					->idiv( a0, d, c )
					->irem( a1, d, c )

					// [rsp] := flags
					// [rsp+8] := t0
					// [rsp+8+*] := t1
					->push( a0 )
					->push( a1 )
					->pushf();
			}
		},
		{
			"VIMULU*",
			[ ] ( vtil::basic_block* fl, const arch::instruction& ins, uint8_t v )
			{
				auto& p = ins.parameters;
				auto [a0, a1, d] = fl->tmp( v * 8, v * 8, v * 8 );

				fl
					// t0 := [rsp]
					// t1 := [rsp+*]
					->pop( d ) // d
					->pop( a0 ) // a
					->mov( a1, a0 )

					// imul
					->imul( a0, d )
					->imulhi( a1, d )
					//->upflg( vtil::REG_FLAGS ) TODO
					->mov( FLAG_SF, vtil::UNDEFINED )
					->mov( FLAG_ZF, vtil::UNDEFINED )
					->mov( FLAG_OF, vtil::UNDEFINED )
					->mov( FLAG_CF, vtil::UNDEFINED )

					// [rsp] := flags
					// [rsp+8] := t0
					// [rsp+8+*] := t1
					->push( a0 )
					->push( a1 )
					->pushf();
			}
		},
		{
			"VNANDU*",
			[ ] ( vtil::basic_block* fl, const arch::instruction& ins, uint8_t v )
			{
				auto& p = ins.parameters;
				auto [t0, t1] = fl->tmp( v * 8, v * 8 );

				fl
					// t0 := [rsp]
					// t1 := [rsp+*]
					->pop( t0 )
					->pop( t1 )

					// t0 = nand(t0, t1)
					->bnot( t0 )
					->bnot( t1 )
					->bor( t0, t1 )
					//->upflg( vtil::REG_FLAGS ) TODO
					->tl( FLAG_SF, t0, 0 )
					->te( FLAG_ZF, t0, 0 )
					->mov( FLAG_OF, 0 )
					->mov( FLAG_CF, 0 )

					// [rsp] := flags
					// [rsp+8] := t0
					->push( t0 )
					->pushf();
			}
		},

		{
			"VNORU*",
			[ ] ( vtil::basic_block* fl, const arch::instruction& ins, uint8_t v )
			{
				auto& p = ins.parameters;
				auto [t0, t1] = fl->tmp( v * 8, v * 8 );

				fl
					// t0 := [rsp]
					// t1 := [rsp+*]
					->pop( t0 )
					->pop( t1 )

					// t0 = nor(t0, t1)
					->bnot( t0 )
					->bnot( t1 )
					->band( t0, t1 )
					//->upflg( vtil::REG_FLAGS ) TODO
					->tl( FLAG_SF, t0, 0 )
					->te( FLAG_ZF, t0, 0 )
					->mov( FLAG_OF, 0 )
					->mov( FLAG_CF, 0 )

					// [rsp] := flags
					// [rsp+8] := t0
					->push( t0 )
					->pushf();
			}
		},

		{
			"VSHRU*",
			[ ] ( vtil::basic_block* fl, const arch::instruction& ins, uint8_t v )
			{
				auto& p = ins.parameters;
				auto [t0, t1, t2] = fl->tmp( v * 8, v * 8, 8 );

				auto cf = t1;
				cf.bit_offset = cf.bit_count - 1;
				cf.bit_count = 1;

				auto ofx = t0;
				ofx.bit_offset = ofx.bit_count - 1;
				ofx.bit_count = 1;

				fl
					// t0 := [rsp]
					// t2 := [rsp+*]
					->pop( t0 )
					->pop( t2 )

					// t0 = t0 >> t2
					->mov( t1, t0 )
					->bshr( t0, t2 )
					//->upflg( vtil::REG_FLAGS ) TODO
					->tl( FLAG_SF, t0, 0 )
					->te( FLAG_ZF, t0, 0 )
					->mov( FLAG_OF, ofx )
					->mov( FLAG_CF, cf )
					->bxor( FLAG_OF, cf )

					// [rsp] := flags
					// [rsp+8] := t0
					->push( t0 )
					->pushf();
			}
		},

		{
			"VSHLU*",
			[ ] ( vtil::basic_block* fl, const arch::instruction& ins, uint8_t v )
			{
				auto& p = ins.parameters;
				auto [t0, t1, t2] = fl->tmp( v * 8, v * 8, 8 );

				auto cf = t1;
				cf.bit_offset = cf.bit_count - 1;
				cf.bit_count = 1;

				auto ofx = t0;
				ofx.bit_offset = ofx.bit_count - 1;
				ofx.bit_count = 1;

				fl
					// t0 := [rsp]
					// t1 := [rsp+*]
					->pop( t0 )
					->pop( t2 )

					// t0 = t0 << t1
					->mov( t1, t0 )
					->bshl( t0, t2 )
					//->upflg( vtil::REG_FLAGS ) TODO
					->tl( FLAG_SF, t0, 0 )
					->te( FLAG_ZF, t0, 0 )
					->mov( FLAG_OF, ofx )
					->mov( FLAG_CF, cf )
					->bxor( FLAG_OF, cf )

					// [rsp] := flags
					// [rsp+8] := t0
					->push( t0 )
					->pushf();
			}
		},

		{
			"VREADU*",
			[ ] ( vtil::basic_block* fl, const arch::instruction& ins, uint8_t v )
			{
				auto& p = ins.parameters;
				auto [t0, t1] = fl->tmp( 64, v * 8 );

				fl
					// t0 := [rsp]
					// t1 := [t0]
					// [rsp] := t1
					->pop( t0 );

				if ( ins.stream[ 1 ].prefix[ 1 ] == X86_PREFIX_GS )
				{
					fl  ->vemits( "mov rax, gs:0x30" )
					    ->vpinw( X86_REG_RAX )
						->add( t0, X86_REG_RAX );
				}
				else if ( ins.stream[ 1 ].prefix[ 1 ] == X86_PREFIX_FS )
				{
					unreachable();
				}

				fl  ->ldd( t1, t0, vtil::make_imm( 0ull ) )
					->push( t1 );
			}
		},
		{
			"VWRITEU*",
			[ ] ( vtil::basic_block* fl, const arch::instruction& ins, uint8_t v )
			{
				auto& p = ins.parameters;
				auto [t0, t1] = fl->tmp( 64, v * 8 );

				fl
					// t0 := [rsp]
					// t1 := [rsp+8]
					// [t0] := t1
					->pop( t0 )
					->pop( t1 );

				if ( ins.stream[ 3 ].prefix[ 1 ] == X86_PREFIX_GS )
				{
					fl  ->vemits( "mov rax, gs:0x30" )
						->vpinw( X86_REG_RAX )
						->add( t0, X86_REG_RAX );
				}
				else if ( ins.stream[ 3 ].prefix[ 1 ] == X86_PREFIX_FS )
				{
					unreachable();
				}

				fl  
					->str( t0, vtil::make_imm( 0ull ), t1 );
			}
		},
		{
			"VSETVSP",
			[ ] ( vtil::basic_block* fl, const arch::instruction& ins, uint8_t v )
			{
				auto& p = ins.parameters;
				fl
					// rsp := [rsp],
					->pop( vtil::REG_SP );
			}
		},

		{
			"VNOP",
			[ ] ( vtil::basic_block* fl, const arch::instruction& ins, uint8_t v )
			{
				auto& p = ins.parameters;
				fl
					// nop
					->nop();
			}
		},
		{
			"VJMP",
			[ ] ( vtil::basic_block* fl, const arch::instruction& ins, uint8_t v )
			{
				auto& p = ins.parameters;
				auto t0 = fl->tmp( 64 );

				fl
					// t0 := [rsp],
					->pop( t0 )

					// jmp t0
					->jmp( t0 );
			}
		},
		{
			"VEMIT",
			[ ] ( vtil::basic_block* fl, const arch::instruction& ins, uint8_t v )
			{
				auto& p = ins.parameters;

				for ( auto& instr : ins.stream.stream )
				{
					// Pin read registers
					//
					for ( uint16_t reg : instr.second.regs_read )
						if ( reg != X86_REG_RSP && reg != X86_REG_RIP && reg != X86_REG_EFLAGS )
							fl->vpinr( vtil::operand( x86_reg( reg ) ) );

					// Emit all bytes
					//
					for ( uint8_t byte : instr.second.bytes )
						fl->vemit( vtil::make_imm( byte ) );

					// Pin written registers
					//
					for ( uint16_t reg : instr.second.regs_write )
						if ( reg != X86_REG_RSP && reg != X86_REG_RIP && reg != X86_REG_EFLAGS )
							fl->vpinw( vtil::operand( x86_reg( reg ) ) );
				}
			}
		},
		{
			"VRDTSC",
			[ ] ( vtil::basic_block* fl, const arch::instruction& ins, uint8_t v )
			{
				auto& p = ins.parameters;
				fl
					// RDTSC
					->vemits( "rdtsc" )
					->vpinw( X86_REG_RDX )
					->vpinw( X86_REG_RAX )

					// [rsp + 4] := edx
					// [rsp] := eax
					->push( X86_REG_EAX )
					->push( X86_REG_EDX );
			}
		},
		{
			"VCPUID",
			[ ] ( vtil::basic_block* fl, const arch::instruction& ins, uint8_t v )
			{
				auto& p = ins.parameters;
				fl
					// eax := [rsp]
					->pop( X86_REG_EAX )

					// CPUID
					->vpinr( X86_REG_RCX )
					->vpinr( X86_REG_RAX )
					->vemits( "cpuid" )
					->vpinw( X86_REG_RDX )
					->vpinw( X86_REG_RCX )
					->vpinw( X86_REG_RBX )
					->vpinw( X86_REG_RAX )

					// [rsp] := edx
					// [rsp+4] := ecx
					// [rsp+8] := ebx
					// [rsp+C] := eax
					->push( X86_REG_EAX )
					->push( X86_REG_EBX )
					->push( X86_REG_ECX )
					->push( X86_REG_EDX );
			}
		},
		{
			"VCPUIDX",
			[ ] ( vtil::basic_block* fl, const arch::instruction& ins, uint8_t v )
			{
				auto& p = ins.parameters;
				fl
					// eax := [rsp]
					->pop( X86_REG_EAX )

					// CPUID
					->vpinr( X86_REG_RCX )
					->vpinr( X86_REG_RAX )
					->vemits( "cpuid" )
					->vpinw( X86_REG_RDX )
					->vpinw( X86_REG_RCX )
					->vpinw( X86_REG_RBX )
					->vpinw( X86_REG_RAX )

					// [rsp] := edx
					// [rsp+4] := ecx
					// [rsp+8] := ebx
					// [rsp+C] := eax
					->push( X86_REG_EAX )
					->push( X86_REG_EBX )
					->push( X86_REG_ECX )
					->push( X86_REG_EDX );
			}
		},
		{
			"VLOCKXCHGU*",
			[ ] ( vtil::basic_block* fl, const arch::instruction& ins, uint8_t v )
			{
				const char* reader =
					v == 8 ? "lock xchg qword ptr [rdx], rax" :
					v == 4 ? "lock xchg dword ptr [rdx], eax" :
					v == 2 ? "lock xchg word ptr [rdx], ax" :
					v == 1 ? "lock xchg byte ptr [rdx], al" : "";

				auto vr = vtil::amd64::registers.remap( X86_REG_RAX, 0, v );
				auto& p = ins.parameters;
				fl
					// rdx := [rsp]
					->pop( X86_REG_RDX )

					// reg := [rsp + 8]
					->pop( vr )

					// LOCK XCHG [RDX], reg
					->vpinr( X86_REG_RDX )
					->vpinr( X86_REG_RAX )
					->vemits( reader )
					->vpinw( X86_REG_RAX )

					// [rsp] := reg
					->push( vr );
			}
		},
		{
			"VSHRDU*",
			[ ] ( vtil::basic_block* fl, const arch::instruction& ins, uint8_t v )
			{
				auto& p = ins.parameters;
				auto [t0, t1, t2, t3] = fl->tmp( v * 8, v * 8, 8, 8 );

				auto [f0, f1] = fl->tmp( v * 8, v * 8 );

				fl
					// t0 := [rsp]
					// t1 := [rsp+*]
					// t2 := [rsp+2*]
					->pop( t0 )
					->pop( t1 )
					->pop( t2 )

					// t0 := t0 >> t2
					->bshr( t0, t2 )

					// t3 := v[0]*8
					// t3 -= t2
					->mov( t3, vtil::make_imm<uint8_t>( v * 8 ) )
					->sub( t3, t2 )

					// t1 := t1 << t3
					->bshl( t1, t3 )

					// t0 |= t1
					->bor( t0, t1 )
					//->upflg( vtil::REG_FLAGS ) TODO
					->tl( FLAG_SF, t0, 0 )
					->te( FLAG_ZF, t0, 0 )
					->mov( FLAG_OF, vtil::UNDEFINED )
					->mov( FLAG_CF, vtil::UNDEFINED )

					// [rsp+8] := t0
					->push( t0 )
					->pushf();
			}
		},
		{
			"VSHLDU*",
			[ ] ( vtil::basic_block* fl, const arch::instruction& ins, uint8_t v )
			{
				auto& p = ins.parameters;
				auto [t0, t1, t2, t3] = fl->tmp( v * 8, v * 8, 8, 8 );

				fl
					// t0 := [rsp]
					// t1 := [rsp+*]
					// t2 := [rsp+2*]
					->pop( t0 )
					->pop( t1 )
					->pop( t2 )

					// t0 := t0 >> t2
					->bshl( t0, t2 )

					// t3 := v[0]*8
					// t3 -= t2
					->mov( t3, vtil::make_imm<uint8_t>( v * 8 ) )
					->sub( t3, t2 )

					// t1 := t1 << t3
					->bshr( t1, t3 )

					// t0 |= t1
					->bor( t0, t1 )
					//->upflg( vtil::REG_FLAGS ) TODO
					->tl( FLAG_SF, t0, 0 )
					->te( FLAG_ZF, t0, 0 )
					->mov( FLAG_OF, vtil::UNDEFINED )
					->mov( FLAG_CF, vtil::UNDEFINED )

					// [rsp+8] := t0
					->push( t0 )
					->pushf();
			}
		},
		{
			"VPUSHCR0",
			[ ] ( vtil::basic_block* fl, const arch::instruction& ins, uint8_t v )
			{
				auto& p = ins.parameters;
				fl
					->vemits( "mov rax, cr0" )
					->vpinw( X86_REG_RAX )
					->push( X86_REG_RAX );
			}
		},
		{
			"VPUSHCR3",
			[ ] ( vtil::basic_block* fl, const arch::instruction& ins, uint8_t v )
			{
				auto& p = ins.parameters;
				fl
					->vemits( "mov rax, cr3" )
					->vpinw( X86_REG_RAX )
					->push( X86_REG_RAX );
			}
		},
	};

	void translate( vtil::basic_block* fl, const arch::instruction& ins )
	{
		for ( auto& converter : converters )
		{
			if ( converter.convert( fl, ins ) )
				return;
		}
		vtil::logger::error( "Failed converting:\n", ins.op.data() );
	}
};
