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
#include "architecture.hpp"
#include "subroutines.hpp"

namespace vmp::arch
{
	// Opcode descriptors
	//
	struct opcode_descriptor
	{
		std::vector<char> parameter_sizes = {};
		std::function<bool( vm_state*, instruction&, const std::vector<char>& )> matcher = 
			[ ] ( auto, auto&, auto& ) -> bool { return false; };
		std::function<void( vm_state*, instruction&, const std::vector<char>& )> adjust_matching =
			[ ] ( auto, auto&, auto& ) {};

		bool reduce( vm_state* vstate, instruction& ins, opcode_id identifier, const std::vector<char>& variants = {} )
		{
			// If parameter _count_ does not match, return failure right away
			//
			if ( ins.parameter_sizes.size() != parameter_sizes.size() ) return false;

			for ( int i = 0; i < parameter_sizes.size(); i++ )
			{
				// If parameter size does not match and it is not the generic variant
				// return failure
				//
				if ( parameter_sizes[ i ] != ins.parameter_sizes[ i ] &&
					 parameter_sizes[ i ] != PANY ) return false;
			}

			// If the opcode accepts variants
			//
			for ( char& c : identifier )
			{
				// Wildcard found:
				//
				if ( c == '*' )
				{
					// For each possible variant:
					//
					for ( char v : possible_variants )
					{
						// Try assigning the variant and reducing again
						//
						std::vector<char> variants_new = variants;
						variants_new.push_back( v );
						c = abbrv_param_size( v );
						if ( reduce( vstate, ins, identifier, variants_new ) )
							return true;
					}

					// Failed assigning the variant
					//
					return false;
				}
			}

			// If lambda pattern matcher reports failure, return rightaway
			//
			if ( !matcher( vstate, ins, variants ) ) return false;
			
			// Assign the identifier, adjust the instruction and indicate success
			//
			ins.op = identifier;
			adjust_matching( vstate, ins, variants );
			return true;
		}
	};

	// Some opcode matching helpers
	//
	static bool i_write_vsp( vm_state* vstate, const vtil::amd64::instruction& i, uint32_t offset, char variant )
	{
		return
			( variant == 1 ? i.id == X86_INS_MOV || i.id == X86_INS_MOVZX : i.id == X86_INS_MOV ) &&
			i.operands[ 0 ].type == X86_OP_MEM &&
			i.operands[ 0 ].mem.base == vstate->reg_vsp &&
			i.operands[ 0 ].mem.index == X86_REG_INVALID &&
			i.operands[ 0 ].mem.disp == offset;
	}

	static bool i_read_vsp( vm_state* vstate, const vtil::amd64::instruction& i, uint32_t offset, char variant )
	{
		return
			( variant == 1 ? i.id == X86_INS_MOV || i.id == X86_INS_MOVZX : i.id == X86_INS_MOV ) &&
			i.operands[ 1 ].type == X86_OP_MEM &&
			i.operands[ 1 ].mem.base == vstate->reg_vsp &&
			i.operands[ 1 ].mem.index == X86_REG_INVALID &&
			i.operands[ 1 ].mem.disp == offset;
	}

	static bool i_ref_vsp( vm_state* vstate, const vtil::amd64::instruction& i, uint32_t offset = 0 )
	{
		if ( !offset && 
			 i.id == X86_INS_MOV &&
			 i.operands[ 1 ].type == X86_OP_REG &&
			 i.operands[ 1 ].reg == vstate->reg_vsp )
		{
			return true;
		}

		return
			i.id == X86_INS_LEA &&
			i.operands[ 1 ].type == X86_OP_MEM &&
			i.operands[ 1 ].mem.base == vstate->reg_vsp &&
			i.operands[ 1 ].mem.index == X86_REG_INVALID &&
			i.operands[ 1 ].mem.disp == offset;
	}

	static bool i_shift_vsp( vm_state* vstate, const vtil::amd64::instruction& i, int32_t offset )
	{
		if ( ( abs( offset ) & 1 ) != 0 )
			return false;

		if ( offset > 0 )
		{
			return 
				i.id == X86_INS_ADD &&
				i.operands[ 0 ].type == X86_OP_REG &&
				i.operands[ 0 ].reg == vstate->reg_vsp &&
				i.operands[ 1 ].type == X86_OP_IMM &&
				i.operands[ 1 ].imm == offset;
		}
		else
		{
			return
				i.id == X86_INS_SUB &&
				i.operands[ 0 ].type == X86_OP_REG &&
				i.operands[ 0 ].reg == vstate->reg_vsp &&
				i.operands[ 1 ].type == X86_OP_IMM &&
				i.operands[ 1 ].imm == -offset;
		}
	}

	static bool i_loadc( vm_state* vstate, const vtil::amd64::instruction& i )
	{
		return i.mnemonic == "loadc";
	}

	static bool i_write_ctx( vm_state* vstate, const vtil::amd64::instruction& i, char variant, int32_t disp = 0 )
	{
		return
			( variant == 1 ? i.id == X86_INS_MOV || i.id == X86_INS_MOVZX : i.id == X86_INS_MOV ) &&
			i.operands[ 0 ].type == X86_OP_MEM &&
			i.operands[ 0 ].mem.base == X86_REG_RSP &&
			i.operands[ 0 ].mem.index != X86_REG_INVALID &&
			i.operands[ 0 ].mem.scale == 1 &&
			i.operands[ 0 ].mem.disp == disp &&
			( variant == 1 ? i.operands[ 1 ].size <= 2 : i.operands[ 1 ].size == variant );
	}

	static bool i_read_ctx( vm_state* vstate, const vtil::amd64::instruction& i, char variant, int32_t disp = 0 )
	{
		return
			( variant == 1 ? i.id == X86_INS_MOV || i.id == X86_INS_MOVZX : i.id == X86_INS_MOV ) &&
			i.operands[ 1 ].type == X86_OP_MEM &&
			i.operands[ 1 ].mem.base == X86_REG_RSP &&
			i.operands[ 1 ].mem.index != X86_REG_INVALID &&
			i.operands[ 1 ].mem.scale == 1 &&
			i.operands[ 1 ].mem.disp == disp &&
			( variant == 1 ? i.operands[ 1 ].size <= 2 : i.operands[ 1 ].size == variant );
	}

	static bool i_save_vsp_flags( vm_state* vstate, const vtil::amd64::instruction& i0, const vtil::amd64::instruction& i1, uint32_t offset = 0 )
	{
		return
			i0.id == X86_INS_PUSHFQ &&
			i1.id == X86_INS_POP &&
			i1.operands[ 0 ].type == X86_OP_MEM &&
			i1.operands[ 0 ].mem.base == vstate->reg_vsp &&
			i1.operands[ 0 ].mem.index == X86_REG_INVALID &&
			i1.operands[ 0 ].mem.disp == offset;
	}

	// Entire opcode table
	//
	std::map<opcode_id, opcode_descriptor> opcodes = 
	{
		// Unknown vmprotect instruction
		//
		{ "VUNK", {} },

		// Instructions executed as is
		//
		{ "VEXEC", {} },

		// -------------------------------------------------------------------

		/*
			# [Emits the whole instruction stream to the raw x86-64 stream]
			#
			# VEMIT()
		*/
		{ "VEMIT", { {} } },

		// -------------------------------------------------------------------

		/*
			# [Pop from user stack into virtual machine context]
			#
			# Pseudocode:
			# ----------------------------------------------
			#	tmp0		:= [VSP]
			#	VSP			+=	*
			#	VCTX[pos]	:=	tmp0
			# ----------------------------------------------
			#
			# VPOPV*(u1 pos)
		*/
		{ 
			"VPOPV*", 
			{
				{ 1 },

				[ ]( vm_state* vstate, instruction& vins, const std::vector<char>& var ) -> bool
				{
					auto& is = vins.stream; auto& ps = vins.parameter_sizes;
					uint8_t sz = var[ 0 ] == 1 ? 2 : var[ 0 ];

					return (is.size() == 4 &&

						// [[ 000000014000A8EE: mov  rcx, qword ptr [rsi]
						i_read_vsp( vstate, is[ 0 ], 0, var[ 0 ] ) &&

						// [[ 000000014000A8F1: add  rsi, 8
						i_shift_vsp( vstate, is[ 1 ], sz ) &&

						// [[ FFFFFFFFFFFFFFFF: loadc        dl, 16
						i_loadc( vstate, is[ 2 ] ) &&

						// [[ 000000014000A93B: mov  qword ptr [rsp + rdx], rcx
						i_write_ctx( vstate, is[ 3 ], var[ 0 ] ))

						||
						( is.size() == 4 &&

						  // [[ FFFFFFFFFFFFFFFF: loadc        dl, 16
						  i_loadc( vstate, is[ 0 ] ) &&

						  // [[ 000000014000A8EE: mov  rcx, qword ptr [rsi]
						  i_read_vsp( vstate, is[ 1 ], 0, var[ 0 ] ) &&

						  // [[ 000000014000A8F1: add  rsi, 8
						  i_shift_vsp( vstate, is[ 2 ], sz ) &&

						  // [[ 000000014000A93B: mov  qword ptr [rsp + rdx], rcx
						  i_write_ctx( vstate, is[ 3 ], var[ 0 ] ) );
				}
			}
		},

		/*
			# [Pop from user stack and discard]
			#
			# Pseudocode:
			# ----------------------------------------------
			#	VSP			+=	*
			# ----------------------------------------------
			#
			# VPOPD*()
		*/
		{ 
			"VPOPD*", 
			{
				{},

				[ ]( vm_state* vstate, instruction& vins, const std::vector<char>& var ) -> bool
				{
					auto& is = vins.stream; auto& ps = vins.parameter_sizes;
					return is.size() == 1 &&
						// [[ 000000014000A8F1: add  rsi, 8
						i_shift_vsp( vstate, is[ 0 ], +var[ 0 ] );
				}
			}
		},

		/*
			# [Push constant into user stack]
			#
			# Pseudocode:
			# ----------------------------------------------
			#	VSP			-=	*
			#	[VSP]		:=	const
			# ----------------------------------------------
			#
			# VPUSHC*(u* const)
		*/
		{
			"VPUSHC*",
			{
				{ PANY },

				[ ]( vm_state* vstate, instruction& vins, const std::vector<char>& var ) -> bool
				{
					auto& is = vins.stream; auto& ps = vins.parameter_sizes;
					uint8_t sz = var[ 0 ] == 1 ? 2 : var[ 0 ];

					return is.size() == 3 && 

						// [[ FFFFFFFFFFFFFFFF: loadc        rdi, 5368713486
						i_loadc( vstate, is[ 0 ] ) &&

						// [[ 0000000140062DBC: sub  rsi, 8
						i_shift_vsp( vstate, is[ 1 ], -sz ) &&

						// [[ 0000000140062DC9: mov  qword ptr [rsi], rdi
						i_write_vsp( vstate, is[ 2 ], 0, var[ 0 ] );
				}
			}
		},

		/*
			# [Push into user stack from virtual machine context]
			#
			# Pseudocode:
			# ----------------------------------------------
			#	t0			:=	VCTX[pos]
			#	VSP			-=	*
			#	[VSP]		:=	t0
			# ----------------------------------------------
			#
			# VPUSHV*(u8 pos)
		*/
		{
			"VPUSHV*",
			{
				{ 1 },

				[ ]( vm_state* vstate, instruction& vins, const std::vector<char>& var ) -> bool
				{
					auto& is = vins.stream; auto& ps = vins.parameter_sizes;
					uint8_t sz = var[ 0 ] == 1 ? 2 : var[ 0 ];

					return is.size() == 4 &&

						// [[ FFFFFFFFFFFFFFFF: loadc        dil, 40
						i_loadc( vstate, is[ 0 ] ) &&

						// [[ 000000014004AEFE: mov  rbp, qword ptr [rsp + rdi]
						i_read_ctx( vstate, is[ 1 ], var[ 0 ] ) &&

						// [[ 000000014004AF02: sub  rsi, 8
						i_shift_vsp( vstate, is[ 2 ], -sz ) &&

						// [[ 000000014004C3F6: mov  qword ptr [rsi], rbp
						i_write_vsp( vstate, is[ 3 ], 0, var[ 0 ] );
				}
			}
		},

		/*
			# [Push a reference to current user stack pointer to the user stack]
			#
			# Pseudocode:
			# ----------------------------------------------
			#	t0			:=	VSP
			#	VSP			-=	*
			#	[VSP]*		:=	t0
			# ----------------------------------------------
			#
			# VPUSHR()
		*/
		{
			"VPUSHR*",
			{
				{},

				[ ]( vm_state* vstate, instruction& vins, const std::vector<char>& var ) -> bool
				{
					auto& is = vins.stream; auto& ps = vins.parameter_sizes;

					return is.size() == 3 &&

						// [[ 0000000140035CF3: mov  rdx, rsi
						i_ref_vsp( vstate, is[ 0 ] ) &&

						// [[ 0000000140035CF9: sub  rsi, *
						i_shift_vsp( vstate, is[ 1 ], -var[ 0 ] ) &&

						// [[ 0000000140035D0D: mov  qword ptr [rsi], rdx
						i_write_vsp( vstate, is[ 2 ], 0, var[ 0 ] );
				}
			}
		},

		/*
			# [Adds two integers from user stack and overwrites them with the results of the operation]
			#
			# Pseudocode:
			# ----------------------------------------------
			#	t0			:=	[VSP]
			#	t1			:=	[VSP+*]
			#	VSP			+= (*-8)
			#	tr			:=	t0 + t1
			#	tf			:=	EFLAGS
			#	[VSP+8]		:=	tr
			#	[VSP]		:=	tf
			# ----------------------------------------------
			#
			# VADDU*()
		*/
		{
			"VADDU*",
			{
				{},

				[ ]( vm_state* vstate, instruction& vins, const std::vector<char>& var ) -> bool
				{
					auto& is = vins.stream; auto& ps = vins.parameter_sizes;
					int dt = var[ 0 ] == 8 ? 0 : 1;
					uint8_t sz = var[ 0 ] == 1 ? 2 : var[ 0 ];

					return is.size() == ( 6 + dt ) &&

						// [[ 00000001400EC455: mov  rax, qword ptr [rsi]
						i_read_vsp( vstate, is[ 0 ], 0, var[ 0 ] ) &&

						// [[ 00000001400EC462: mov  rcx, qword ptr [rsi + 8]
						i_read_vsp( vstate, is[ 1 ], sz, var[ 0 ] ) &&

						// [[ 00000001400DC64C: sub  rsi, 4
						( dt == 0 || i_shift_vsp( vstate, is[ 2 ], sz - 8 ) ) &&

						// [[ 00000001400EC46A: add  rax, rcx
						is[ 2 + dt ].id == X86_INS_ADD &&

						// [[ 00000001400EC46D: mov  qword ptr [rsi + 8], rax
						i_write_vsp( vstate, is[ 3 + dt ], +8, var[ 0 ] ) &&

						// [[ 00000001400F3782: pushfq
						// [[ 00000001400F3787: pop  qword ptr [rsi]
						i_save_vsp_flags( vstate, is[ 4 + dt ], is[ 5 + dt ] );
				}
			}
		},

		/*
			# [IMUL two integers from user stack and overwrite with the results]
			#
			# Pseudocode:
			# ----------------------------------------------
			#	*A			:=	[VSP+*]
			#	*D			:=	[VSP]
			#	VSP			-=	8
			#	IMUL(*D)
			#	[VSP+8]		:=	D
			#	[VSP+8+*]	:=	A
			#	[VSP]		:=	EFLAGS
			# ----------------------------------------------
			#
			# VIMULU*()
		*/
		{
			"VIMULU*",
			{
				{},

				[ ]( vm_state* vstate, instruction& vins, const std::vector<char>& var ) -> bool
				{
					auto& is = vins.stream; auto& ps = vins.parameter_sizes;
					uint8_t sz = var[ 0 ] == 1 ? 2 : var[ 0 ];

					return is.size() == 8 &&

						// [[ 00000001400FD732: mov  rax, qword ptr [r10 + 8]
						i_read_vsp( vstate, is[ 0 ], sz, var[ 0 ] ) &&
						vtil::amd64::registers.extend( is[ 0 ].operands[ 0 ].reg ) == X86_REG_RAX &&

						// [[ 00000001400FD740: mov  rdx, qword ptr [r10]
						i_read_vsp( vstate, is[ 1 ], 0, var[ 0 ] ) &&
						vtil::amd64::registers.extend( is[ 1 ].operands[ 0 ].reg ) == X86_REG_RDX &&
						
						// [[ 00000001400FD750: sub  r10, 8
						i_shift_vsp( vstate, is[ 2 ], -8 ) &&

						// [[ 00000001400FD75F: imul rdx
						is[ 3 ].is( X86_INS_IMUL, { X86_OP_REG } ) &&
						vtil::amd64::registers.extend( is[ 3 ].operands[ 0 ].reg ) == X86_REG_RDX &&

						// [[ 00000001400FD769: mov  qword ptr [r10 + 8], rdx
						i_write_vsp( vstate, is[ 4 ], +8, var[ 0 ] ) &&
						vtil::amd64::registers.extend( is[ 4 ].operands[ 1 ].reg ) == X86_REG_RDX &&

						// [[ 00000001400FD76D: mov  qword ptr [r10 + 0x10], rax
						i_write_vsp( vstate, is[ 5 ], +8 + sz, var[ 0 ] ) &&
						vtil::amd64::registers.extend( is[ 5 ].operands[ 1 ].reg ) == X86_REG_RAX &&

						// [[ 00000001400FD778: pushfq
						// [[ 00000001400FD779: pop  qword ptr [r10]
						i_save_vsp_flags( vstate, is[ 6 ], is[ 7 ] );
				}
			}
		},

		/*
			# [IDIV two integers from user stack and overwrite with the results]
			#
			# Pseudocode:
			# ----------------------------------------------
			#	*A			:=	[VSP+*]
			#	*D			:=	[VSP]
			#	VSP			-=	8
			#	IDIV(*D)
			#	[VSP+8]		:=	D
			#	[VSP+8+*]	:=	A
			#	[VSP]		:=	EFLAGS
			# ----------------------------------------------
			#
			# VIDIVU*()
		*/
		{
			"VIDIVU*",
			{
				{},

				[ ]( vm_state* vstate, instruction& vins, const std::vector<char>& var ) -> bool
				{
					auto& is = vins.stream; auto& ps = vins.parameter_sizes;
					int dt = var[ 0 ] == 8 ? 0 : 1;
					uint8_t sz = var[ 0 ] == 1 ? 2 : var[ 0 ];

					return is.size() == ( 8 + dt ) &&

						// [[ 00000001400FD732: mov  rax, qword ptr [r10 + 8]
						i_read_vsp( vstate, is[ 0 ], sz, var[ 0 ] ) &&
						vtil::amd64::registers.extend( is[ 0 ].operands[ 0 ].reg ) == X86_REG_RAX &&

						// [[ 00000001400FD740: mov  rdx, qword ptr [r10]
						i_read_vsp( vstate, is[ 1 ], 0, var[ 0 ] ) &&
						vtil::amd64::registers.extend( is[ 1 ].operands[ 0 ].reg ) == X86_REG_RDX &&

						// 0000000140028C61: mov  rcx, qword ptr [r9 + 0x10]
						i_read_vsp( vstate, is[ 2 ], sz * 2, var[ 0 ] ) &&
						
						// [[ 00000001400FD750: sub  r10, 8
						( !dt || i_shift_vsp( vstate, is[ 3 ], sz - 8 ) ) &&

						// [[ 00000001400FD75F: idiv rcx
						is[ 3 + dt ].is( X86_INS_IDIV, { X86_OP_REG } ) &&

						// [[ 00000001400FD769: mov  qword ptr [r10 + 8], rdx
						i_write_vsp( vstate, is[ 4 + dt ], +8, var[ 0 ] ) &&
						vtil::amd64::registers.extend( is[ 4 + dt ].operands[ 1 ].reg ) == X86_REG_RDX &&

						// [[ 00000001400FD76D: mov  qword ptr [r10 + 0x10], rax
						i_write_vsp( vstate, is[ 5 + dt ], +8 + sz, var[ 0 ] ) &&
						vtil::amd64::registers.extend( is[ 5 + dt ].operands[ 1 ].reg ) == X86_REG_RAX &&

						// [[ 00000001400FD778: pushfq
						// [[ 00000001400FD779: pop  qword ptr [r10]
						i_save_vsp_flags( vstate, is[ 6 + dt ], is[ 7 + dt ] );
				}
			}
		},

		/*
			# [MUL two integers from user stack and overwrite with the results]
			#
			# Pseudocode:
			# ----------------------------------------------
			#	*A			:=	[VSP+*]
			#	*D			:=	[VSP]
			#	VSP			-=	8
			#	MUL(*D)
			#	[VSP+8]		:=	D
			#	[VSP+8+*]	:=	A
			#	[VSP]		:=	EFLAGS
			# ----------------------------------------------
			#
			# VMULU*()
		*/
		{
			"VMULU*",
			{
				{},

				[ ]( vm_state* vstate, instruction& vins, const std::vector<char>& var ) -> bool
				{
					auto& is = vins.stream; auto& ps = vins.parameter_sizes;
					uint8_t sz = var[ 0 ] == 1 ? 2 : var[ 0 ];

					return is.size() == 8 &&

						// [[ 00000001400FD732: mov  rax, qword ptr [r10 + 8]
						i_read_vsp( vstate, is[ 0 ], +sz, var[ 0 ] ) &&
						vtil::amd64::registers.extend( is[ 0 ].operands[ 0 ].reg ) == X86_REG_RAX &&

						// [[ 00000001400FD740: mov  rdx, qword ptr [r10]
						i_read_vsp( vstate, is[ 1 ], 0, var[ 0 ] ) &&
						vtil::amd64::registers.extend( is[ 1 ].operands[ 0 ].reg ) == X86_REG_RDX &&
						
						// [[ 00000001400FD750: sub  r10, 8
						i_shift_vsp( vstate, is[ 2 ], -8 ) &&

						// [[ 00000001400FD75F: MUL rdx
						is[ 3 ].is( X86_INS_MUL, { X86_OP_REG } ) &&
						vtil::amd64::registers.extend( is[ 3 ].operands[ 0 ].reg ) == X86_REG_RDX &&

						// [[ 00000001400FD769: mov  qword ptr [r10 + 8], rdx
						i_write_vsp( vstate, is[ 4 ], +8, var[ 0 ] ) &&
						vtil::amd64::registers.extend( is[ 4 ].operands[ 1 ].reg ) == X86_REG_RDX &&

						// [[ 00000001400FD76D: mov  qword ptr [r10 + 0x10], rax
						i_write_vsp( vstate, is[ 5 ], +8 + sz, var[ 0 ] ) &&
						vtil::amd64::registers.extend( is[ 5 ].operands[ 1 ].reg ) == X86_REG_RAX &&

						// [[ 00000001400FD778: pushfq
						// [[ 00000001400FD779: pop  qword ptr [r10]
						i_save_vsp_flags( vstate, is[ 6 ], is[ 7 ] );
				}
			}
		},

		/*
			# [DIV two integers from user stack and overwrite with the results]
			#
			# Pseudocode:
			# ----------------------------------------------
			#	*A			:=	[VSP+*]
			#	*D			:=	[VSP]
			#	VSP			-=	8
			#	DIV(*D)
			#	[VSP+8]		:=	D
			#	[VSP+8+*]	:=	A
			#	[VSP]		:=	EFLAGS
			# ----------------------------------------------
			#
			# VDIVU*()
		*/
		{
			"VDIVU*",
			{
				{},

				[ ]( vm_state* vstate, instruction& vins, const std::vector<char>& var ) -> bool
				{
					auto& is = vins.stream; auto& ps = vins.parameter_sizes;
					int dt = var[ 0 ] == 8 ? 0 : 1;
					uint8_t sz = var[ 0 ] == 1 ? 2 : var[ 0 ];

					return is.size() == ( 8 + dt ) &&

						// [[ 00000001400FD732: mov  rax, qword ptr [r10 + 8]
						i_read_vsp( vstate, is[ 0 ], sz, var[ 0 ] ) &&
						vtil::amd64::registers.extend( is[ 0 ].operands[ 0 ].reg ) == X86_REG_RAX &&

						// [[ 00000001400FD740: mov  rdx, qword ptr [r10]
						i_read_vsp( vstate, is[ 1 ], 0, var[ 0 ] ) &&
						vtil::amd64::registers.extend( is[ 1 ].operands[ 0 ].reg ) == X86_REG_RDX &&

						// 0000000140028C61: mov  rcx, qword ptr [r9 + 0x10]
						i_read_vsp( vstate, is[ 2 ], sz * 2, var[ 0 ] ) &&
						
						// [[ 00000001400FD750: sub  r10, 8
						( !dt || i_shift_vsp( vstate, is[ 3 ], sz - 8 ) ) &&

						// [[ 00000001400FD75F: div rcx
						is[ 3 + dt ].is( X86_INS_DIV, { X86_OP_REG } ) &&

						// [[ 00000001400FD769: mov  qword ptr [r10 + 8], rdx
						i_write_vsp( vstate, is[ 4 + dt ], 8, var[ 0 ] ) &&
						vtil::amd64::registers.extend( is[ 4 + dt ].operands[ 1 ].reg ) == X86_REG_RDX &&

						// [[ 00000001400FD76D: mov  qword ptr [r10 + 0x10], rax
						i_write_vsp( vstate, is[ 5 + dt ], 8 + sz, var[ 0 ] ) &&
						vtil::amd64::registers.extend( is[ 5 + dt ].operands[ 1 ].reg ) == X86_REG_RAX &&

						// [[ 00000001400FD778: pushfq
						// [[ 00000001400FD779: pop  qword ptr [r10]
						i_save_vsp_flags( vstate, is[ 6 + dt ], is[ 7 + dt ] );
				}
			}
		},

		/*
			# [NAND two integers from user stack and overwrites them with the results of the operation]
			#
			# Pseudocode:
			# ----------------------------------------------
			#	t0			:=	[VSP]
			#	t1			:=	[VSP+*]
			#	t1			:=	~t0
			#	t1			:=	~t1
			#	tr			:=	t0 & t1
			#	tf			:=	EFLAGS
			#	[VSP+8]		:=	tr
			#	[VSP]		:=	tf
			# ----------------------------------------------
			#
			# VNORU*()
		*/
		{
			"VNORU*",
			{
				{},

				[ ]( vm_state* vstate, instruction& vins, const std::vector<char>& var ) -> bool
				{
					auto& is = vins.stream; auto& ps = vins.parameter_sizes;
					int dt = var[ 0 ] == 8 ? 0 : 1;
					uint8_t sz = var[ 0 ] == 1 ? 2 : var[ 0 ];

					return is.size() == ( 8 + dt ) &&

						// [[ 00000001400E37DD: mov  rax, qword ptr [rbp]
						i_read_vsp( vstate, is[ 0 ], 0, var[ 0 ] ) &&

						// [[ 00000001400E37E7: mov  r10, qword ptr [rbp + 8]
						i_read_vsp( vstate, is[ 1 ], sz, var[ 0 ] ) &&

						// [[ 00000001400DC64C: sub  rsi, 4
						( dt == 0 || i_shift_vsp( vstate, is[ 2 ], sz - 8 ) ) &&

						// [[ 00000001400E37F1: not  rax
						is[ 2 + dt ].id == X86_INS_NOT &&

						// [[ 00000001400E37F8: not  r10
						is[ 3 + dt ].id == X86_INS_NOT &&

						// [[ 00000001400E37FE: and  rax, r10
						is[ 4 + dt ].id == X86_INS_AND &&

						// [[ 00000001400EC46D: mov  qword ptr [rsi + 8], rax
						i_write_vsp( vstate, is[ 5 + dt ], 8, var[ 0 ] ) &&

						// [[ 00000001400E381E: pushfq
						// [[ 00000001400E381F: pop  qword ptr [rbp]
						i_save_vsp_flags( vstate, is[ 6 + dt ], is[ 7 + dt ] );
				}
			}
		},

		/*
			# [NOR two integers from user stack and overwrites them with the results of the operation]
			#
			# Pseudocode:
			# ----------------------------------------------
			#	t0			:=	[VSP]
			#	t1			:=	[VSP+*]
			#	t1			:=	~t0
			#	t1			:=	~t1
			#	tr			:=	t0 | t1
			#	tf			:=	EFLAGS
			#	[VSP+8]		:=	tr
			#	[VSP]		:=	tf
			# ----------------------------------------------
			#
			# VNANDU*()
		*/
		{
			"VNANDU*",
			{
				{},

				[ ]( vm_state* vstate, instruction& vins, const std::vector<char>& var ) -> bool
				{
					auto& is = vins.stream; auto& ps = vins.parameter_sizes;
					int dt = var[ 0 ] == 8 ? 0 : 1;
					uint8_t sz = var[ 0 ] == 1 ? 2 : var[ 0 ];

					return is.size() == ( 8 + dt ) &&

						// [[ 00000001400E37DD: mov  rax, qword ptr [rbp]
						i_read_vsp( vstate, is[ 0 ], 0, var[ 0 ] ) &&

						// [[ 00000001400E37E7: mov  r10, qword ptr [rbp + 8]
						i_read_vsp( vstate, is[ 1 ], sz, var[ 0 ] ) &&

						// [[ 00000001400DC64C: sub  rsi, 4
						( dt == 0 || i_shift_vsp( vstate, is[ 2 ], sz - 8 ) ) &&

						// [[ 00000001400E37F1: not  rax
						is[ 2 + dt ].id == X86_INS_NOT &&

						// [[ 00000001400E37F8: not  r10
						is[ 3 + dt ].id == X86_INS_NOT &&

						// [[ 00000001400E37FE: and  rax, r10
						is[ 4 + dt ].id == X86_INS_OR &&

						// [[ 00000001400EC46D: mov  qword ptr [rsi + 8], rax
						i_write_vsp( vstate, is[ 5 + dt ], 8, var[ 0 ] ) &&

						// [[ 00000001400E381E: pushfq
						// [[ 00000001400E381F: pop  qword ptr [rbp]
						i_save_vsp_flags( vstate, is[ 6 + dt ], is[ 7 + dt ] );
				}
			}
		},

		/*
			# [Shifts ST[0]* right by ST[1]w and writes the results on top of the stack]
			#
			# Pseudocode:
			# ----------------------------------------------
			#	t0			:=	[VSP]
			#	t1			:=	[VSP+*]w
			#	VSP			-=  6
			#	tr			:=	t0 >> t1
			#	[VSP+8]		:=	tr
			#	[VSP]		:=	tf
			# ----------------------------------------------
			#
			# VSHRU*()
		*/
		{
			"VSHRU*",
			{
				{},

				[ ]( vm_state* vstate, instruction& vins, const std::vector<char>& var ) -> bool
				{
					auto& is = vins.stream; auto& ps = vins.parameter_sizes;
					uint8_t sz = var[ 0 ] == 1 ? 2 : var[ 0 ];

					return is.size() == 7 &&

						// [[ 000000014003649E: mov  rdi, qword ptr [rbp]
						i_read_vsp( vstate, is[ 0 ], 0, var[ 0 ] ) &&

						// [[ 00000001400364A6: mov  cl, byte ptr [rbp + 8]
						i_read_vsp( vstate, is[ 1 ], sz, 2 ) &&

						// [[ 00000001400364AD: sub  rbp, 6
						i_shift_vsp( vstate, is[ 2 ], -6 ) &&

						// [[ 00000001400364B4: shr  rdi, cl
						is[ 3 ].id == X86_INS_SHR &&

						// 00000001400510DE: mov  qword ptr [rbp + 8], rdi
						i_write_vsp( vstate, is[ 4 ], 8, var[ 0 ] ) &&

						// [[ 00000001400E381E: pushfq
						// [[ 00000001400E381F: pop  qword ptr [rbp]
						i_save_vsp_flags( vstate, is[ 5 ], is[ 6 ] );
				}
			}
		},

		/*
			# [Shifts ST[0]* left by ST[1]w and writes the results on top of the stack]
			#
			# Pseudocode:
			# ----------------------------------------------
			#	t0			:=	[VSP]
			#	t1			:=	[VSP+*]w
			#	VSP			-=  6
			#	tr			:=	t0 << t1
			#	[VSP+8]		:=	tr
			#	[VSP]		:=	tf
			# ----------------------------------------------
			#
			# VSHLU*()
		*/
		{
			"VSHLU*",
			{
				{},

				[ ]( vm_state* vstate, instruction& vins, const std::vector<char>& var ) -> bool
				{
					auto& is = vins.stream; auto& ps = vins.parameter_sizes;
					uint8_t sz = var[ 0 ] == 1 ? 2 : var[ 0 ];

					return is.size() == 7 &&

						// [[ 000000014003649E: mov  rdi, qword ptr [rbp]
						i_read_vsp( vstate, is[ 0 ], 0, var[ 0 ] ) &&

						// [[ 00000001400364A6: mov  cl, byte ptr [rbp + 8]
						i_read_vsp( vstate, is[ 1 ], sz, 2 ) &&

						// [[ 00000001400364AD: sub  rbp, 6
						i_shift_vsp( vstate, is[ 2 ], -6 ) &&

						// [[ 00000001400364B4: shr  rdi, cl
						is[ 3 ].id == X86_INS_SHL &&

						// 00000001400510DE: mov  qword ptr [rbp + 8], rdi
						i_write_vsp( vstate, is[ 4 ], 8, var[ 0 ] ) &&

						// [[ 00000001400E381E: pushfq
						// [[ 00000001400E381F: pop  qword ptr [rbp]
						i_save_vsp_flags( vstate, is[ 5 ], is[ 6 ] );
				}
			}
		},

		/*
			# [SHRD and write the results on top of the stack]
			#
			# Pseudocode:
			# ----------------------------------------------
			#	t0			:=	[VSP]
			#	t1			:=	[VSP+*]
			#	t2			:=	[VSP+2*]b (but kinda treated like WORD because yea whatever LOL)
			#	VSP			+=  (*-6)
			#	SHRD(t0, t1, t2)
			#	[VSP+8]		:=	t0
			#	[VSP]		:=	tf
			# ----------------------------------------------
			#
			# VSHRDU*()
		*/
		{
			"VSHRDU*",
			{
				{},

				[ ]( vm_state* vstate, instruction& vins, const std::vector<char>& var ) -> bool
				{
					auto& is = vins.stream; auto& ps = vins.parameter_sizes;
					uint8_t sz = var[ 0 ] == 1 ? 2 : var[ 0 ];

					return is.size() == 8 &&

						// [[ 000000014002B10C: mov  r10, qword ptr [r9]
						i_read_vsp( vstate, is[ 0 ], 0, var[ 0 ] ) &&

						// [[ 000000014002B115: mov  rdi, qword ptr [r9 + 8]
						i_read_vsp( vstate, is[ 1 ], sz, var[ 0 ] ) &&

						// [[ 000000014002B119: mov  cl, byte ptr [r9 + 0x10]
						i_read_vsp( vstate, is[ 2 ], sz * 2, 2 ) &&

						// [[ 0000000140089097: add  r9, 2
						i_shift_vsp( vstate, is[ 3 ], sz - 6 ) &&

						// [[ 00000001400364B4: shrd  r10, rdi, cl
						is[ 4 ].id == X86_INS_SHRD &&

						// [[ 00000001400890AB: mov  qword ptr [r9 + 8], r10
						i_write_vsp( vstate, is[ 5 ], 8, var[ 0 ] ) &&

						// [[ 00000001400E381E: pushfq
						// [[ 00000001400E381F: pop  qword ptr [rbp]
						i_save_vsp_flags( vstate, is[ 6 ], is[ 7 ] );
				}
			}
		},

		/*
			# [SHLD and write the results on top of the stack]
			#
			# Pseudocode:
			# ----------------------------------------------
			#	t0			:=	[VSP]
			#	t1			:=	[VSP+*]
			#	t2			:=	[VSP+2*]b (but kinda treated like WORD because yea whatever LOL)
			#	VSP			+=  (*-6)
			#	SHLD(t0, t1, t2)
			#	[VSP+8]		:=	t0
			#	[VSP]		:=	tf
			# ----------------------------------------------
			#
			# VSHLDU*()
		*/
		{
			"VSHLDU*",
			{
				{},

				[ ]( vm_state* vstate, instruction& vins, const std::vector<char>& var ) -> bool
				{
					auto& is = vins.stream; auto& ps = vins.parameter_sizes;
					uint8_t sz = var[ 0 ] == 1 ? 2 : var[ 0 ];

					return is.size() == 8 &&

						// [[ 000000014002B10C: mov  r10, qword ptr [r9]
						i_read_vsp( vstate, is[ 0 ], 0, var[ 0 ] ) &&

						// [[ 000000014002B115: mov  rdi, qword ptr [r9 + 8]
						i_read_vsp( vstate, is[ 1 ], sz, var[ 0 ] ) &&

						// [[ 000000014002B119: mov  cl, byte ptr [r9 + 0x10]
						i_read_vsp( vstate, is[ 2 ], sz * 2, 2 ) &&

						// [[ 0000000140089097: add  r9, 2
						i_shift_vsp( vstate, is[ 3 ], sz - 6 ) &&

						// [[ 00000001400364B4: shrd  r10, rdi, cl
						is[ 4 ].id == X86_INS_SHLD &&

						// [[ 00000001400890AB: mov  qword ptr [r9 + 8], r10
						i_write_vsp( vstate, is[ 5 ], 8, var[ 0 ] ) &&

						// [[ 00000001400E381E: pushfq
						// [[ 00000001400E381F: pop  qword ptr [rbp]
						i_save_vsp_flags( vstate, is[ 6 ], is[ 7 ] );
				}
			}
		},

		/*
			# [Dereferences the top user stack entry and replaces it with the value]
			#
			# Pseudocode:
			# ----------------------------------------------
			#	t0			:=	[VSP]
			#	[VSP]		:=	[t0]
			# ----------------------------------------------
			#
			# VREADU*()
		*/
		{
			"VREADU*",
			{
				{},

				[ ]( vm_state* vstate, instruction& vins, const std::vector<char>& var ) -> bool
				{
					auto& is = vins.stream; auto& ps = vins.parameter_sizes;
					int dt = var[ 0 ] == 8 ? 0 : 1;
					uint8_t sz = var[ 0 ] == 1 ? 2 : var[ 0 ];

					return is.size() == ( 3 + dt ) &&

						// [[ 0000000140038C8B: mov  rdi, qword ptr [rsi]
						i_read_vsp( vstate, is[ 0 ], 0, 8 ) &&

						// [[ 0000000140038C90: mov  rdx, qword ptr ss:[rdi]
						( is[ 1 ].id == X86_INS_MOV || is[ 1 ].id == X86_INS_MOVZX ) &&
						is[ 1 ].operands[ 1 ].type == X86_OP_MEM &&
						is[ 1 ].operands[ 1 ].mem.index == X86_REG_INVALID &&
						is[ 1 ].operands[ 1 ].mem.disp == 0 &&
						is[ 1 ].operands[ 1 ].size == var[ 0 ] &&

						// [[ 000000014005EB12: add  rsi, 4
						( dt == 0 || i_shift_vsp( vstate, is[ 2 ], 8 - sz ) ) &&

						// [[ 0000000140038C97: mov  qword ptr [rsi], rdx
						i_write_vsp( vstate, is[ 2 + dt ], 0 , var[ 0 ] );
				}
			}
		},

		/*
			# [Pops a pointer from user stack, pops a u* from the stack and writes it into the pointer]
			#
			# Pseudocode:
			# ----------------------------------------------
			#	t0			:=	[VSP]
			#	t1			:=	[VSP+8]
			#	VSP			+=	*
			#	[t0]		:=	t1
			# ----------------------------------------------
			#
			# VWRITEU*()
		*/
		{
			"VWRITEU*",
			{
				{},

				[ ]( vm_state* vstate, instruction& vins, const std::vector<char>& var ) -> bool
				{
					auto& is = vins.stream; auto& ps = vins.parameter_sizes;

					return is.size() == 4 &&

						// [[ 00000001400E16C9: mov  rbp, qword ptr [rsi]
						i_read_vsp( vstate, is[ 0 ], 0, 8 ) &&

						// [[ 00000001400E16CF: mov  r9, qword ptr [rsi + 8]
						i_read_vsp( vstate, is[ 1 ], 8, var[ 0 ] ) &&

						// [[ 00000001400E16DE: add  rsi, 0x10
						i_shift_vsp( vstate, is[ 2 ], 0x8 + var[ 0 ] ) &&

						// [[ 00000001400E16E8: mov  qword ptr [rbp], r9
						is[ 3 ].id == X86_INS_MOV &&
						is[ 3 ].operands[ 0 ].type == X86_OP_MEM &&
						is[ 3 ].operands[ 0 ].mem.index == X86_REG_INVALID &&
						is[ 3 ].operands[ 0 ].mem.disp == 0;
				}
			}
		},

		/*
			# [LOCK XCHG the pointer on top of the stack with the value on top of that, discard the pointer]
			#
			# Pseudocode:
			# ----------------------------------------------
			#	t0			:=	[VSP]
			#	t1			:=	[VSP+8]
			#	VSP			+=	8
			#	LOCK XCHG [t0],	t1
			#   [VSP]		:=	t1
			# ----------------------------------------------
			#
			# VLOCKXCHGU*()
		*/
		{
			"VLOCKXCHGU*",
			{
				{},

				[ ]( vm_state* vstate, instruction& vins, const std::vector<char>& var ) -> bool
				{
					auto& is = vins.stream; auto& ps = vins.parameter_sizes;
					uint8_t sz = var[ 0 ] == 1 ? 2 : var[ 0 ];

					return is.size() == 5 &&

						// [[ 00000001400E6751: mov  rdi, qword ptr [r11]
						i_read_vsp( vstate, is[ 0 ], 0, 8 ) &&

						// [[ 00000001400EBF4E: mov  edx, dword ptr [r11 + 8]
						i_read_vsp( vstate, is[ 1 ], 8, var[ 0 ] ) &&

						// [[ 00000001400EBF52: add  r11, 8
						i_shift_vsp( vstate, is[ 2 ], 8 ) &&

						// [[ 00000001400EBF5E: lock xchg    dword ptr [rdi], edx
						is[ 3 ].id == X86_INS_XCHG &&

						// [[ 00000001400EBF65: mov  dword ptr [r11], edx
						i_write_vsp( vstate, is[ 4 ], 0, var[ 0 ] );
				}
			}
		},

		/*
			# [Pop CPUID branch from the top of the stack and push output]
			#
			# Pseudocode:
			# ----------------------------------------------
			#   br			:=  [VSP]
			#   CPUID(br)
			#   VSP			-=	0xC
			#	[VSP+0]		=	EDX
			#	[VSP+4]		=	ECX
			#	[VSP+8]		=	EBX
			#	[VSP+C]		=	EAX
			# ----------------------------------------------
			#
			# VCPUID()
		*/
		{
			"VCPUID",
			{
				{},

				[ ]( vm_state* vstate, instruction& vins, const std::vector<char>& var ) -> bool
				{
					auto& is = vins.stream; auto& ps = vins.parameter_sizes;

					return is.size() == 7 &&

						// [[ 00007FFB7243D10D: mov  eax, dword ptr [rdi]
						i_read_vsp( vstate, is[ 0 ], 0, 4 ) &&

						// [[ 00007FFB7243D117: cpuid
						is[ 1 ].id == X86_INS_CPUID &&

						// [[ 00007FFB7243D121: sub  rdi, 0xc
						i_shift_vsp( vstate, is[ 2 ], -0xC ) &&

						// [[ 00007FFB7243D133: mov  dword ptr [rdi + 0xc], eax
						i_write_vsp( vstate, is[ 3 ], 0xC, 4 ) &&

						// [[ 00007FFB7243D13F: mov  dword ptr [rdi + 8], ebx
						i_write_vsp( vstate, is[ 4 ], 0x8, 4 ) &&

						// [[ 00007FFB7243D142: mov  dword ptr [rdi + 4], ecx
						i_write_vsp( vstate, is[ 5 ], 0x4, 4 ) &&

						// [[ 00007FFB7243D14A: mov  dword ptr [rdi], edx
						i_write_vsp( vstate, is[ 6 ], 0x0, 4 );
				}
			}
		},

		/*
			# [Pop CPUID branch from the top of the stack and push output]
			#
			# Pseudocode:
			# ----------------------------------------------
			#   br			:=  [VSP]
			#   CPUID(br)
			#   VSP			-=	0xC
			#	[VSP+0]		=	EDX
			#	[VSP+4]		=	ECX
			#	[VSP+8]		=	EBX
			#	[VSP+C]		=	EAX
			# ----------------------------------------------
			#
			# VCPUIDX()
		*/
		{
			"VCPUIDX",
			{
				{},

				[ ]( vm_state* vstate, instruction& vins, const std::vector<char>& var ) -> bool
				{
					auto& is = vins.stream; auto& ps = vins.parameter_sizes;
					/* (Special case when stack pointer is at RAX|RBX|RCX|RDX)
					Failed to clasify the instruction:
					00000000002C7B83: mov   eax, dword ptr [rbx]
					00000000002C7B8D: mov   rdi, rbx
					00000000002C7BA4: cpuid
					00000000002C7BA6: sub   rdi, 0xc
					0000000000283DF8: mov   dword ptr [rdi + 0xc], eax
					00000000003C47C3: mov   dword ptr [rdi + 8], ebx
					00000000003C47CE: mov   dword ptr [rdi + 4], ecx
					00000000003C47D8: mov   dword ptr [rdi], edx
					00000000003C47E7: mov   rbx, rdi
					*/
					return is.size() == 9 &&

						// [[ 00007FFB7243D10D: mov  eax, dword ptr [rdi]
						i_read_vsp( vstate, is[ 0 ], 0, 4 ) &&

						// [[ 00007FFB7243D117: cpuid
						is[ 2 ].id == X86_INS_CPUID;
				},

				[ ]( auto*, instruction& i, auto& ) { i.stack_delta = -0xC; }
			}
		},

		/*
			# [Execute RDTSC and push output]
			#
			# Pseudocode:
			# ----------------------------------------------
			#   RDTSC()
			#   VSP			-=	0x8
			#	[VSP+0]		=	EDX
			#	[VSP+8]		=	EAX
			# ----------------------------------------------
			#
			# VRDTSC()
		*/
		{
			"VRDTSC",
			{
				{},

				[ ]( vm_state* vstate, instruction& vins, const std::vector<char>& var ) -> bool
				{
					auto& is = vins.stream; auto& ps = vins.parameter_sizes;

					return is.size() == 4 &&

						// [[ 0000000140095243: rdtsc
						is[ 0 ].id == X86_INS_RDTSC &&

						// [[ 0000000140095245: sub  r10, 8
						i_shift_vsp( vstate, is[ 1 ], -0x8 ) &&

						// [[ 000000014009524C: mov  dword ptr [r10], edx
						i_write_vsp( vstate, is[ 2 ], 0, 4 ) &&

						// [[ 0000000140095259: mov  dword ptr [r10 + 4], eax
						i_write_vsp( vstate, is[ 3 ], 4, 4 );
				}
			}
		},

		/*
			# [Pop new stack pointer value from top of the stack and replace VSP]
			#
			# Pseudocode:
			# ----------------------------------------------
			#   t0			:=  [VSP]
			#   VSP			=	t0		# Not visible in instruction stream beacuse it's below JA
			# ----------------------------------------------
			#
			# VSETVSP()
		*/
		{
			"VSETVSP",
			{
				{},

				[ ]( vm_state* vstate, instruction& vins, const std::vector<char>& var ) -> bool
				{
					auto& is = vins.stream; auto& ps = vins.parameter_sizes;

					return is.size() == 1 &&

						// [[ 00007FFB7246A04F: mov r10, qword ptr [r10]
						i_read_vsp( vstate, is[ 0 ], 0, 8 ) &&
						is[ 0 ].operands[ 0 ].type == X86_OP_REG &&
						is[ 0 ].operands[ 0 ].reg == vstate->reg_vsp;
				},

				// Reflect the side effects of VSP=UNK (See note about the missing instruction above)
				//
				[ ] ( auto*, instruction& i, auto& ) { i.stack_delta = unknown_delta; }
			}
		},

		/*
			# [Pop VIP from the top of the stack and continue execution]
			#
			# Pseudocode:
			# ----------------------------------------------
			#	VIP			=	[VSP]
			#	VSP			+=	0x8
			# ----------------------------------------------
			#
			# VJMP()
		*/
		{
			"VJMP",
			{
				{},

				[ ]( vm_state* vstate, instruction& vins, const std::vector<char>& var ) -> bool
				{
					auto& is = vins.stream; auto& ps = vins.parameter_sizes;

					if ( is.size() == 2 )
					{
						return 
							// [[ 00000001400E6301: add  rbp, 8
							is[ 0 ].id == X86_INS_ADD &&
							is[ 0 ].operands[ 0 ].type == X86_OP_REG &&
							// is[ 0 ].operands[ 0 ].reg == vstate->reg_vsp && (Can't check this as this is pre-mutation VSP)
							is[ 0 ].operands[ 1 ].type == X86_OP_IMM &&
							is[ 0 ].operands[ 1 ].imm == 8 &&

							// [[ 000000014009FCEC: lea  rbx, [rip - 7]
							is[ 1 ].id == X86_INS_LEA;
					}
					else if ( is.size() == 3 )
					{
						// Out of pure coincidence VIP regsiter matches, so another instruction is appended LUL
						return
							is[ 0 ].id == X86_INS_MOV &&

							// [[ 00000001400E6301: add  rbp, 8
							is[ 1 ].id == X86_INS_ADD &&
							is[ 1 ].operands[ 0 ].type == X86_OP_REG &&
							// is[ 1 ].operands[ 0 ].reg == vstate->reg_vsp && (Can't check this as this is pre-mutation VSP)
							is[ 1 ].operands[ 1 ].type == X86_OP_IMM &&
							is[ 1 ].operands[ 1 ].imm == 8 &&

							// [[ 000000014009FCEC: lea  rbx, [rip - 7]
							is[ 2 ].id == X86_INS_LEA;
					}
					return false;
				},

				// Reflect the side effects of VIP=[VSP] (Not reflected properly as VSP might mutate)
				//
				[ ]( auto*, instruction& i, auto& ) { i.stack_reads.insert( 0 ); i.stack_delta = +8; }
			}
		},
					
		/*
			# [Jumps a constant distance VIP, no effects]
			#
			# Pseudocode:
			# ----------------------------------------------
			#	VIP			+=	distance
			# ----------------------------------------------
			#
			# VNOP
		*/
		{
			"VNOP",
			{
				{},

				[ ]( vm_state* vstate, instruction& vins, const std::vector<char>& var ) -> bool
				{
					auto& is = vins.stream; auto& ps = vins.parameter_sizes;

					return is.size() == 1 &&

						// [[ 000000014009FCEC: lea  rbx, [rip - 7]
						is[ 0 ].id == X86_INS_LEA;
				}
			}
		},

		/*
			# [Read control/debug register and push it]
			#
			# Pseudocode:
			# ----------------------------------------------
			#   t0          =   <reg>
			#   VSP			-=	0x8
			#	[VSP+0]		=	t0
			# ----------------------------------------------
			#
			# VPUSH<special>()
		*/
		{
			"VPUSHCR0",
			{
				{},

				[ ]( vm_state* vstate, instruction& vins, const std::vector<char>& var ) -> bool
				{
					auto& is = vins.stream; auto& ps = vins.parameter_sizes;

					return is.size() == 3 &&

						// [[ 0000000140095243: mov r9, cr0
						is[ 0 ].id == X86_INS_MOV &&
						is[ 0 ].operands[ 1 ].reg == X86_REG_CR0 &&

						// [[ 0000000140095245: sub  r10, 8
						i_shift_vsp( vstate, is[ 1 ], -0x8 ) &&

						// [[ 000000014009524C: mov  dword ptr [r10], edx
						i_write_vsp( vstate, is[ 2 ], 0, 8 );
				}
			}
		},
		{
			"VPUSHCR3",
			{
				{},

				[ ]( vm_state* vstate, instruction& vins, const std::vector<char>& var ) -> bool
				{
					auto& is = vins.stream; auto& ps = vins.parameter_sizes;

					return is.size() == 3 &&

						// [[ 0000000140095243: mov r9, cr0
						is[ 0 ].id == X86_INS_MOV &&
						is[ 0 ].operands[ 1 ].reg == X86_REG_CR3 &&

						// [[ 0000000140095245: sub  r10, 8
						i_shift_vsp( vstate, is[ 1 ], -0x8 ) &&

						// [[ 000000014009524C: mov  dword ptr [r10], edx
						i_write_vsp( vstate, is[ 2 ], 0, 8 );
				}
			}
		},
	};

	instruction classify( vm_state* vstate, const instruction_stream& is )
	{
		// Begin parsing the instruction
		//
		instruction out;
		out.stream = is;
		out.op = "VUNK";

		// Calculate stack delta
		//
		auto stack_instructions = {
			X86_INS_MOV,
			X86_INS_MOVZX,
			X86_INS_MOVSX,
			X86_INS_ADD,
			X86_INS_SUB,
			X86_INS_XOR,
			X86_INS_OR,
			X86_INS_AND,
		};
		for ( int i = 0; i < is.size(); i++ )
		{
			auto& ins = is[ i ];

			// Determine whether stack is read from | written into
			// TODO: This list won't ever be complete but hey will work
			//
			const x86_op_mem* stack_op_wtarget = nullptr;
			const x86_op_mem* stack_op_rtarget = nullptr;
			for ( auto base_instruction : stack_instructions )
			{
				if ( ins.is( base_instruction, { X86_OP_REG, X86_OP_MEM } ) )
				{
					if ( ins.operands[ 1 ].mem.base == vstate->reg_vsp )
						stack_op_rtarget = &ins.operands[ 1 ].mem;
					break;
				}
				else if ( ins.is( base_instruction, { X86_OP_MEM, X86_OP_REG } ) )
				{
					if ( ins.operands[ 0 ].mem.base == vstate->reg_vsp )
						stack_op_wtarget = &ins.operands[ 0 ].mem;
					break;
				}
				else if ( ins.is( X86_INS_PUSH, { X86_OP_MEM } ) )
				{
					if ( ins.operands[ 0 ].mem.base == vstate->reg_vsp )
						stack_op_rtarget = &ins.operands[ 0 ].mem;
					break;
				}
				else if ( ins.is( X86_INS_POP, { X86_OP_MEM } ) )
				{
					if ( ins.operands[ 0 ].mem.base == vstate->reg_vsp )
						stack_op_wtarget = &ins.operands[ 0 ].mem;
					break;
				}
			}

			if ( !stack_op_rtarget && !stack_op_wtarget )
			{
				for ( int j = 0; j < ins.operands.size(); j++ )
				{
					if ( ins.operands[ j ].type == X86_OP_MEM )
					{
						// TODO in case: Handle this instruction
						fassert( ins.operands[ j ].mem.index != vstate->reg_vsp );
						fassert( ins.operands[ j ].mem.base != vstate->reg_vsp );
					}
				}
			}
			else
			{
				auto process_mem_target = [ & ] ( const x86_op_mem* mem )
				{
					return mem->index == X86_REG_INVALID
						? ( out.stack_delta + mem->disp )
						: unknown_delta;
				};

				if ( stack_op_rtarget )
					out.stack_reads.insert( process_mem_target( stack_op_rtarget ) );
				if ( stack_op_wtarget )
					out.stack_writes.insert( process_mem_target( stack_op_wtarget ) );
			}

			// Calculate stack delta
			//
			// -- add vsp, n
			if ( ins.is( X86_INS_ADD, { X86_OP_REG, X86_OP_IMM } ) &&
				 ins.operands[ 0 ].reg == vstate->reg_vsp )
			{
				out.stack_delta += ins.operands[ 1 ].imm;
			}
			// -- sub vsp, n
			else if ( ins.is( X86_INS_SUB, { X86_OP_REG, X86_OP_IMM } ) &&
					  ins.operands[ 0 ].reg == vstate->reg_vsp )
			{
				out.stack_delta -= ins.operands[ 1 ].imm;
			}
			// -- lea vsp, [vsp+n]
			else if ( ins.is( X86_INS_LEA, { X86_OP_REG, X86_OP_MEM } ) &&
					  ins.operands[ 0 ].reg == vstate->reg_vsp &&
					  ins.operands[ 1 ].mem.base == vstate->reg_vsp &&
					  ins.operands[ 1 ].mem.index == X86_REG_INVALID )
			{
				out.stack_delta += ins.operands[ 1 ].mem.disp;
			}
			// -- inc vsp
			else if ( ins.is( X86_INS_INC, { X86_OP_REG } ) &&
					  ins.operands[ 0 ].reg == vstate->reg_vsp )
			{
				out.stack_delta++;
			}
			// -- dec vsp
			else if ( ins.is( X86_INS_DEC, { X86_OP_REG } ) &&
					  ins.operands[ 0 ].reg == vstate->reg_vsp )
			{
				out.stack_delta--;
			}
			// -- any other instruction writing to VSP
			else
			{
				bool vsp_written = false;
				for ( auto& reg : ins.regs_write )
				{
					if ( reg == vstate->reg_vsp )
					{
						vsp_written = true;
						break;
					}
				}
				if ( vsp_written )
				{
					out.stack_delta = unknown_delta;
					break;
				}
			}

			// Track context operations
			//
			auto is_ctx_mem_op = [ ] ( const cs_x86_op& op ) -> std::optional<x86_reg>
			{
				if ( op.type == X86_OP_MEM &&
					 op.mem.base == X86_REG_RSP &&
					 op.mem.index != X86_REG_INVALID &&
					 op.mem.scale == 1 &&
					 op.mem.disp == 0 )
				{
					return op.mem.index;
				}
				return {};
			};
			if ( ins.id == X86_INS_MOV )
			{
				auto resolve_ctx_off = [ & ] ( x86_reg ri ) -> std::optional<uint8_t>
				{
					for ( int j = i; j >= 0; j-- )
					{
						if ( is[ j ].mnemonic == "loadc" )
							return vtil::math::narrow_cast<uint8_t>( is[ j ].operands[ 1 ].imm );
					}
					return {};
				};

				if ( auto reg_w = is_ctx_mem_op( ins.operands[ 0 ] ) )
				{
					auto write_offset = resolve_ctx_off( reg_w.value() );
					fassert( write_offset.has_value() );
					out.context_writes.insert( write_offset.value() );
				}
				else if ( auto reg_r = is_ctx_mem_op( ins.operands[ 1 ] ) )
				{
					auto read_offset = resolve_ctx_off( reg_r.value() );
					fassert( read_offset.has_value() );
					out.context_reads.insert( read_offset.value() );
				}
			}
		}

		// Extract parameters
		//
		for ( auto& ins : is.stream )
		{
			if ( ins.second.mnemonic == "loadc" )
			{
				out.parameter_sizes.push_back( ins.second.operands[ 0 ].size );
				out.parameters.push_back( ins.second.operands[ 1 ].imm );
			}
		}

		// For each opcode we've defined:
		//
		for ( auto& opcode : opcodes )
		{
			// Try to reduce the instruction we have into a single opcode
			//
			if ( opcode.second.reduce( vstate, out, opcode.first ) )
				break;
		}

		// Fail if the instruction could not be classified
		//
		if ( out.op == "VUNK" )
		{
			warning( "Failed to clasify the instruction:\n%s", out.stream.to_string().data() );
			out.op = "VEMIT";
			out.parameters = { 0xCC };
			out.parameter_sizes = { 1 };
		}
		return out;
	}
};