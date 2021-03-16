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
#define _CRT_SECURE_NO_WARNINGS
#ifdef _WIN32
#include <intrin.h>
#else
#include <x86intrin.h>
#endif
#include <fstream>
#include <tuple>
#include <vector>
#include <algorithm>
#include <filesystem>
#include <future>
#include <linuxpe>
#include <algorithm>
#include "vmprotect/image_desc.hpp"
#include "vmprotect/vtil_lifter.hpp"
#include "vmprotect/vm_state.hpp"
#include "demo_compiler.hpp"

#ifdef _MSC_VER
#pragma comment(linker, "/STACK:34359738368")
#endif

using namespace vtil::logger;

static std::vector<uint8_t> read_raw( const std::string& file_path )
{
	// Try to open file as binary
	std::ifstream file( file_path, std::ios::binary );
	if ( !file.good() ) error( "Input file cannot be opened." );

	// Read the whole file
	std::vector<uint8_t> bytes = std::vector<uint8_t>( std::istreambuf_iterator<char>( file ), {} );
	if ( bytes.size() == 0 ) error( "Input file is empty." );
	return bytes;
}

static void write_raw( void* data, size_t size, const std::string& file_path )
{
	std::ofstream file( file_path, std::ios::binary );
	if ( !file.good() ) error( "File cannot be opened for write." );
	file.write( ( char* ) data, size );
}

static const std::string gpl3_license_header = ""
"##############################################################################\n"
"# NoVmp  Copyright (C) 2020 Can Boluk                                        #\n"
"# This program comes with absolutely no warranty, and it is free software.   #\n"
"# You are welcome to redistribute it under certain conditions--for which you #\n"
"# can refer to the GNU General Public License v3.                            #\n"
"##############################################################################\n\n";

int main( int argc, const char** argv )
{
	vtil::logger::error_hook = [ ] ( const std::string& message )
	{
		log<CON_RED>( "[*] Unexpected error: %s\n", message );
		throw std::runtime_error( message );
	};

	// Feelin' fancy.
	//
	for ( char c : gpl3_license_header )
		log( c == '#' ? CON_RED : CON_YLW, "%c", c );

	// Parse command line.
	//
	if ( argc < 2 ) error( "No input file provided." );
	std::filesystem::path image_path( argv[ 1 ] );
	std::filesystem::path working_directory = vtil::make_copy(
		image_path
	).remove_filename() / "vms";
	std::filesystem::create_directory( working_directory );
	
	// Create the basic descriptor for the image
	//
	vmp::image_desc* desc = new vmp::image_desc;
	desc->raw = read_raw( image_path.string() );
	desc->override_image_base = 0;
	desc->has_relocs = desc->get_nt_headers()->optional_header.data_directories.basereloc_directory.present();
	desc->strip_constant_obfuscation = false;

	// Warn if relocs are stripped.
	//
	if ( !desc->has_relocs )
		warning( "This image has relocations stripped, NoVmp is not 100%% compatible with this switch yet." );

	// Parse options:
	//
	bool compile = false;
	bool optimize = true;
	std::vector<uint32_t> target_vms;
	for ( int i = 2; i < argc; )
	{
		if ( !strcmp( argv[ i ], "-vms" ) )
		{
			while ( ++i < argc && argv[ i ][ 0 ] != '-' )
				target_vms.emplace_back( strtoul( argv[ i ], nullptr, 16 ) );
		}
		else if ( !strcmp( argv[ i ], "-sections" ) )
		{
			while ( ++i < argc && argv[ i ][ 0 ] != '-' )
				vmp::section_prefixes.emplace_back( argv[ i ] );
		}
		else if ( !strcmp( argv[ i ], "-base" ) )
		{
			fassert( ++i < argc );
			desc->override_image_base = strtoull( argv[ i ], nullptr, 16 );
			i++;
		}
		else if ( !strcmp( argv[ i ], "-noopt" ) )
		{
			optimize = false;
			i++;
		}
		else if ( !strcmp( argv[ i ], "-opt:constant" ) )
		{
			desc->strip_constant_obfuscation = true;
			i++;
		}
		else if ( !strcmp( argv[ i ], "-experimental:recompile" ) )
		{
			i++;
			compile = true;
		}
		else
		{
			error( "Unknown parameter: %s", argv[ i ] );
		}
	}

	// Iterate each section:
	//
	uint32_t rva_high = 0;
	uint32_t raw_low = 0;
	for ( int i = 0; i < desc->get_nt_headers()->file_header.num_sections; i++ )
	{
		// Reference section and re-calculate some stats
		//
		win::section_header_t* scn = desc->get_nt_headers()->get_section( i );
		rva_high = std::max( scn->virtual_address + std::max( scn->virtual_size, scn->size_raw_data ), rva_high );
		raw_low = std::max( scn->ptr_raw_data, raw_low );

		// Skip if it cannot be executed
		//
		if ( !scn->characteristics.mem_execute ) continue;

		// Iterate each byte
		//
		uint8_t* scn_begin = desc->raw.data() + scn->ptr_raw_data;
		uint8_t* scn_end = scn_begin + std::min( scn->size_raw_data, scn->virtual_size );

		for ( uint8_t* it = scn_begin; it < ( scn_end - 10 ); it++ )
		{
			// Skip if not [JMP rel32] OR [CALL rel32 NOP]
			//
			bool mid_func = false;
			if ( it[ 0 ] == 0xE9 )
				mid_func = true;
			else if ( it[ 0 ] == 0xE8 )
				mid_func = false;
			else
				continue;
			uint32_t jmp_rva = scn->virtual_address + ( it - scn_begin ) + 5 + *( int32_t* ) &it[ 1 ];

			// Skip if JMP target is in the same section / in a non-executable section
			//
			win::section_header_t* scn_jmp = desc->rva_to_section( jmp_rva );
			if ( !scn_jmp || scn_jmp == scn || !scn_jmp->characteristics.mem_execute ) continue;

			// Skip if it's not VMENTER
			//
			uint8_t* jmp_target_bytes = desc->raw.data() + jmp_rva + scn_jmp->ptr_raw_data - scn_jmp->virtual_address;
			if ( jmp_target_bytes > &desc->raw.back() ||
				 jmp_target_bytes[ 0 ] != 0x68 ||
				 jmp_target_bytes[ 5 ] != 0xE8 ) continue;

			// Add to image descriptor
			//
			uint64_t ptr = ( scn->virtual_address + ( it - scn_begin ) );

			desc->virt_routines.push_back( vmp::virtual_routine{
				.jmp_rva = jmp_rva,
				.mid_routine = mid_func
			 } );

			log<CON_YLW>( "Discovered vmenter at %p\n", desc->get_real_image_base() + ptr );
		}
	}

	// If VM list is given, replace discovery.
	//
	if ( !target_vms.empty() ) desc->virt_routines.clear();
	for ( uint32_t rva : target_vms )
	{
		desc->virt_routines.push_back( vmp::virtual_routine{
				.jmp_rva = rva,
		} );
	}

	// Declare the worker.
	//
	const auto vm_lifter = [ & ] ( int vm_index ) -> vtil::routine*
	{
		// Lift the virtual machine.
		//
		vmp::virtual_routine* vr = &desc->virt_routines[ vm_index ];
		log<CON_DEF>( "Lifting virtual-machine at %p...\n", vr->jmp_rva );
		vmp::vm_state state = { desc, vr->jmp_rva };
		vtil::routine* rtn = lift_il( &state );
		if ( !rtn ) return nullptr;

		// Save unoptimized routine.
		//
		vtil::save_routine( 
			rtn, 
			( working_directory / vtil::format::str( "%p.premature.vtil", vr->jmp_rva ) ).string()
		);

		// If noopt set, return.
		//
		if ( !optimize ) return rtn;

		// Apply optimizations.
		//
		int64_t ins = rtn->num_instructions();
		int64_t blks = rtn->num_blocks();
		vtil::optimizer::apply_all_profiled( rtn );
		int64_t oins = rtn->num_instructions();
		int64_t oblks = rtn->num_blocks();

		// Write routine and optimization information.
		//
		{
			std::lock_guard _g{ logger_state };
			log<CON_GRN>( "\nLifted & optimized virtual-machine at %p\n", vr->jmp_rva );

			log<CON_YLW>( "Optimizer stats:\n" );
			log<CON_CYN>( " - Block count:       %-5d => %-5d (%.2f%%).\n", blks, oblks, 100.0f * float( float( oblks - blks ) / blks ) );
			log<CON_CYN>( " - Instruction count: %-5d => %-5d (%.2f%%).\n", ins, oins, 100.0f * float( float( oins - ins ) / ins ) );

			std::vector<uint8_t> bytes;
			for ( auto& [_, block] : rtn->explored_blocks )
			{
				for ( auto& ins : *block )
				{
					if ( ins.base->name == "vemit" )
					{
						uint8_t* bs = ( uint8_t* ) &ins.operands[ 0 ].imm().u64;
						bytes.insert( bytes.end(), bs, bs + ins.operands[ 0 ].size() );
					}
				}
			}

			if ( bytes.size() )
			{
				log<CON_YLW>( "Special instructions:\n" );

				size_t n = 0;
				auto dasm = vtil::amd64::disasm( bytes.data(), 0, bytes.size() );
				for ( auto& ins : dasm )
				{
					n++;
					log<CON_PRP>( " - %s\n", ins );
					if ( n > 10 )
					{
						log<CON_PRP>( " - ...\n" );
						break;
					}
				}
			}
		}

		// Save optimized routine.
		//
		vtil::save_routine(
			rtn,
			( working_directory / vtil::format::str( "%p.optimized.vtil", vr->jmp_rva ) ).string()
		);
		return rtn;
	};

	// Lift every routine and wait for completion.
	//
	std::vector<std::pair<size_t, std::future<vtil::routine*>>> worker_pool;
	for ( int i = 0; i < desc->virt_routines.size(); i++ )
		worker_pool.emplace_back( i, std::async( /*std::launch::async*/ std::launch::deferred, vm_lifter, i ) );

	for ( auto& [idx, rtn] : worker_pool )
	{
		try
		{
			desc->virt_routines[ idx ].routine = rtn.get();
		}
		catch ( const std::exception& ex )
		{
			log<CON_RED>( "Error: %s\n", ex.what() );
		}
	}

	// Return if recompilation is not requested.
	//
	if ( !compile )
	{
		system( "pause" ); 
		return 0;
	}

	uint32_t rva_sec = ( rva_high + 0xFFF ) & ~0xFFF;
	std::vector<uint8_t> byte_stream;
	for ( auto& vr : desc->virt_routines )
	{
		// Page align rva high and calculate where we place the next section
		//
		uint32_t rva_routine = rva_sec + byte_stream.size();
		std::vector substream = vtil::compile( vr.routine, rva_routine );

		// Write jump to new routine.
		//
		if ( vr.jmp_rva )
		{
			uint8_t* jmp_rel32 = desc->rva_to_ptr<uint8_t>( vr.jmp_rva );
			*jmp_rel32 = 0xE9;
			*( int32_t* ) ( jmp_rel32 + 1 ) = rva_routine - ( vr.jmp_rva + 5 );
		}

		// Append to stream.
		//
		byte_stream.insert( byte_stream.end(), substream.begin(), substream.end() );
	}

	// Page align the section
	//
	size_t scn_original_size = byte_stream.size();
	byte_stream.resize( ( scn_original_size + 0xFFF ) & ~0xFFF );
	memset( byte_stream.data() + scn_original_size, 0xCC, byte_stream.size() - scn_original_size );

	// Create a new section in the image
	//
	fassert( raw_low > ( sizeof( win::section_header_t ) + desc->get_nt_headers()->optional_header.size_headers ) );
	size_t img_original_size = desc->raw.size();
	desc->raw.resize( img_original_size + byte_stream.size() );
	win::image_x64_t* img = ( win::image_x64_t* ) desc->raw.data();

	win::nt_headers_x64_t* nt_hdrs = img->get_nt_headers();
	nt_hdrs->optional_header.size_code += byte_stream.size();
	nt_hdrs->optional_header.size_image += byte_stream.size();
	nt_hdrs->optional_header.size_headers += sizeof( win::section_header_t );

	win::section_header_t* scn = nt_hdrs->get_section( nt_hdrs->file_header.num_sections++ );
	memset( scn, 0, sizeof( win::section_header_t ) );
	strcpy( &scn->name.short_name[ 0 ], ".novmp" );
	scn->characteristics.cnt_code = 1;
	scn->characteristics.mem_execute = 1;
	scn->characteristics.mem_read = 1;
	scn->virtual_address = rva_sec;
	scn->ptr_raw_data = img_original_size;
	scn->size_raw_data = byte_stream.size();
	scn->virtual_size = byte_stream.size();

	memcpy( desc->raw.data() + img_original_size,
			byte_stream.data(),
			byte_stream.size() );

	// Write the recompiled image.
	//
	image_path.replace_extension( "devirt" + image_path.extension().string() );
	write_raw( 
		desc->raw.data(), 
		desc->raw.size(), 
		image_path.string() 
	);
	system( "pause" );
	return 0;
}
