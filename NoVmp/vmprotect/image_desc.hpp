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
#include <vector>
#include <linuxpe>
#include <algorithm>
#include <vtil/arch>

namespace vmp
{
	struct virtual_routine
	{
		uint32_t jmp_rva;
		bool mid_routine;
		vtil::routine* routine = nullptr;
	};

	struct image_desc
	{
		// Basic PE image & details
		//
		std::vector<uint8_t> raw;
		uint64_t override_image_base = 0;

		win::image_x64_t* get_pe_header() { return ( win::image_x64_t* ) raw.data(); }
		win::nt_headers_x64_t* get_nt_headers() { return get_pe_header()->get_nt_headers(); }
		uint64_t get_mapped_image_base() { return get_nt_headers()->optional_header.image_base; }
		uint64_t get_real_image_base() { return override_image_base ? override_image_base : get_mapped_image_base(); }

		template<typename T = void>
		T* rva_to_ptr( uint32_t rva ) { return get_pe_header()->rva_to_ptr<T>( rva ); }
		win::section_header_t* rva_to_section( uint32_t rva ) { return get_pe_header()->rva_to_section( rva ); }

		// List of virtualized routines
		//
		std::vector<virtual_routine> virt_routines;

		// VMProtect specific options.
		//
		bool has_relocs = false;
		bool strip_constant_obfuscation = false;
	};
};