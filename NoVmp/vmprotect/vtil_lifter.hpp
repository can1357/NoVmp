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
#include <vtil/vtil>
#include "vm_state.hpp"

namespace vmp
{
	// List of vmp section names, used to chain VMs, detecting re-entry.
	//
	inline std::vector<std::string> section_prefixes = { ".vmp" };

	vtil::basic_block* lift_il( vtil::basic_block* block, vm_state* vstate );
	static vtil::routine* lift_il( vm_state* vstate )
	{
		if ( vtil::routine* rtn = lift_il( nullptr, vstate )->owner )
			return rtn;
		return nullptr;
	}
};