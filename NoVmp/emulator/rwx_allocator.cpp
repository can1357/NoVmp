// Copyright (c) 2020 Can Boluk and contributors of the VTIL Project   
// All rights reserved.   
//    
// Redistribution and use in source and binary forms, with or without   
// modification, are permitted provided that the following conditions are met: 
//    
// 1. Redistributions of source code must retain the above copyright notice,   
//    this list of conditions and the following disclaimer.   
// 2. Redistributions in binary form must reproduce the above copyright   
//    notice, this list of conditions and the following disclaimer in the   
//    documentation and/or other materials provided with the distribution.   
// 3. Neither the name of VTIL Project nor the names of its contributors
//    may be used to endorse or promote products derived from this software 
//    without specific prior written permission.   
//    
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE   
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE  
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE   
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR   
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF   
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS   
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN   
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)   
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE  
// POSSIBILITY OF SUCH DAMAGE.        
//
#include "rwx_allocator.hpp"
#if _WIN64
	#define WIN32_LEAN_AND_MEAN
	#define NOMINMAX
	#include <Windows.h>
#else
	#include <sys/mman.h>
#endif
#include <vtil/io>

namespace mem
{
	// If on Windows platform, create a RWX heap.
	//
#if _WIN64
	auto rwx_heap = [ ] ()
	{
		static HANDLE h = HeapCreate( HEAP_CREATE_ENABLE_EXECUTE, 0, 0 );
		return h;
	};
#endif

	// A RWX memory descriptor prefixes any allocations made by us,
	// most to support freeing without an explicit size argument
	// on non-Windows platforms.
	//
	static constexpr size_t rwx_mem_magic = 0x1337DEAD;
	struct rwx_mem_desc
	{
		size_t magic;
		size_t allocation_size;
	};

	// Allocates <size> bytes of read/write/execute memory.
	//
	void* allocate_rwx( size_t size )
	{
		size += sizeof( rwx_mem_desc );

#if _WIN64
		// Allocate a block of RWX memory from the heap we've created.
		//
		void* p = HeapAlloc( rwx_heap(), HEAP_ZERO_MEMORY, size );
#else
		// Allocate new RWX page(s).
		//
		void* p = mmap( 0, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0 );
#endif
		// If the API returned NULL, throw exception.
		//
		if ( !p ) throw std::bad_alloc();

		// Cast the type to rwx_mem_desc, write the size and magic.
		//
		rwx_mem_desc* desc = ( rwx_mem_desc* ) p;
		desc->allocation_size = size;
		desc->magic = rwx_mem_magic;

		// Return the data pointer, which is right after the descriptor.
		//
		return desc + 1;
	}

	// Frees the read/write/execute memory at <pointer>.
	//
	void free_rwx( void* pointer ) noexcept
	{
		// Resolve the descriptor which is right before the data, assert magic is valid.
		//
		rwx_mem_desc* desc = ( rwx_mem_desc* ) pointer - 1;
		fassert( desc->magic == rwx_mem_magic );

#if _WIN64
		// Free the heap memory we've allocated.
		//
		HeapFree( rwx_heap(), 0, desc );
#else
		// Free the page(s) we've allocated.
		//
		mmunmap( desc, desc->allocation_size );
#endif
	}
};