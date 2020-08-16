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
#pragma once
#include <new>
#include <algorithm>

namespace mem
{
    // Allocates <size> bytes of read/write/execute memory.
    //
    void* allocate_rwx( size_t size );

    // Frees <size> byets of read/write/execute memory at <pointer>.
    //
    void free_rwx( void* pointer ) noexcept;

    // A standard C++ allocator wrapping our helpers.
    //
    template <typename T>
    struct rwx_allocator
    {
	    using value_type = T;

	    rwx_allocator() = default;

	    template <typename T2> 
	    constexpr rwx_allocator( const rwx_allocator<T2>& ) noexcept {}

	    inline T* allocate( size_t count ) { return ( T* ) allocate_rwx( count * sizeof( T ) ); }
	    inline void deallocate( T* pointer, size_t ) noexcept { free_rwx( pointer ); }

        template <typename T2> constexpr bool operator==( const rwx_allocator<T2>& ) { return true; }
        template <typename T2> constexpr bool operator!=( const rwx_allocator<T2>& ) { return false; }
    };
};