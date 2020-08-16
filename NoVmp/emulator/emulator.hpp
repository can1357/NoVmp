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
#include <stdint.h>
#include <tuple>
#include <vtil/amd64>

#pragma pack(push, 1)
struct emulator
{
    static constexpr uint64_t default_register_value =  0xCCCCCCCCCCCCCCCC;
    static constexpr uint64_t default_rflags_value =    0x202;
    static constexpr size_t user_stack_size =           0x100;
    static constexpr size_t reserved_stack_size =       0x20;

    // Virtual stack, must not be moved from the beginning of this structure 
    // since this pointer is used as a stack pointer.
    //
    uint64_t v_reserved_stack[ reserved_stack_size / 8 ] = { default_register_value };
    uint64_t v_stack[ user_stack_size / 8 ] =              { default_register_value };

    // Each individual register.
    //
    uint64_t v_rax =    default_register_value;
    uint64_t v_rbx =    default_register_value;
    uint64_t v_rcx =    default_register_value;
    uint64_t v_rdx =    default_register_value;
    uint64_t v_rsi =    default_register_value;
    uint64_t v_rdi =    default_register_value;
    uint64_t v_rbp =    default_register_value;
    uint64_t v_r8 =     default_register_value;
    uint64_t v_r9 =     default_register_value;
    uint64_t v_r10 =    default_register_value;
    uint64_t v_r11 =    default_register_value;
    uint64_t v_r12 =    default_register_value;
    uint64_t v_r13 =    default_register_value;
    uint64_t v_r14 =    default_register_value;
    uint64_t v_r15 =    default_register_value;
    uint64_t v_rflags = default_rflags_value;

    // Internal values that must be stored, used by ::transform().
    //
    const void* __rip = nullptr;
    const void* __rsp = 0;

    // Invokes routine at the pointer given with the current context and updates the context.
    // - Template argument is a small trick to make it work with ICC, declaring a constexpr within the scope does not work.
    //
    void invoke( const void* routine_pointer );

    // Resolves the offset<0> where the value is saved at for the given register
    // and the number of bytes<1> it takes.
    //
    std::pair<int32_t, uint8_t> resolve( x86_reg reg ) const;

    // Sets the value of a register.
    //
    emulator& set( x86_reg reg, uint64_t value );

    // Gets the value of a register.
    //
    uint64_t get( x86_reg reg ) const;
};
#pragma pack(pop)