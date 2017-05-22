/*******************************************************************************
*   BOLOS Enclave
*   (c) 2017 Ledger
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/

/* Simulator for the moxie processor
   Copyright 2014 Anthony Green
   Distributed under the MIT/X11 software license, see the accompanying
   file COPYING or http://www.opensource.org/licenses/mit-license.php.
*/

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <endian.h>
#include "signal.h"
#include <errno.h>
#include "moxie.h"
#include "machine.h"

int moxie_swi_dispatcher(struct machine *mach, int swi);

#ifndef SGX
#define INLINE inline
#else
#define INLINE
#endif

/* Extract the signed 10-bit offset from a 16-bit branch
   instruction.  */
#define INST2OFFSET(o)                                                         \
    ((((signed short)((o & ((1 << 10) - 1)) << 6)) >> 6) << 1)

#define EXTRACT_WORD(addr) extract_word32(mach, addr)
#define EXTRACT_WORD16(addr) extract_word16(mach, addr)
#define EXTRACT_OFFSET(addr) (((int32_t)EXTRACT_WORD16(addr) << 16) >> 16)

static INLINE uint16_t extract_word16(struct machine *mach, uint32_t addr) {
    uint32_t ret;
    if (!read16(mach, addr, &ret))
        mach->cpu.exception = SIGBUS;
    return (uint16_t)ret;
}

static INLINE uint32_t extract_word32(struct machine *mach, uint32_t addr) {
    uint32_t ret;
    if (!read32(mach, addr, &ret))
        mach->cpu.exception = SIGBUS;
    return ret;
}

/* Write a 1 byte value to memory.  */

static void INLINE wbat(struct machine *mach, word addr, word v) {
    if (!write8(mach, addr, v))
        mach->cpu.exception = SIGBUS;
}

/* Write a 2 byte value to memory.  */

static void INLINE wsat(struct machine *mach, word addr, word v) {
    if (!write16(mach, addr, v))
        mach->cpu.exception = SIGBUS;
}

/* Write a 4 byte value to memory.  */

static void INLINE wlat(struct machine *mach, word addr, word v) {
    if (!write32(mach, addr, v))
        mach->cpu.exception = SIGBUS;
}

/* Read 2 bytes from memory.  */

static int INLINE rsat(struct machine *mach, word addr) {
    uint32_t ret;
    if (!read16(mach, addr, &ret))
        mach->cpu.exception = SIGBUS;
    return (int32_t)ret;
}

/* Read 1 byte from memory.  */

static int INLINE rbat(struct machine *mach, word addr) {
    uint32_t ret;
    if (!read8(mach, addr, &ret))
        mach->cpu.exception = SIGBUS;
    return (int32_t)ret;
}

/* Read 4 bytes from memory.  */

static int INLINE rlat(struct machine *mach, word addr) {
    uint32_t ret;
    if (!read32(mach, addr, &ret))
        mach->cpu.exception = SIGBUS;
    return (int32_t)ret;
}

//#define TRACE(str) if (mach->tracing) fprintf(tracefile,"0x%08x, %s, 0x%x,
//0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x,
//0x%x, 0x%x\n", opc, str, cpu.asregs.regs[0], cpu.asregs.regs[1],
//cpu.asregs.regs[2], cpu.asregs.regs[3], cpu.asregs.regs[4],
//cpu.asregs.regs[5], cpu.asregs.regs[6], cpu.asregs.regs[7],
//cpu.asregs.regs[8], cpu.asregs.regs[9], cpu.asregs.regs[10],
//cpu.asregs.regs[11], cpu.asregs.regs[12], cpu.asregs.regs[13],
//cpu.asregs.regs[14], cpu.asregs.regs[15]);
//#define TRACE(str) fprintf(stderr,"0x%08x, %s, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x,
//0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x\n", opc, str,
//mach->cpu.regs[0], mach->cpu.regs[1], mach->cpu.regs[2], mach->cpu.regs[3],
//mach->cpu.regs[4], mach->cpu.regs[5], mach->cpu.regs[6], mach->cpu.regs[7],
//mach->cpu.regs[8], mach->cpu.regs[9], mach->cpu.regs[10], mach->cpu.regs[11],
//mach->cpu.regs[12], mach->cpu.regs[13], mach->cpu.regs[14],
//mach->cpu.regs[15]);
//#define TRACE(str) printf(str); printf("\n");
#define TRACE(str)

void sim_resume(struct machine *mach, unsigned long long cpu_budget) {
    int step = 0;

    word pc, opc;
    unsigned long long insts;
    unsigned short inst;

    mach->cpu.exception = step ? SIGTRAP : 0;
    pc = mach->cpu.regs[PC_REGNO];
    insts = mach->cpu.insts;

    /* Run instructions here. */
    do {
        opc = pc;

        /* Fetch the instruction at pc.  */
        inst = EXTRACT_WORD16(pc);

        /* Decode instruction.  */
        if (inst & (1 << 15)) {
            if (inst & (1 << 14)) {
                /* This is a Form 3 instruction.  */
                int opcode = (inst >> 10 & 0xf);

                switch (opcode) {
                case 0x00: /* beq */
                {
                    TRACE("beq");
                    if (mach->cpu.cc & CC_EQ)
                        pc += INST2OFFSET(inst);
                } break;
                case 0x01: /* bne */
                {
                    TRACE("bne");
                    if (!(mach->cpu.cc & CC_EQ))
                        pc += INST2OFFSET(inst);
                } break;
                case 0x02: /* blt */
                {
                    TRACE("blt");
                    if (mach->cpu.cc & CC_LT)
                        pc += INST2OFFSET(inst);
                } break;
                case 0x03: /* bgt */
                {
                    TRACE("bgt");
                    if (mach->cpu.cc & CC_GT)
                        pc += INST2OFFSET(inst);
                } break;
                case 0x04: /* bltu */
                {
                    TRACE("bltu");
                    if (mach->cpu.cc & CC_LTU)
                        pc += INST2OFFSET(inst);
                } break;
                case 0x05: /* bgtu */
                {
                    TRACE("bgtu");
                    if (mach->cpu.cc & CC_GTU)
                        pc += INST2OFFSET(inst);
                } break;
                case 0x06: /* bge */
                {
                    TRACE("bge");
                    if (mach->cpu.cc & (CC_GT | CC_EQ))
                        pc += INST2OFFSET(inst);
                } break;
                case 0x07: /* ble */
                {
                    TRACE("ble");
                    if (mach->cpu.cc & (CC_LT | CC_EQ))
                        pc += INST2OFFSET(inst);
                } break;
                case 0x08: /* bgeu */
                {
                    TRACE("bgeu");
                    if (mach->cpu.cc & (CC_GTU | CC_EQ))
                        pc += INST2OFFSET(inst);
                } break;
                case 0x09: /* bleu */
                {
                    TRACE("bleu");
                    if (mach->cpu.cc & (CC_LTU | CC_EQ))
                        pc += INST2OFFSET(inst);
                } break;
                default: {
                    TRACE("SIGILL3");
                    mach->cpu.exception = SIGILL;
                    break;
                }
                }
            } else {
                /* This is a Form 2 instruction.  */
                int opcode = (inst >> 12 & 0x3);
                switch (opcode) {
                case 0x00: /* inc */
                {
                    int a = (inst >> 8) & 0xf;
                    unsigned av = mach->cpu.regs[a];
                    unsigned v = (inst & 0xff);

                    TRACE("inc");
                    mach->cpu.regs[a] = av + v;
                } break;
                case 0x01: /* dec */
                {
                    int a = (inst >> 8) & 0xf;
                    unsigned av = mach->cpu.regs[a];
                    unsigned v = (inst & 0xff);

                    TRACE("dec");
                    mach->cpu.regs[a] = av - v;
                } break;
                case 0x02: /* gsr */
                {
                    int a = (inst >> 8) & 0xf;
                    unsigned v = (inst & 0xff);

                    TRACE("gsr");
                    mach->cpu.regs[a] = mach->cpu.sregs[v];
                } break;
                case 0x03: /* ssr */
                {
                    int a = (inst >> 8) & 0xf;
                    unsigned sreg = (inst & 0xff);
                    int32_t sval = mach->cpu.regs[a];

                    TRACE("ssr");
                    switch (sreg) {
                    case 6: /* sim return buf addr */
                        if (!physaddr(mach, sval, 1, false))
                            mach->cpu.exception = SIGBUS;
                        else
                            mach->cpu.sregs[sreg] = sval;
                        break;
                    case 7: /* sim return buf length */
                        if (!mach->cpu.sregs[6] ||
                            !physaddr(mach, mach->cpu.sregs[6], sval, false))
                            mach->cpu.exception = SIGBUS;
                        else
                            mach->cpu.sregs[sreg] = sval;
                        break;
                    default:
                        mach->cpu.sregs[sreg] = sval;
                        break;
                    }
                } break;
                default:
                    TRACE("SIGILL2");
                    mach->cpu.exception = SIGILL;
                    break;
                }
            }
        } else {
            /* This is a Form 1 instruction.  */
            int opcode = inst >> 8;
            switch (opcode) {
            case 0x00: /* bad */
                opc = opcode;

                TRACE("SIGILL0");
                mach->cpu.exception = SIGILL;
                break;
            case 0x01: /* ldi.l (immediate) */
            {
                int reg = (inst >> 4) & 0xf;
                unsigned int val;

                TRACE("ldi.l");
                val = EXTRACT_WORD(pc + 2);
                mach->cpu.regs[reg] = val;
                pc += 4;
            } break;
            case 0x02: /* mov (register-to-register) */
            {
                int dest = (inst >> 4) & 0xf;
                int src = (inst)&0xf;

                TRACE("mov");
                mach->cpu.regs[dest] = mach->cpu.regs[src];
            } break;
            case 0x03: /* jsra */
            {
                unsigned int fn = EXTRACT_WORD(pc + 2);
                unsigned int sp = mach->cpu.regs[1];

                TRACE("jsra");
                /* Save a slot for the static chain.  */
                sp -= 4;

                /* Push the return address.  */
                sp -= 4;
                wlat(mach, sp, pc + 6);

                /* Push the current frame pointer.  */
                sp -= 4;
                wlat(mach, sp, mach->cpu.regs[0]);

                /* Uncache the stack pointer and set the pc and $fp.  */
                mach->cpu.regs[1] = sp;
                mach->cpu.regs[0] = sp;
                pc = fn - 2;
            } break;
            case 0x04: /* ret */
            {
                unsigned int sp = mach->cpu.regs[0];

                TRACE("ret");

                /* Pop the frame pointer.  */
                mach->cpu.regs[0] = rlat(mach, sp);
                sp += 4;

                /* Pop the return address.  */
                pc = rlat(mach, sp) - 2;
                sp += 4;

                /* Skip over the static chain slot.  */
                sp += 4;

                /* Uncache the stack pointer.  */
                mach->cpu.regs[1] = sp;
            } break;
            case 0x05: /* add */
            {
                int a = (inst >> 4) & 0xf;
                int b = inst & 0xf;
                unsigned av = mach->cpu.regs[a];
                unsigned bv = mach->cpu.regs[b];

                TRACE("add");
                mach->cpu.regs[a] = av + bv;
            } break;
            case 0x06: /* push */
            {
                int a = (inst >> 4) & 0xf;
                int b = inst & 0xf;
                int sp = mach->cpu.regs[a] - 4;

                TRACE("push");
                wlat(mach, sp, mach->cpu.regs[b]);
                mach->cpu.regs[a] = sp;
            } break;
            case 0x07: /* pop */
            {
                int a = (inst >> 4) & 0xf;
                int b = inst & 0xf;
                int sp = mach->cpu.regs[a];

                TRACE("pop");
                mach->cpu.regs[b] = rlat(mach, sp);
                mach->cpu.regs[a] = sp + 4;
            } break;
            case 0x08: /* lda.l */
            {
                int reg = (inst >> 4) & 0xf;
                unsigned int addr = EXTRACT_WORD(pc + 2);

                TRACE("lda.l");
                mach->cpu.regs[reg] = rlat(mach, addr);
                pc += 4;
            } break;
            case 0x09: /* sta.l */
            {
                int reg = (inst >> 4) & 0xf;
                unsigned int addr = EXTRACT_WORD(pc + 2);

                TRACE("sta.l");
                wlat(mach, addr, mach->cpu.regs[reg]);
                pc += 4;
            } break;
            case 0x0a: /* ld.l (register indirect) */
            {
                int src = inst & 0xf;
                int dest = (inst >> 4) & 0xf;
                int xv;

                TRACE("ld.l");
                xv = mach->cpu.regs[src];
                mach->cpu.regs[dest] = rlat(mach, xv);
            } break;
            case 0x0b: /* st.l */
            {
                int dest = (inst >> 4) & 0xf;
                int val = inst & 0xf;

                TRACE("st.l");
                wlat(mach, mach->cpu.regs[dest], mach->cpu.regs[val]);
            } break;
            case 0x0c: /* ldo.l */
            {
                unsigned int addr = EXTRACT_OFFSET(pc + 2);
                int a = (inst >> 4) & 0xf;
                int b = inst & 0xf;

                TRACE("ldo.l");
                addr += mach->cpu.regs[b];
                mach->cpu.regs[a] = rlat(mach, addr);
                pc += 2;
            } break;
            case 0x0d: /* sto.l */
            {
                unsigned int addr = EXTRACT_OFFSET(pc + 2);
                int a = (inst >> 4) & 0xf;
                int b = inst & 0xf;

                TRACE("sto.l");
                addr += mach->cpu.regs[a];
                wlat(mach, addr, mach->cpu.regs[b]);
                pc += 2;
            } break;
            case 0x0e: /* cmp */
            {
                int a = (inst >> 4) & 0xf;
                int b = inst & 0xf;
                int cc = 0;
                int va = mach->cpu.regs[a];
                int vb = mach->cpu.regs[b];

                TRACE("cmp");

                if (va == vb)
                    cc = CC_EQ;
                else {
                    cc |= (va < vb ? CC_LT : 0);
                    cc |= (va > vb ? CC_GT : 0);
                    cc |= ((unsigned int)va < (unsigned int)vb ? CC_LTU : 0);
                    cc |= ((unsigned int)va > (unsigned int)vb ? CC_GTU : 0);
                }

                mach->cpu.cc = cc;
            } break;
            case 0x0f: /* nop */
                break;
            case 0x10: /* sex.b */
            {
                int a = (inst >> 4) & 0xf;
                int b = inst & 0xf;
                signed char bv = mach->cpu.regs[b];

                TRACE("sex.b");
                mach->cpu.regs[a] = (int)bv;
            } break;
            case 0x11: /* sex.s */
            {
                int a = (inst >> 4) & 0xf;
                int b = inst & 0xf;
                signed short bv = mach->cpu.regs[b];

                TRACE("sex.s");
                mach->cpu.regs[a] = (int)bv;
            } break;
            case 0x12: /* zex.b */
            {
                int a = (inst >> 4) & 0xf;
                int b = inst & 0xf;
                signed char bv = mach->cpu.regs[b];

                TRACE("zex.b");
                mach->cpu.regs[a] = (int)bv & 0xff;
            } break;
            case 0x13: /* zex.s */
            {
                int a = (inst >> 4) & 0xf;
                int b = inst & 0xf;
                signed short bv = mach->cpu.regs[b];

                TRACE("zex.s");
                mach->cpu.regs[a] = (int)bv & 0xffff;
            } break;
            case 0x14: /* umul.x */
            {
                int a = (inst >> 4) & 0xf;
                int b = inst & 0xf;
                unsigned av = mach->cpu.regs[a];
                unsigned bv = mach->cpu.regs[b];
                unsigned long long r =
                    (unsigned long long)av * (unsigned long long)bv;

                TRACE("umul.x");
                mach->cpu.regs[a] = r >> 32;
            } break;
            case 0x15: /* mul.x */
            {
                int a = (inst >> 4) & 0xf;
                int b = inst & 0xf;
                unsigned av = mach->cpu.regs[a];
                unsigned bv = mach->cpu.regs[b];
                signed long long r =
                    (signed long long)av * (signed long long)bv;

                TRACE("mul.x");
                mach->cpu.regs[a] = r >> 32;
            } break;
            case 0x16: /* bad */
            case 0x17: /* bad */
            case 0x18: /* bad */
            {
                opc = opcode;

                TRACE("SIGILL0");
                mach->cpu.exception = SIGILL;
                break;
            }
            case 0x19: /* jsr */
            {
                unsigned int fn = mach->cpu.regs[(inst >> 4) & 0xf];
                unsigned int sp = mach->cpu.regs[1];

                TRACE("jsr");

                /* Save a slot for the static chain.  */
                sp -= 4;

                /* Push the return address.  */
                sp -= 4;
                wlat(mach, sp, pc + 2);

                /* Push the current frame pointer.  */
                sp -= 4;
                wlat(mach, sp, mach->cpu.regs[0]);

                /* Uncache the stack pointer and set the fp & pc.  */
                mach->cpu.regs[1] = sp;
                mach->cpu.regs[0] = sp;
                pc = fn - 2;
            } break;
            case 0x1a: /* jmpa */
            {
                unsigned int tgt = EXTRACT_WORD(pc + 2);

                TRACE("jmpa");
                pc = tgt - 2;
            } break;
            case 0x1b: /* ldi.b (immediate) */
            {
                int reg = (inst >> 4) & 0xf;
                unsigned int val = EXTRACT_WORD(pc + 2);

                TRACE("ldi.b");
                mach->cpu.regs[reg] = val;
                pc += 4;
            } break;
            case 0x1c: /* ld.b (register indirect) */
            {
                int src = inst & 0xf;
                int dest = (inst >> 4) & 0xf;
                int xv;

                TRACE("ld.b");
                xv = mach->cpu.regs[src];
                mach->cpu.regs[dest] = rbat(mach, xv);
            } break;
            case 0x1d: /* lda.b */
            {
                int reg = (inst >> 4) & 0xf;
                unsigned int addr = EXTRACT_WORD(pc + 2);

                TRACE("lda.b");
                mach->cpu.regs[reg] = rbat(mach, addr);
                pc += 4;
            } break;
            case 0x1e: /* st.b */
            {
                int dest = (inst >> 4) & 0xf;
                int val = inst & 0xf;

                TRACE("st.b");
                wbat(mach, mach->cpu.regs[dest], mach->cpu.regs[val]);
            } break;
            case 0x1f: /* sta.b */
            {
                int reg = (inst >> 4) & 0xf;
                unsigned int addr = EXTRACT_WORD(pc + 2);

                TRACE("sta.b");
                wbat(mach, addr, mach->cpu.regs[reg]);
                pc += 4;
            } break;
            case 0x20: /* ldi.s (immediate) */
            {
                int reg = (inst >> 4) & 0xf;
                unsigned int val = EXTRACT_WORD(pc + 2);

                TRACE("ldi.s");
                mach->cpu.regs[reg] = val;
                pc += 4;
            } break;
            case 0x21: /* ld.s (register indirect) */
            {
                int src = inst & 0xf;
                int dest = (inst >> 4) & 0xf;
                int xv;

                TRACE("ld.s");
                xv = mach->cpu.regs[src];
                mach->cpu.regs[dest] = rsat(mach, xv);
            } break;
            case 0x22: /* lda.s */
            {
                int reg = (inst >> 4) & 0xf;
                unsigned int addr = EXTRACT_WORD(pc + 2);

                TRACE("lda.s");
                mach->cpu.regs[reg] = rsat(mach, addr);
                pc += 4;
            } break;
            case 0x23: /* st.s */
            {
                int dest = (inst >> 4) & 0xf;
                int val = inst & 0xf;

                TRACE("st.s");
                wsat(mach, mach->cpu.regs[dest], mach->cpu.regs[val]);
            } break;
            case 0x24: /* sta.s */
            {
                int reg = (inst >> 4) & 0xf;
                unsigned int addr = EXTRACT_WORD(pc + 2);

                TRACE("sta.s");
                wsat(mach, addr, mach->cpu.regs[reg]);
                pc += 4;
            } break;
            case 0x25: /* jmp */
            {
                int reg = (inst >> 4) & 0xf;

                TRACE("jmp");
                pc = mach->cpu.regs[reg] - 2;
            } break;
            case 0x26: /* and */
            {
                int a = (inst >> 4) & 0xf;
                int b = inst & 0xf;
                int av, bv;

                TRACE("and");
                av = mach->cpu.regs[a];
                bv = mach->cpu.regs[b];
                mach->cpu.regs[a] = av & bv;
            } break;
            case 0x27: /* lshr */
            {
                int a = (inst >> 4) & 0xf;
                int b = inst & 0xf;
                int av = mach->cpu.regs[a];
                int bv = mach->cpu.regs[b];

                TRACE("lshr");
                mach->cpu.regs[a] = (unsigned)((unsigned)av >> bv);
            } break;
            case 0x28: /* ashl */
            {
                int a = (inst >> 4) & 0xf;
                int b = inst & 0xf;
                int av = mach->cpu.regs[a];
                int bv = mach->cpu.regs[b];

                TRACE("ashl");
                mach->cpu.regs[a] = av << bv;
            } break;
            case 0x29: /* sub */
            {
                int a = (inst >> 4) & 0xf;
                int b = inst & 0xf;
                unsigned av = mach->cpu.regs[a];
                unsigned bv = mach->cpu.regs[b];

                TRACE("sub");
                mach->cpu.regs[a] = av - bv;
            } break;
            case 0x2a: /* neg */
            {
                int a = (inst >> 4) & 0xf;
                int b = inst & 0xf;
                int bv = mach->cpu.regs[b];

                TRACE("neg");
                mach->cpu.regs[a] = -bv;
            } break;
            case 0x2b: /* or */
            {
                int a = (inst >> 4) & 0xf;
                int b = inst & 0xf;
                int av, bv;

                TRACE("or");
                av = mach->cpu.regs[a];
                bv = mach->cpu.regs[b];
                mach->cpu.regs[a] = av | bv;
            } break;
            case 0x2c: /* not */
            {
                int a = (inst >> 4) & 0xf;
                int b = inst & 0xf;
                int bv = mach->cpu.regs[b];

                TRACE("not");
                mach->cpu.regs[a] = 0xffffffff ^ bv;
            } break;
            case 0x2d: /* ashr */
            {
                int a = (inst >> 4) & 0xf;
                int b = inst & 0xf;
                int av = mach->cpu.regs[a];
                int bv = mach->cpu.regs[b];

                TRACE("ashr");
                mach->cpu.regs[a] = av >> bv;
            } break;
            case 0x2e: /* xor */
            {
                int a = (inst >> 4) & 0xf;
                int b = inst & 0xf;
                int av, bv;

                TRACE("xor");
                av = mach->cpu.regs[a];
                bv = mach->cpu.regs[b];
                mach->cpu.regs[a] = av ^ bv;
            } break;
            case 0x2f: /* mul */
            {
                int a = (inst >> 4) & 0xf;
                int b = inst & 0xf;
                unsigned av = mach->cpu.regs[a];
                unsigned bv = mach->cpu.regs[b];

                TRACE("mul");
                mach->cpu.regs[a] = av * bv;
            } break;
            case 0x30: /* swi */
            {
                unsigned int inum = EXTRACT_WORD(pc + 2);

                TRACE("swi");
                /* Set the special registers appropriately.  */
                mach->cpu.sregs[2] = 3; /* MOXIE_EX_SWI */
                mach->cpu.sregs[3] = inum;

                /* Commit cache before calling SWI */
                mach->cpu.regs[PC_REGNO] = pc;
                mach->cpu.insts += insts;
                insts = 0;

                if (!moxie_swi_dispatcher(mach, inum)) {
                    mach->cpu.exception = SIGBUS;
                }
                pc += 4;
            } break;
            case 0x31: /* div */
            {
                int a = (inst >> 4) & 0xf;
                int b = inst & 0xf;
                int av = mach->cpu.regs[a];
                int bv = mach->cpu.regs[b];

                TRACE("div");
                mach->cpu.regs[a] = av / bv;
            } break;
            case 0x32: /* udiv */
            {
                int a = (inst >> 4) & 0xf;
                int b = inst & 0xf;
                unsigned int av = mach->cpu.regs[a];
                unsigned int bv = mach->cpu.regs[b];

                TRACE("udiv");
                mach->cpu.regs[a] = (av / bv);
            } break;
            case 0x33: /* mod */
            {
                int a = (inst >> 4) & 0xf;
                int b = inst & 0xf;
                int av = mach->cpu.regs[a];
                int bv = mach->cpu.regs[b];

                TRACE("mod");
                mach->cpu.regs[a] = av % bv;
            } break;
            case 0x34: /* umod */
            {
                int a = (inst >> 4) & 0xf;
                int b = inst & 0xf;
                unsigned int av = mach->cpu.regs[a];
                unsigned int bv = mach->cpu.regs[b];

                TRACE("umod");
                mach->cpu.regs[a] = (av % bv);
            } break;
            case 0x35: /* brk */
                TRACE("brk");
                mach->cpu.exception = SIGTRAP;
                pc -= 2; /* Adjust pc */
                break;
            case 0x36: /* ldo.b */
            {
                unsigned int addr = EXTRACT_OFFSET(pc + 2);
                int a = (inst >> 4) & 0xf;
                int b = inst & 0xf;

                TRACE("ldo.b");
                addr += mach->cpu.regs[b];
                mach->cpu.regs[a] = rbat(mach, addr);
                pc += 2;
            } break;
            case 0x37: /* sto.b */
            {
                unsigned int addr = EXTRACT_OFFSET(pc + 2);
                int a = (inst >> 4) & 0xf;
                int b = inst & 0xf;

                TRACE("sto.b");
                addr += mach->cpu.regs[a];
                wbat(mach, addr, mach->cpu.regs[b]);
                pc += 2;
            } break;
            case 0x38: /* ldo.s */
            {
                unsigned int addr = EXTRACT_OFFSET(pc + 2);
                int a = (inst >> 4) & 0xf;
                int b = inst & 0xf;

                TRACE("ldo.s");
                addr += mach->cpu.regs[b];
                mach->cpu.regs[a] = rsat(mach, addr);
                pc += 2;
            } break;
            case 0x39: /* sto.s */
            {
                unsigned int addr = EXTRACT_OFFSET(pc + 2);
                int a = (inst >> 4) & 0xf;
                int b = inst & 0xf;

                TRACE("sto.s");
                addr += mach->cpu.regs[a];
                wsat(mach, addr, mach->cpu.regs[b]);
                pc += 2;
            } break;
            default:
                opc = opcode;
                TRACE("SIGILL1");
                mach->cpu.exception = SIGILL;
                break;
            }
        }

        insts++;
        pc += 2;

        if (cpu_budget && (insts >= cpu_budget))
            break;

    } while (!mach->cpu.exception);

    /* Hide away the things we've cached while executing.  */
    mach->cpu.regs[PC_REGNO] = pc;
    mach->cpu.insts += insts; /* instructions done ... */
}
