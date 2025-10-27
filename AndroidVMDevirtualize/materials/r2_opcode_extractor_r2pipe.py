#!/usr/bin/env python3

import r2pipe
import sys
import re

def extract_opcodes(binary_path, vm_offset=0x4d3cc):

    r2 = r2pipe.open(binary_path, flags=['-2'])
    r2.cmd('aaa')
    r2.cmd(f's 0x{vm_offset:x}')
    r2.cmd('af')

    disasm = r2.cmdj('pdfj')

    opcodes = {}

    if disasm and 'ops' in disasm:
        ops = disasm['ops']
        i = 0
        while i < len(ops):
            op = ops[i]

            # Look for: mov wX, #imm
            if op.get('type') == 'mov' and 'disasm' in op:
                disasm_str = op['disasm']
                mov_match = re.search(r'mov\s+w(\d+),\s+(?:#)?0x([0-9a-f]+)', disasm_str)

                if mov_match and i + 1 < len(ops):
                    reg = mov_match.group(1)
                    low = int(mov_match.group(2), 16)

                    next_op = ops[i + 1]
                    if next_op.get('type') == 'mov' and 'disasm' in next_op:
                        next_disasm = next_op['disasm']
                        movk_match = re.search(
                            rf'movk\s+w{reg},\s+(?:#)?0x([0-9a-f]+),\s+lsl\s+(?:#)?16',
                            next_disasm
                        )

                        if movk_match:
                            high = int(movk_match.group(1), 16)
                            opcode = (high << 16) | low
                            addr = op['offset']

                            opcodes[opcode] = addr
                            i += 2
                            continue

            i += 1

    dispatcher_reg = None
    if disasm and 'ops' in disasm:
        for op in disasm['ops']:
            if op.get('type') == 'cmp' and 'disasm' in op:
                # Look for: cmp wX, wY
                match = re.search(r'cmp\s+w(\d+),\s+w(\d+)', op['disasm'])
                if match:
                    # Most common register in comparisons is likely the dispatcher
                    dispatcher_reg = f"w{match.group(1)}"
                    break

    r2.quit()

    return {
        'opcodes': list(sorted(opcodes.keys())),
        'dispatcher_reg': dispatcher_reg,
        'count': len(opcodes)
    }

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: ./r2_opcode_extractor_r2pipe.py <binary_path>")
        sys.exit(1)

    binary = sys.argv[1]
    result = extract_opcodes(binary)

    print("\nExtracted Opcodes:")
    print(result['opcodes'])
    print(f"\nTotal: {result['count']} opcodes")
    if result['dispatcher_reg']:
        print(f"Dispatcher register: {result['dispatcher_reg']}")
