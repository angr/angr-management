import ailment
from angrmanagement.plugins import BasePlugin

from .asm_output import AsmOutput


class AIL2ARM32(BasePlugin):
    """
    Assemble expressions into assembly.
    """

    def __init__(self, workspace, sp_adjust=0x30):
        super().__init__(workspace)
        self.sp_adjust = sp_adjust
        self.registers_in_use = []
        self.free_registers = ['r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10', 'r11']
        self.free_registers.reverse()

    def reserve_register(self):
        if not self.free_registers:
            raise Exception("No more registers available")
        reg = self.free_registers.pop()
        self.registers_in_use.append(reg)
        return reg

    def return_register(self, reg):
        self.registers_in_use.remove(reg)
        self.free_registers.append(reg)

    @staticmethod
    def opcode_variant(opcode, size=None, signed=None, cond=None):
        if size is not None:
            if size == 4:
                pass
            elif size == 2:
                if signed is not None and signed:
                    opcode += "s"
                opcode += "h"
            elif size == 1:
                if signed is not None and signed:
                    opcode += "s"
                opcode += "b"
            else:
                raise Exception(f"unsupported size {size} for opcode {opcode}")
        if cond is not None:
            opcode += cond
        return opcode

    def bp_offset_to_sp_offset(self, offset_from_bp, function_addr, expr_addr, adjust=0):
        if function_addr is None or expr_addr is None:
            raise Exception("function_addr and expr_addr must be specified")
        sp = self.workspace.instance.project.arch.sp_offset
        bp = self.workspace.instance.project.arch.bp_offset
        sptracker = self.workspace.instance.project.analyses.StackPointerTracker(
            self.workspace.instance.project.kb.functions[function_addr], {sp, bp}
            )
        sp_offset = sptracker.offset_after(expr_addr, sp)
        bp_offset = sptracker.offset_after(expr_addr, bp)
        if sp_offset >= (1<<(32-1)):
            sp_offset -= 1 << 32
        if bp_offset >= (1<<(32-1)):
            bp_offset -= 1 << 32
        return bp_offset + offset_from_bp - sp_offset + adjust

    def assemble(self, expr, function_addr=None, expr_addr=None):
        dest, asm, const_pool = self.assemble_recursive(expr, function_addr, expr_addr)
        self.return_register(dest)
        asm += f"mov r0, {dest}\n"
        if const_pool:
            asm += "b _end\n"
            asm += const_pool
            asm += "_end:\n"
        return asm

    def assemble_recursive(self, expr, function_addr=None, expr_addr=None):
        asm = ""
        const_pool = ""
        ###################################################
        # Complex Expressions
        ###################################################
        ## ldr REG, [CONSTANT]
        if isinstance(expr, ailment.Expr.Load) and isinstance(expr.addr, ailment.Expr.Const) \
            and expr.addr.value <= 0xffff:
            dest = self.reserve_register()
            asm += f"{self.opcode_variant('ldr', size=expr.size)} {dest}, [#{hex(expr.addr.value)}]\n"
            return dest, asm, const_pool
        ## add REG, CONSTANT / lsl REG, CONSTANT
        elif isinstance(expr, ailment.Expr.BinaryOp) and isinstance(expr.operands[1], ailment.Expr.Const) \
            and expr.operands[1].value <= 0xffff:
            operand0, ret_asm, ret_const_pool = self.assemble_recursive(expr.operands[0], function_addr, expr_addr)
            asm += ret_asm
            const_pool += ret_const_pool
            dest = self.reserve_register()
            if expr.op == "Add":
                asm += f"add {dest}, {operand0}, #{hex(expr.operands[1].value)}\n"
            elif expr.op == "Shl":
                asm += f"lsl {dest}, {operand0}, #{hex(expr.operands[1].value)}\n"
            self.return_register(operand0)
            return dest, asm, const_pool
        ## ldr REG, [REG, CONSTANT]
        elif isinstance(expr, ailment.Expr.Load) and isinstance(expr.addr, ailment.Expr.BinaryOp) \
            and expr.addr.op == "Add" and isinstance(expr.addr.operands[1], ailment.Expr.Const) \
            and expr.addr.operands[1].value <= 0xffff:
            operand0, ret_asm, ret_const_pool = self.assemble_recursive(expr.addr.operands[0], function_addr, expr_addr)
            asm += ret_asm
            const_pool += ret_const_pool
            dest = self.reserve_register()
            asm += (f"{self.opcode_variant('ldr', size=expr.size)} {dest}, "
                    f"[{operand0}, #{hex(expr.addr.operands[1].value)}]\n")
            self.return_register(operand0)
            return dest, asm, const_pool
        ## ldr REG, [CONSTANT, REG] -> ldr REG, [REG, CONSTANT]
        elif isinstance(expr, ailment.Expr.Load) and isinstance(expr.addr, ailment.Expr.BinaryOp) \
            and expr.addr.op == "Add" and isinstance(expr.addr.operands[0], ailment.Expr.Const) \
            and expr.addr.operands[0].value <= 0xffff:
            operand1, ret_asm, ret_const_pool = self.assemble_recursive(expr.addr.operands[1], function_addr, expr_addr)
            asm += ret_asm
            const_pool += ret_const_pool
            dest = self.reserve_register()
            asm += (f"{self.opcode_variant('ldr', size=expr.size)} {dest}, "
                    f"[{operand1}, #{hex(expr.addr.operands[0].value)}]\n")
            self.return_register(operand1)
            return dest, asm, const_pool
        ## ldr REG, [REG, REG]
        elif isinstance(expr, ailment.Expr.Load) and isinstance(expr.addr, ailment.Expr.BinaryOp) \
            and expr.addr.op == "Add":
            operand0, ret_asm, ret_const_pool = self.assemble_recursive(expr.addr.operands[0], function_addr, expr_addr)
            asm += ret_asm
            const_pool += ret_const_pool
            operand1, ret_asm, ret_const_pool = self.assemble_recursive(expr.addr.operands[1], function_addr, expr_addr)
            asm += ret_asm
            const_pool += ret_const_pool
            dest = self.reserve_register()
            asm += f"{self.opcode_variant('ldr', size=expr.size)} {dest}, [{operand0}, {operand1}]\n"
            self.return_register(operand0)
            self.return_register(operand1)
            return dest, asm, const_pool
        ## ldr REG, [STACK_OFFSET]
        elif isinstance(expr, ailment.Expr.Load) and isinstance(expr.addr, ailment.Expr.StackBaseOffset):
            dest = self.reserve_register()
            asm += (f"{self.opcode_variant('ldr', size=expr.size)} "
                    f"{dest}, [sp, "
                    f"{self.bp_offset_to_sp_offset(expr.addr.offset, function_addr, expr_addr, self.sp_adjust)}]\n")
            return dest, asm, const_pool

        ###################################################
        # Fall back to the default implementation
        ###################################################
        ## Ignore Convert
        elif isinstance(expr, ailment.Expr.Convert):
            return self.assemble_recursive(expr.operand, function_addr, expr_addr)
        ## ldr REG, [REG]
        elif isinstance(expr, ailment.Expr.Load):
            src, ret_asm, ret_const_pool = self.assemble_recursive(expr.addr, function_addr, expr_addr)
            asm += ret_asm
            const_pool += ret_const_pool
            dest = self.reserve_register()
            asm += f"{self.opcode_variant('ldr', size=expr.size)} {dest}, [{src}]\n"
            self.return_register(src)
            return dest, asm, const_pool
        ## add REG, REG, REG / lsl REG, REG, REG
        elif isinstance(expr, ailment.Expr.BinaryOp):
            operand0, ret_asm, ret_const_pool = self.assemble_recursive(expr.operands[0], function_addr, expr_addr)
            asm += ret_asm
            const_pool += ret_const_pool
            operand1, ret_asm, ret_const_pool = self.assemble_recursive(expr.operands[1], function_addr, expr_addr)
            asm += ret_asm
            const_pool += ret_const_pool
            dest = self.reserve_register()
            if expr.op == "Add":
                asm += f"add {dest}, {operand0}, {operand1}\n"
            elif expr.op == "Shl":
                asm += f"lsl {dest}, {operand0}, {operand1}\n"
            self.return_register(operand0)
            self.return_register(operand1)
            return dest, asm, const_pool
        ## Stack Base Offset (bp+offset) -> add REG, sp, #PLACE_HOLDER
        ## sp + offset
        elif isinstance(expr, ailment.Expr.StackBaseOffset):
            dest = self.reserve_register()
            asm += (f"{self.opcode_variant('ldr', size=expr.size)}"
                    f"{dest}, [sp, "
                    f"{self.bp_offset_to_sp_offset(expr.addr.offset, function_addr, expr_addr, self.sp_adjust)}]\n")
            return dest, asm, const_pool
        ## Constant -> mov REG, #CONSTANT
        elif isinstance(expr, ailment.Expr.Const):
            if expr.value <= 0xffff: # either < 16 bits, or > 16 bits but can be represented in 16 bits
                dest = self.reserve_register()
                asm += f"mov {dest}, #{hex(expr.value)}\n"
                return dest, asm, const_pool
            elif expr.bits == 32:
                dest = self.reserve_register()
                asm += f"ldr {dest}, ptr_{hex(expr.value)}\n"
                const_pool += f"ptr_{hex(expr.value)}:\n"
                const_pool += f"  .long {hex(expr.value)}\n"
                return dest, asm, const_pool
            else:
                raise NotImplementedError(f"Unsupported constant size: {expr.bits}")
        else:
            raise Exception("Unsupported expression")

    def display_output(self, s: str):
        AsmOutput(s, parent=self.workspace.main_window).exec_()
