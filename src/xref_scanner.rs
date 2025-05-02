use capstone::{prelude::*, Capstone, Insn};
use memflow::prelude::v1::*;
use std::result;

// Define reference types
#[derive(Debug, Clone, Copy)]
pub enum XrefType {
    Call,      // Direct call instruction
    Jump,      // Jump instruction
    Indirect,  // Indirect call/jump
    DataRef,   // Data reference
}

// Simple architecture enum
#[derive(Debug, Clone, Copy)]
pub enum Arch {
    X86_32,
    X86_64,
}

impl XrefType {
    pub fn to_string(&self) -> &'static str {
        match self {
            XrefType::Call => "call",
            XrefType::Jump => "jump",
            XrefType::Indirect => "indirect",
            XrefType::DataRef => "data_ref",
        }
    }
}

// Structure to hold XREF results
pub struct XrefResult {
    pub address: u64,        // Address of the reference
    pub xref_type: XrefType, // Type of reference
    pub instruction: String, // Disassembled instruction
    pub context: Vec<String>, // Surrounding instructions for context
}

// Helper function to initialize Capstone for the appropriate architecture
pub fn init_capstone(arch: Arch) -> result::Result<Capstone, capstone::Error> {
    match arch {
        Arch::X86_32 => {
            // 32-bit x86
            let cs = Capstone::new()
                .x86()
                .mode(arch::x86::ArchMode::Mode32)
                .detail(true)
                .build()?;
            Ok(cs)
        },
        Arch::X86_64 => {
            // 64-bit x86
            let cs = Capstone::new()
                .x86()
                .mode(arch::x86::ArchMode::Mode64)
                .detail(true)
                .build()?;
            Ok(cs)
        },
    }
}

// Helper function to check if an instruction references a target address
pub fn is_reference_to(
    insn: &Insn,
    target_addr: u64,
    include_jumps: bool,
    include_indirect: bool,
    cs: &Capstone,
) -> Option<XrefType> {
    // Get instruction details
    let detail = match cs.insn_detail(insn) {
        Ok(detail) => detail,
        Err(_) => return None,
    };

    // Get architecture-specific details
    let arch_detail = match detail.arch_detail() {
        capstone::arch::ArchDetail::X86Detail(detail) => detail,
        _ => return None,
    };

    // Check instruction group
    let is_call = detail.groups().iter().any(|&g| g.0 == capstone::InsnGroupType::CS_GRP_CALL as u8);
    let is_jump = detail.groups().iter().any(|&g| g.0 == capstone::InsnGroupType::CS_GRP_JUMP as u8);
    
    // Skip if it's a jump and we're not including jumps
    if is_jump && !include_jumps {
        return None;
    }
    
    // Check if it's a direct reference
    for op in arch_detail.operands() {
        match op.op_type {
            capstone::arch::x86::X86OperandType::Imm(imm) => {
                // For direct calls/jumps, the immediate value is the target
                if imm as u64 == target_addr {
                    if is_call {
                        return Some(XrefType::Call);
                    } else if is_jump {
                        return Some(XrefType::Jump);
                    }
                }
                
                // For relative calls/jumps, calculate the target address
                // E8/E9 + 5 + imm = target_addr
                let insn_addr = insn.address();
                let insn_size = insn.bytes().len() as u64;
                let calculated_target = insn_addr.wrapping_add(insn_size).wrapping_add(imm as u64);
                
                if calculated_target == target_addr {
                    if is_call {
                        return Some(XrefType::Call);
                    } else if is_jump {
                        return Some(XrefType::Jump);
                    }
                }
            },
            capstone::arch::x86::X86OperandType::Mem(mem) => {
                // For indirect calls/jumps through memory
                if include_indirect {
                    // This is a simplified check - in a real implementation,
                    // we would need to read the memory at this location to see if it contains our target
                    if mem.disp() as u64 == target_addr {
                        return Some(XrefType::Indirect);
                    }
                }
            },
            _ => {}
        }
    }
    
    None
}

// Helper function to get context instructions around a reference
pub fn get_instruction_context(
    buffer: &[u8],
    ref_offset: usize,
    context_count: usize,
    base_addr: u64,
    cs: &Capstone,
) -> Vec<String> {
    let mut context = Vec::new();
    
    // Determine the range to disassemble for context
    // This is a simplified approach - in a real implementation, we would need to
    // be more careful about instruction boundaries
    let start_offset = if ref_offset > context_count * 15 {
        ref_offset - context_count * 15
    } else {
        0
    };
    
    let end_offset = if ref_offset + 15 + context_count * 15 < buffer.len() {
        ref_offset + 15 + context_count * 15
    } else {
        buffer.len()
    };
    
    // Disassemble the context range
    if let Ok(insns) = cs.disasm_all(&buffer[start_offset..end_offset], base_addr + start_offset as u64) {
        for insn in insns.iter() {
            let addr_str = format!("0x{:x}", insn.address());
            let bytes_str = insn.bytes().iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<String>>()
                .join(" ");
            let mnemonic = insn.mnemonic().unwrap_or("");
            let op_str = insn.op_str().unwrap_or("");
            
            let formatted = format!("{:<10} {:<20} {:<8} {}", addr_str, bytes_str, mnemonic, op_str);
            context.push(formatted);
        }
    }
    
    context
}

// Helper function to scan a memory region for references to a target address
pub fn scan_region_for_xrefs(
    process: &mut ProcessInstanceArcBox<'_>,
    region_addr: Address,
    region_size: usize,
    target_addr: u64,
    include_jumps: bool,
    include_indirect: bool,
    context_count: usize,
    arch: Arch,
) -> Vec<XrefResult> {
    let mut results = Vec::new();
    
    // Initialize Capstone
    let cs = match init_capstone(arch) {
        Ok(cs) => cs,
        Err(_) => return results,
    };
    
    // Read the memory region
    let mut buffer = vec![0u8; region_size];
    if let Err(_) = process.read_raw_into(region_addr, &mut buffer) {
        return results;
    }
    
    // First pass: use pattern scanning to find potential call/jump instructions
    // E8 (call), E9 (jmp), FF15 (call [mem]), etc.
    let potential_offsets = find_potential_call_offsets(&buffer, include_jumps, include_indirect);
    
    // Second pass: disassemble and verify each potential reference
    for offset in potential_offsets {
        // Skip if we're too close to the end of the buffer
        if offset + 10 >= buffer.len() {
            continue;
        }
        
        // Disassemble a small chunk around the potential reference
        let chunk_start = if offset > 15 { offset - 15 } else { 0 };
        let chunk_end = if offset + 15 < buffer.len() { offset + 15 } else { buffer.len() };
        let chunk = &buffer[chunk_start..chunk_end];
        
        if let Ok(insns) = cs.disasm_all(chunk, region_addr.to_umem() + chunk_start as u64) {
            for insn in insns.iter() {
                // Check if this instruction contains our offset of interest
                let insn_start = insn.address() - region_addr.to_umem();
                let insn_end = insn_start + insn.bytes().len() as u64;
                
                if insn_start as usize <= offset && offset < insn_end as usize {
                    // Check if this instruction references our target
                    if let Some(xref_type) = is_reference_to(&insn, target_addr, include_jumps, include_indirect, &cs) {
                        // Get context instructions
                        let context = get_instruction_context(
                            &buffer,
                            offset,
                            context_count,
                            region_addr.to_umem(),
                            &cs,
                        );
                        
                        // Create result
                        let result = XrefResult {
                            address: insn.address(),
                            xref_type,
                            instruction: format!(
                                "{} {}",
                                insn.mnemonic().unwrap_or(""),
                                insn.op_str().unwrap_or("")
                            ),
                            context,
                        };
                        
                        results.push(result);
                    }
                }
            }
        }
    }
    
    results
}

// Helper function to find potential call/jump instruction offsets
fn find_potential_call_offsets(
    buffer: &[u8],
    include_jumps: bool,
    include_indirect: bool,
) -> Vec<usize> {
    let mut offsets = Vec::new();
    
    // Look for direct call (E8) instructions
    for i in 0..buffer.len().saturating_sub(5) {
        if buffer[i] == 0xE8 {
            offsets.push(i);
        }
    }
    
    // Look for direct jump (E9) instructions if requested
    if include_jumps {
        for i in 0..buffer.len().saturating_sub(5) {
            if buffer[i] == 0xE9 {
                offsets.push(i);
            }
        }
    }
    
    // Look for indirect call (FF 15) instructions if requested
    if include_indirect {
        for i in 0..buffer.len().saturating_sub(6) {
            if buffer[i] == 0xFF && buffer[i + 1] == 0x15 {
                offsets.push(i);
            }
        }
    }
    
    offsets
}