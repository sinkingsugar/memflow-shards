use crate::memflow_process_wrapper::MemflowProcessWrapper;
use crate::xref_scanner::{scan_region_for_xrefs, Arch};
use crate::MEMFLOW_PROCESS_TYPE;
use crate::protection_filter::protection_filter_matches;

use memflow::prelude::v1::*;
use shards::shard::Shard;
use shards::types::{common_type, AutoSeqVar, AutoTableVar, Context, ExposedTypes, InstanceData, ParamVar, Type, Types, Var, ANYS_TYPES};
use shards::shlog_debug;

// Define the FunctionXref Shard
#[derive(shards::shard)]
#[shard_info(
    "Memflow.FunctionXref",
    "Scans for cross-references to a specific function."
)]
pub struct MemflowFunctionXrefShard {
    #[shard_required]
    required: ExposedTypes,

    // Parameters
    #[shard_param("FunctionAddress", "Address of the target function.", [common_type::int, common_type::int_var])]
    function_address: ParamVar,

    #[shard_param("IncludeJumps", "Whether to include jumps in addition to calls.", [common_type::bool, common_type::bool_var])]
    include_jumps: ParamVar,

    #[shard_param("IncludeIndirect", "Whether to include indirect references.", [common_type::bool, common_type::bool_var])]
    include_indirect: ParamVar,

    #[shard_param("ContextInstructions", "Number of context instructions to include.", [common_type::int, common_type::int_var])]
    context_instructions: ParamVar,

    #[shard_param("Protection", "Memory protection to filter by (default: 'r-x').", [common_type::string, common_type::string_var])]
    protection: ParamVar,

    // Output results
    xref_results: AutoSeqVar,
}

impl Default for MemflowFunctionXrefShard {
    fn default() -> Self {
        Self {
            required: ExposedTypes::new(),
            function_address: ParamVar::default(),
            include_jumps: ParamVar::new(false.into()),
            include_indirect: ParamVar::new(false.into()),
            context_instructions: ParamVar::new(2.into()),
            protection: ParamVar::new(Var::ephemeral_string("r-x")),
            xref_results: AutoSeqVar::new(),
        }
    }
}

#[shards::shard_impl]
impl Shard for MemflowFunctionXrefShard {
    fn input_types(&mut self) -> &Types {
        &crate::MEMFLOW_PROCESS_TYPES // Takes process as input
    }

    fn output_types(&mut self) -> &Types {
        &ANYS_TYPES // Outputs a sequence of results
    }

    fn compose(&mut self, data: &InstanceData) -> std::result::Result<Type, &str> {
        self.compose_helper(data)?;
        Ok(self.output_types()[0])
    }

    fn warmup(&mut self, ctx: &Context) -> std::result::Result<(), &str> {
        self.warmup_helper(ctx)?;
        Ok(())
    }

    fn cleanup(&mut self, ctx: Option<&Context>) -> std::result::Result<(), &str> {
        self.xref_results = AutoSeqVar::new();
        self.cleanup_helper(ctx)?;
        Ok(())
    }

    fn activate(
        &mut self,
        _context: &Context,
        input: &Var,
    ) -> std::result::Result<Option<Var>, &str> {
        // Get the Process instance from input
        let process = unsafe {
            &mut *Var::from_ref_counted_object::<MemflowProcessWrapper>(
                input,
                &*MEMFLOW_PROCESS_TYPE,
            )?
        };

        // Get parameters
        let target_addr: i64 = self.function_address.get().as_ref().try_into()?;
        let include_jumps: bool = self.include_jumps.get().as_ref().try_into()?;
        let include_indirect: bool = self.include_indirect.get().as_ref().try_into()?;
        let context_count: i64 = self.context_instructions.get().as_ref().try_into()?;
        let protection_filter: &str = self.protection.get().as_ref().try_into()?;

        shlog_debug!(
            "Scanning for XREFs to function at 0x{:x}, include_jumps={}, include_indirect={}",
            target_addr,
            include_jumps,
            include_indirect
        );

        // Get memory maps with filtering for executable regions
        let maps = process.0.mapped_mem_vec(0);
        let filtered_maps: Vec<_> = maps
            .into_iter()
            .filter(|map| {
                // Filter by protection
                protection_filter_matches(map.2, protection_filter)
            })
            .collect();

        shlog_debug!("Filtered to {} memory regions", filtered_maps.len());

        self.xref_results.0.clear();

        // Get the architecture of the process
        // Default to X86_64 for simplicity
        let arch = Arch::X86_64;

        // Scan each memory region for references
        for map in filtered_maps {
            let base_addr = map.0;
            let size = map.1.to_umem() as usize;

            // Skip regions that are too small
            if size < 10 {
                continue;
            }

            shlog_debug!("Scanning region at 0x{:x} with size {}", base_addr.to_umem(), size);

            // Scan the region for references
            let xrefs = scan_region_for_xrefs(
                &mut process.0,
                base_addr,
                size,
                target_addr as u64,
                include_jumps,
                include_indirect,
                context_count as usize,
                arch,
            );

            // Add results to output
            for xref in xrefs {
                let mut result_entry = AutoTableVar::new();
                
                // Add basic information
                let address_var: Var = (xref.address as i64).into();
                let type_var = Var::ephemeral_string(xref.xref_type.to_string());
                let instruction_var = Var::ephemeral_string(&xref.instruction);
                
                result_entry.0.insert_fast_static("address", &address_var);
                result_entry.0.insert_fast_static("type", &type_var);
                result_entry.0.insert_fast_static("instruction", &instruction_var);
                
                // Add context instructions
                let mut context_seq = AutoSeqVar::new();
                for (_i, ctx_insn) in xref.context.iter().enumerate() {
                    let ctx_var = Var::ephemeral_string(ctx_insn);
                    context_seq.0.push(&ctx_var);
                }
                
                result_entry.0.insert_fast_static("context", &context_seq.0.0);
                
                self.xref_results.0.emplace_table(result_entry);
            }
        }

        Ok(Some(self.xref_results.0.0))
    }
}