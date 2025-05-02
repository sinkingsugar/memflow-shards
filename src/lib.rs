use protection_filter::protection_filter_matches;
use shards::core::register_shard;
use shards::ref_counted_object_type_impl;
use shards::shard::Shard;
use shards::types::{
    common_type,
    AutoSeqVar,
    AutoTableVar,
    ClonedVar,
    Context,
    ExposedTypes,
    InstanceData,
    ParamVar,
    TableVar,
    Type,
    Types,
    Var,
    ANYS_TYPES,
    ANY_TABLE_TYPES,
    ANY_TYPES,
    BYTES_TYPES,
    NONE_TYPES, // Input type
};
use shards::{fourCharacterCode, shlog_debug, shlog_error};

use ctor::ctor;
use lazy_static::lazy_static;

use memflow::prelude::v1::*;

mod protection_filter;
mod xref_scanner;
mod xref_shard;

// 1. Define static types for the Memflow Inventory object
lazy_static! {
    // Unique Vendor and Type IDs for the Inventory object
    static ref MEMFLOW_VENDOR_ID: i32 = fourCharacterCode(*b"MEMF"); // Example Vendor ID
    static ref MEMFLOW_OS_TYPE_ID: i32 = fourCharacterCode(*b"OS__"); // Example Type ID
    static ref MEMFLOW_PROCESS_TYPE_ID: i32 = fourCharacterCode(*b"PROC"); // Process Type ID
    static ref MEMFLOW_MODULE_TYPE_ID: i32 = fourCharacterCode(*b"MODL"); // Module Type ID
    static ref MEMFLOW_CACHED_PROCESS_TYPE_ID: i32 = fourCharacterCode(*b"CPRC"); // Cached Process Type ID

    // The Shards Type descriptor for the Inventory object
    pub static ref MEMFLOW_OS_TYPE: Type = Type::object(*MEMFLOW_VENDOR_ID, *MEMFLOW_OS_TYPE_ID);
    pub static ref MEMFLOW_OS_TYPE_VAR: Type = Type::context_variable(&[*MEMFLOW_OS_TYPE]);
    // A vector containing the type, useful for input/output_types
    pub static ref MEMFLOW_OS_TYPES: Vec<Type> = vec![*MEMFLOW_OS_TYPE];

    // Process type definitions
    pub static ref MEMFLOW_PROCESS_TYPE: Type = Type::object(*MEMFLOW_VENDOR_ID, *MEMFLOW_PROCESS_TYPE_ID);
    pub static ref MEMFLOW_PROCESS_TYPE_VAR: Type = Type::context_variable(&[*MEMFLOW_PROCESS_TYPE]);
    pub static ref MEMFLOW_PROCESS_TYPES: Vec<Type> = vec![*MEMFLOW_PROCESS_TYPE];

    // Module type definitions
    pub static ref MEMFLOW_MODULE_TYPE: Type = Type::object(*MEMFLOW_VENDOR_ID, *MEMFLOW_MODULE_TYPE_ID);
    pub static ref MEMFLOW_MODULE_TYPE_VAR: Type = Type::context_variable(&[*MEMFLOW_MODULE_TYPE]);
    pub static ref MEMFLOW_MODULE_TYPES: Vec<Type> = vec![*MEMFLOW_MODULE_TYPE];
}

mod memflow_os_wrapper {
    use super::*;

    // Wrapper struct to hold the OsInstanceArcBox
    #[derive(Clone)] // Clone is needed because OsInstanceArcBox is Clone
    pub struct MemflowOsWrapper(pub OsInstanceArcBox<'static>);

    ref_counted_object_type_impl!(MemflowOsWrapper);
}

pub mod memflow_process_wrapper {
    use super::*;

    // Process wrapper struct to hold the ProcessInstance
    pub struct MemflowProcessWrapper(pub ProcessInstanceArcBox<'static>);

    ref_counted_object_type_impl!(MemflowProcessWrapper);
}

mod memflow_module_wrapper {
    use super::*;

    // Module wrapper struct to hold the ModuleInfo
    #[derive(Clone)]
    pub struct MemflowModuleWrapper(pub ModuleInfo);

    ref_counted_object_type_impl!(MemflowModuleWrapper);
}

// 4. Define the Shard struct
#[derive(shards::shard)]
#[shard_info(
    "Memflow.Os",
    "Creates a Memflow OS instance using a specified connector and OS plugin."
)]
struct MemflowOsShard {
    #[shard_required]
    required: ExposedTypes,

    // Parameters
    #[shard_param("Connector", "The name of the memflow connector to use.", [common_type::none, common_type::string])]
    connector_name: ClonedVar,
    #[shard_param("Os", "The name of the OS plugin to use (e.g., 'win32', 'linux').", [common_type::string])]
    os_name: ClonedVar,

    // Store the output OS object
    output_os: ClonedVar,
}

impl Default for MemflowOsShard {
    fn default() -> Self {
        let default_os_name = Var::ephemeral_string("native");
        Self {
            required: ExposedTypes::new(),
            connector_name: ClonedVar::default(),
            os_name: default_os_name.into(),
            output_os: ClonedVar::default(),
        }
    }
}

// 5. Implement the Shard trait
#[shards::shard_impl]
impl Shard for MemflowOsShard {
    fn input_types(&mut self) -> &Types {
        &NONE_TYPES // Takes no input
    }

    fn output_types(&mut self) -> &Types {
        &MEMFLOW_OS_TYPES // Outputs our custom OS object
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
        // Drop the OS instance when the shard is cleaned up
        self.output_os = ClonedVar::default();

        self.cleanup_helper(ctx)?;
        Ok(())
    }

    fn activate(
        &mut self,
        _context: &Context,
        _input: &Var,
    ) -> std::result::Result<Option<Var>, &str> {
        // Retrieve parameters
        let connector_name: &str = self.connector_name.0.as_ref().try_into().unwrap_or("");
        let os_name: &str = self.os_name.0.as_ref().try_into()?;

        shlog_debug!(
            "Attempting to create OS instance: connector='{}', os='{}'",
            connector_name,
            os_name
        );

        // Create inventory and OS instance
        let mut inventory = Inventory::scan();

        if connector_name != "" {
            let os = inventory
                .builder()
                .connector(connector_name)
                .os(os_name)
                .build()
                .map_err(|e| {
                    shlog_error!("Failed to create OS instance: {}", e);
                    "Failed to create OS instance."
                })?;

            self.output_os =
                Var::new_ref_counted(memflow_os_wrapper::MemflowOsWrapper(os), &MEMFLOW_OS_TYPE)
                    .into();
        } else {
            let os = inventory.builder().os(os_name).build().map_err(|e| {
                shlog_error!("Failed to create OS instance: {}", e);
                "Failed to create OS instance."
            })?;

            self.output_os =
                Var::new_ref_counted(memflow_os_wrapper::MemflowOsWrapper(os), &MEMFLOW_OS_TYPE)
                    .into();
        }

        Ok(Some(self.output_os.0))
    }
}

// Define the ProcessList Shard
#[derive(shards::shard)]
#[shard_info(
    "Memflow.ProcessList",
    "Returns a list of processes from a Memflow OS instance."
)]
struct MemflowProcessListShard {
    #[shard_required]
    required: ExposedTypes,

    // Parameters - OS instance to get process list from
    #[shard_param("Os", "The Memflow OS instance to get process list from.", [*MEMFLOW_OS_TYPE, *MEMFLOW_OS_TYPE_VAR])]
    os_instance: ParamVar,

    // Output list of processes as tables
    process_list: AutoTableVar,
}

// Define the KernelModuleList Shard
#[derive(shards::shard)]
#[shard_info(
    "Memflow.KernelModuleList",
    "Returns a list of kernel modules from a Memflow OS instance."
)]
struct MemflowKernelModuleListShard {
    #[shard_required]
    required: ExposedTypes,

    // Parameters - OS instance to get kernel module list from
    #[shard_param("Os", "The Memflow OS instance to get kernel module list from.", [*MEMFLOW_OS_TYPE, *MEMFLOW_OS_TYPE_VAR])]
    os_instance: ParamVar,

    // Output list of kernel modules as tables
    module_list: AutoSeqVar,
}

impl Default for MemflowProcessListShard {
    fn default() -> Self {
        Self {
            required: ExposedTypes::new(),
            os_instance: ParamVar::new_named("memflow/default-os"),
            process_list: AutoTableVar::new(),
        }
    }
}

impl Default for MemflowKernelModuleListShard {
    fn default() -> Self {
        Self {
            required: ExposedTypes::new(),
            os_instance: ParamVar::new_named("memflow/default-os"),
            module_list: AutoSeqVar::new(),
        }
    }
}

#[shards::shard_impl]
impl Shard for MemflowProcessListShard {
    fn input_types(&mut self) -> &Types {
        &NONE_TYPES // Takes no input
    }

    fn output_types(&mut self) -> &Types {
        &ANY_TABLE_TYPES // Outputs sequence of process data tables
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
        self.process_list = AutoTableVar::new();
        self.cleanup_helper(ctx)?;
        Ok(())
    }

    fn activate(
        &mut self,
        _context: &Context,
        _input: &Var,
    ) -> std::result::Result<Option<Var>, &str> {
        // Get the OS instance from parameter
        let os_var = &self.os_instance.get();

        let os = unsafe {
            &mut *Var::from_ref_counted_object::<memflow_os_wrapper::MemflowOsWrapper>(
                os_var,
                &*MEMFLOW_OS_TYPE,
            )?
        };

        shlog_debug!("Getting process list from OS instance");

        let process_list = os.0.process_info_list().map_err(|e| {
            shlog_error!("Failed to get process list: {}", e);
            "Failed to get process list."
        })?;

        self.process_list.0.clear();

        for process in process_list {
            let mut process_table = AutoTableVar::new();

            let name = process.name.to_string();
            let name_str = Var::ephemeral_string(&name);
            process_table.0.insert_fast_static("name", &name_str);

            let pid: Var = process.pid.into();

            let path = process.path.to_string();
            let path_str = Var::ephemeral_string(&path);
            process_table.0.insert_fast_static("path", &path_str);

            let command_line = process.command_line.to_string();
            let command_line_str = Var::ephemeral_string(&command_line);
            process_table
                .0
                .insert_fast_static("command_line", &command_line_str);

            self.process_list.0.emplace_table(pid, process_table);
        }

        Ok(Some(self.process_list.0 .0))
    }
}

// Define the Process Shard
#[derive(shards::shard)]
#[shard_info(
    "Memflow.Process",
    "Creates a handle to a specific process from a Memflow OS instance."
)]
struct MemflowProcessShard {
    #[shard_required]
    required: ExposedTypes,

    // Parameters
    #[shard_param("Os", "The Memflow OS instance to get the process from.", [*MEMFLOW_OS_TYPE, *MEMFLOW_OS_TYPE_VAR])]
    os_instance: ParamVar,

    #[shard_param("Name", "Process name to search for (optional).", [common_type::none, common_type::string, common_type::string_var])]
    process_name: ParamVar,

    #[shard_param("Pid", "Process ID to search for (optional).", [common_type::none, common_type::int, common_type::int_var])]
    process_pid: ParamVar,

    // Store the output Process object
    output_process: ClonedVar,
}

// Define the Module Info Shard
#[derive(shards::shard)]
#[shard_info(
    "Memflow.ModuleInfo",
    "Gets information about a specific module from a process."
)]
struct MemflowModuleInfoShard {
    #[shard_required]
    required: ExposedTypes,

    // Parameters
    #[shard_param("Process", "The Memflow Process instance to get the module from.", [*MEMFLOW_PROCESS_TYPE, *MEMFLOW_PROCESS_TYPE_VAR])]
    process_instance: ParamVar,

    #[shard_param("Name", "Module name to search for.", [common_type::string, common_type::string_var])]
    module_name: ParamVar,

    // Store the output Module object
    output_module: ClonedVar,
}

impl Default for MemflowProcessShard {
    fn default() -> Self {
        Self {
            required: ExposedTypes::new(),
            os_instance: ParamVar::new_named("memflow/default-os"),
            process_name: ParamVar::default(),
            process_pid: ParamVar::default(),
            output_process: ClonedVar::default(),
        }
    }
}

impl Default for MemflowModuleInfoShard {
    fn default() -> Self {
        Self {
            required: ExposedTypes::new(),
            process_instance: ParamVar::default(),
            module_name: ParamVar::default(),
            output_module: ClonedVar::default(),
        }
    }
}
#[shards::shard_impl]
impl Shard for MemflowModuleInfoShard {
    fn input_types(&mut self) -> &Types {
        &NONE_TYPES // Takes no input
    }

    fn output_types(&mut self) -> &Types {
        &MEMFLOW_MODULE_TYPES // Outputs our custom Module object
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
        // Drop the Module instance when the shard is cleaned up
        self.output_module = ClonedVar::default();
        self.cleanup_helper(ctx)?;
        Ok(())
    }

    fn activate(
        &mut self,
        _context: &Context,
        _input: &Var,
    ) -> std::result::Result<Option<Var>, &str> {
        // Get the Process instance from parameter
        let process_var = &self.process_instance.get();
        let process = unsafe {
            &mut *Var::from_ref_counted_object::<memflow_process_wrapper::MemflowProcessWrapper>(
                process_var,
                &*MEMFLOW_PROCESS_TYPE,
            )?
        };

        // Get module name parameter
        let module_name: &str = self.module_name.get().as_ref().try_into()?;

        shlog_debug!("Searching for module by name: {}", module_name);

        // Find module by name
        let module_info = process.0.module_by_name(module_name).map_err(|e| {
            shlog_error!("Failed to find module by name '{}': {}", module_name, e);
            "Module not found by name."
        })?;

        // Create and return the module object
        self.output_module = Var::new_ref_counted(
            memflow_module_wrapper::MemflowModuleWrapper(module_info),
            &MEMFLOW_MODULE_TYPE,
        )
        .into();

        Ok(Some(self.output_module.0))
    }
}

#[shards::shard_impl]
impl Shard for MemflowProcessShard {
    fn input_types(&mut self) -> &Types {
        &NONE_TYPES // Takes no input
    }

    fn output_types(&mut self) -> &Types {
        &MEMFLOW_PROCESS_TYPES // Outputs our custom Process object
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
        // Drop the Process instance when the shard is cleaned up
        self.output_process = ClonedVar::default();
        self.cleanup_helper(ctx)?;
        Ok(())
    }

    fn activate(
        &mut self,
        _context: &Context,
        _input: &Var,
    ) -> std::result::Result<Option<Var>, &str> {
        // Get the OS instance from parameter
        let os_var = &self.os_instance.get();
        let os = unsafe {
            &mut *Var::from_ref_counted_object::<memflow_os_wrapper::MemflowOsWrapper>(
                os_var,
                &*MEMFLOW_OS_TYPE,
            )?
        };

        // Try to find the process by name or pid
        let process_instance = if !self.process_name.get().is_none() {
            // Find by name
            let name: &str = self.process_name.get().as_ref().try_into()?;
            shlog_debug!("Searching for process by name: {}", name);

            os.0.process_by_name(name).map_err(|e| {
                shlog_error!("Failed to find process by name '{}': {}", name, e);
                "Process not found by name."
            })?
        } else if !self.process_pid.get().is_none() {
            // Find by PID
            let pid: i64 = self.process_pid.get().as_ref().try_into()?;
            let pid_u32 = pid as u32;
            shlog_debug!("Searching for process by PID: {}", pid_u32);

            os.0.process_by_pid(pid_u32).map_err(|e| {
                shlog_error!("Failed to find process by PID {}: {}", pid_u32, e);
                "Process not found by PID."
            })?
        } else {
            return Err("Either Name or Pid parameter must be provided.");
        };

        // Create and return the process object
        self.output_process = Var::new_ref_counted(
            memflow_process_wrapper::MemflowProcessWrapper(process_instance),
            &MEMFLOW_PROCESS_TYPE,
        )
        .into();
        Ok(Some(self.output_process.0))
    }
}

// Define the MemMap Shard
#[derive(shards::shard)]
#[shard_info(
    "Memflow.MemMap",
    "Retrieves memory mappings from a Memflow Process instance."
)]
struct MemflowMemMapShard {
    #[shard_required]
    required: ExposedTypes,

    // Parameters
    #[shard_param("GapSize", "Size of gaps to ignore between memory regions (in bytes).", [common_type::int, common_type::int_var])]
    gap_size: ParamVar,

    // Output memory maps as table
    mem_maps: AutoSeqVar,
}

impl Default for MemflowMemMapShard {
    fn default() -> Self {
        Self {
            required: ExposedTypes::new(),
            gap_size: ParamVar::new(0.into()),
            mem_maps: AutoSeqVar::new(),
        }
    }
}

#[shards::shard_impl]
impl Shard for MemflowMemMapShard {
    fn input_types(&mut self) -> &Types {
        &MEMFLOW_PROCESS_TYPES // Takes process as input
    }

    fn output_types(&mut self) -> &Types {
        &ANYS_TYPES // Outputs a table of memory mappings
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
        self.mem_maps = AutoSeqVar::new();
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
            &mut *Var::from_ref_counted_object::<memflow_process_wrapper::MemflowProcessWrapper>(
                input,
                &*MEMFLOW_PROCESS_TYPE,
            )?
        };

        // Get gap size parameter
        let gap_size: i64 = self.gap_size.get().as_ref().try_into()?;

        shlog_debug!(
            "Getting memory maps for process with gap size: {}",
            gap_size
        );

        // Get memory maps
        let maps = process.0.mapped_mem_vec(gap_size);

        self.mem_maps.0.clear();

        // Build output table with memory maps
        for map in maps {
            let address: Var = map.0.to_umem().into();
            let size: Var = map.1.to_umem().into();
            let prot: Var = Var::ephemeral_string(&format!("{:?}", map.2));

            // Insert into table
            let mut tab = AutoTableVar::new();
            tab.0.insert_fast_static("address", &address);
            tab.0.insert_fast_static("size", &size);
            tab.0.insert_fast_static("protection", &prot);
            self.mem_maps.0.emplace_table(tab);
        }

        Ok(Some(self.mem_maps.0 .0))
    }
}

#[shards::shard_impl]
impl Shard for MemflowKernelModuleListShard {
    fn input_types(&mut self) -> &Types {
        &NONE_TYPES // Takes no input
    }

    fn output_types(&mut self) -> &Types {
        &ANYS_TYPES // Outputs sequence of module data tables
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
        self.module_list = AutoSeqVar::new();
        self.cleanup_helper(ctx)?;
        Ok(())
    }

    fn activate(
        &mut self,
        _context: &Context,
        _input: &Var,
    ) -> std::result::Result<Option<Var>, &str> {
        // Get the OS instance from parameter
        let os_var = &self.os_instance.get();

        let os = unsafe {
            &mut *Var::from_ref_counted_object::<memflow_os_wrapper::MemflowOsWrapper>(
                os_var,
                &*MEMFLOW_OS_TYPE,
            )?
        };

        shlog_debug!("Getting kernel module list from OS instance");

        let module_list = os.0.module_list().map_err(|e| {
            shlog_error!("Failed to get kernel module list: {}", e);
            "Failed to get kernel module list."
        })?;

        self.module_list.0.clear();

        for module in module_list {
            // Create column values for module information
            let address: Var = module.address.to_umem().into();
            let base: Var = module.base.to_umem().into();
            let size: Var = module.size.into();
            let name = Var::ephemeral_string(&module.name);
            let path = Var::ephemeral_string(&module.path);

            // Insert into table
            let mut tab = AutoTableVar::new();
            tab.0.insert_fast_static("address", &address);
            tab.0.insert_fast_static("base", &base);
            tab.0.insert_fast_static("size", &size);
            tab.0.insert_fast_static("name", &name);
            tab.0.insert_fast_static("path", &path);

            self.module_list.0.emplace_table(tab);
        }

        Ok(Some(self.module_list.0 .0))
    }
}

// Define the ReadMemory Shard
#[derive(shards::shard)]
#[shard_info(
    "Memflow.ReadMemory",
    "Reads memory from a specific address in a process."
)]
struct MemflowReadMemoryShard {
    #[shard_required]
    required: ExposedTypes,

    // Parameters
    #[shard_param("Address", "Memory address to read from.", [common_type::int, common_type::int_var])]
    address: ParamVar,

    #[shard_param("Size", "Number of bytes to read.", [common_type::int, common_type::int_var])]
    size: ParamVar,

    // Output buffer
    output_buffer: ClonedVar,
}

impl Default for MemflowReadMemoryShard {
    fn default() -> Self {
        Self {
            required: ExposedTypes::new(),
            address: ParamVar::new(0.into()),
            size: ParamVar::new(1.into()),
            output_buffer: ClonedVar::default(),
        }
    }
}

#[shards::shard_impl]
impl Shard for MemflowReadMemoryShard {
    fn input_types(&mut self) -> &Types {
        &MEMFLOW_PROCESS_TYPES // Takes process as input
    }

    fn output_types(&mut self) -> &Types {
        &BYTES_TYPES // Outputs an array of bytes
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
        self.output_buffer = ClonedVar::default();
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
            &mut *Var::from_ref_counted_object::<memflow_process_wrapper::MemflowProcessWrapper>(
                input,
                &*MEMFLOW_PROCESS_TYPE,
            )?
        };

        // Get address and size parameters
        let address: i64 = self.address.get().as_ref().try_into()?;
        let size: i64 = self.size.get().as_ref().try_into()?;

        if size <= 0 {
            return Err("Size must be greater than 0");
        }

        let size_usize = size as usize;
        let address_umem = address as umem;

        shlog_debug!(
            "Reading memory at address: 0x{:x}, size: {} bytes",
            address_umem,
            size_usize
        );

        // Create buffer to hold the read data
        let mut buffer = vec![0u8; size_usize];

        // Read memory into buffer
        process
            .0
            .read_raw_into(Address::from(address_umem), &mut buffer)
            .map_err(|e| {
                shlog_error!("Failed to read memory: {}", e);
                "Failed to read memory from process."
            })?;

        self.output_buffer = buffer.as_slice().into();
        Ok(Some(self.output_buffer.0))
    }
}

// Define the BatchReadMemory Shard for more efficient reading
#[derive(shards::shard)]
#[shard_info(
    "Memflow.BatchReadMemory",
    "Reads memory from multiple addresses in a process using batched operations."
)]
struct MemflowBatchReadMemoryShard {
    #[shard_required]
    required: ExposedTypes,

    // Parameters - table of addresses and sizes
    #[shard_param("Reads", "Table of memory reads with 'address' and 'size' fields.", [common_type::any_table, common_type::any_table_var])]
    reads: ParamVar,

    // Output table of results
    output_results: AutoTableVar,
}

impl Default for MemflowBatchReadMemoryShard {
    fn default() -> Self {
        Self {
            required: ExposedTypes::new(),
            reads: ParamVar::default(),
            output_results: AutoTableVar::new(),
        }
    }
}

#[shards::shard_impl]
impl Shard for MemflowBatchReadMemoryShard {
    fn input_types(&mut self) -> &Types {
        &MEMFLOW_PROCESS_TYPES // Takes process as input
    }

    fn output_types(&mut self) -> &Types {
        &ANY_TABLE_TYPES // Outputs a table of results
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
        if self.reads.is_none() {
            return Err("Missing 'reads' parameter");
        }
        self.output_results = AutoTableVar::new();
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
            &mut *Var::from_ref_counted_object::<memflow_process_wrapper::MemflowProcessWrapper>(
                input,
                &*MEMFLOW_PROCESS_TYPE,
            )?
        };

        // Get reads table
        let reads_var = self.reads.get();
        let reads_table = reads_var.as_table()?;

        shlog_debug!("Performing batch memory read operation");

        // Prepare data for batch operations
        struct ReadOp {
            key: Var,
            address: umem,
            buffer: Vec<u8>,
        }

        let mut read_ops = Vec::new();

        // Collect all read operations first
        for (key, _) in reads_table.iter() {
            let read_entry = reads_table.get(key).unwrap();
            let read_table = read_entry.as_table()?;

            // Get address and size from the table
            let address_var = read_table
                .get(Var::ephemeral_string("address"))
                .ok_or("Missing 'address' field in read entry")?;
            let size_var = read_table
                .get(Var::ephemeral_string("size"))
                .ok_or("Missing 'size' field in read entry")?;

            let address: i64 = address_var.as_ref().try_into()?;
            let size: i64 = size_var.as_ref().try_into()?;

            if size <= 0 {
                return Err("Size must be greater than 0");
            }

            let size_usize = size as usize;
            let address_umem = address as umem;

            // Create read operation
            read_ops.push(ReadOp {
                key,
                address: address_umem,
                buffer: vec![0u8; size_usize],
            });
        }

        // Now perform the batch read
        {
            let mut batcher = process.0.batcher();

            // Set up all read operations in the batcher
            for op in &mut read_ops {
                batcher.read_raw_into(Address::from(op.address), &mut op.buffer);
            }

            // Execute all read operations in batch
            batcher.commit_rw().map_err(|e| {
                shlog_error!("Failed to execute batch memory read: {}", e);
                "Failed to read memory from process."
            })?;
        }

        self.output_results.0.clear();

        // Process results
        for op in read_ops {
            let bytes = Var::ephemeral_slice(op.buffer.as_slice());
            // Add to results table
            self.output_results.0.insert_fast(op.key, &bytes);
        }

        Ok(Some(self.output_results.0 .0))
    }
}

// Define the ProcessModuleList Shard
#[derive(shards::shard)]
#[shard_info(
    "Memflow.ProcessModuleList",
    "Returns a list of modules from a specific process."
)]
struct MemflowProcessModuleListShard {
    #[shard_required]
    required: ExposedTypes,

    // Output list of modules as sequence of tables
    module_list: AutoSeqVar,
}

impl Default for MemflowProcessModuleListShard {
    fn default() -> Self {
        Self {
            required: ExposedTypes::new(),
            module_list: AutoSeqVar::new(),
        }
    }
}

#[shards::shard_impl]
impl Shard for MemflowProcessModuleListShard {
    fn input_types(&mut self) -> &Types {
        &MEMFLOW_PROCESS_TYPES // Takes process as input
    }

    fn output_types(&mut self) -> &Types {
        &ANYS_TYPES // Outputs sequence of module data tables
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
        self.module_list = AutoSeqVar::new();
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
            &mut *Var::from_ref_counted_object::<memflow_process_wrapper::MemflowProcessWrapper>(
                input,
                &*MEMFLOW_PROCESS_TYPE,
            )?
        };

        shlog_debug!("Getting module list from process");

        let module_list = process.0.module_list().map_err(|e| {
            shlog_error!("Failed to get process module list: {}", e);
            "Failed to get process module list."
        })?;

        self.module_list.0.clear();

        for module in module_list {
            // Create column values for module information
            let base: Var = module.base.to_umem().into();
            let size: Var = module.size.into();
            let name = Var::ephemeral_string(&module.name);
            let path = Var::ephemeral_string(&module.path);
            let arch = Var::ephemeral_string(&format!("{:?}", module.arch));

            // Insert into table
            let mut tab = AutoTableVar::new();
            tab.0.insert_fast_static("base", &base);
            tab.0.insert_fast_static("size", &size);
            tab.0.insert_fast_static("name", &name);
            tab.0.insert_fast_static("path", &path);
            tab.0.insert_fast_static("arch", &arch);

            self.module_list.0.emplace_table(tab);
        }

        Ok(Some(self.module_list.0 .0))
    }
}

// Define the WriteMemory Shard
#[derive(shards::shard)]
#[shard_info(
    "Memflow.WriteMemory",
    "Writes memory to a specific address in a process."
)]
struct MemflowWriteMemoryShard {
    #[shard_required]
    required: ExposedTypes,

    // Parameters
    #[shard_param("Address", "Memory address to write to.", [common_type::int, common_type::int_var])]
    address: ParamVar,

    #[shard_param("Process", "The Memflow Process instance to write to.", [*MEMFLOW_PROCESS_TYPE, *MEMFLOW_PROCESS_TYPE_VAR])]
    process_instance: ParamVar,

    // Output status
    output_status: ClonedVar,
}

impl Default for MemflowWriteMemoryShard {
    fn default() -> Self {
        Self {
            required: ExposedTypes::new(),
            address: ParamVar::new(0.into()),
            process_instance: ParamVar::default(),
            output_status: ClonedVar::default(),
        }
    }
}

#[shards::shard_impl]
impl Shard for MemflowWriteMemoryShard {
    fn input_types(&mut self) -> &Types {
        &BYTES_TYPES // Takes bytes as input to write
    }

    fn output_types(&mut self) -> &Types {
        &NONE_TYPES // No output, just success/failure
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
        self.output_status = ClonedVar::default();
        self.cleanup_helper(ctx)?;
        Ok(())
    }

    fn activate(
        &mut self,
        _context: &Context,
        input: &Var,
    ) -> std::result::Result<Option<Var>, &str> {
        // Get the Process instance from parameter
        let process_var = &self.process_instance.get();
        let process = unsafe {
            &mut *Var::from_ref_counted_object::<memflow_process_wrapper::MemflowProcessWrapper>(
                process_var,
                &*MEMFLOW_PROCESS_TYPE,
            )?
        };

        // Get address parameter
        let address: i64 = self.address.get().as_ref().try_into()?;
        let address_umem = address as umem;

        // Get data to write from input
        let data: &[u8] = input.try_into()?;
        if data.is_empty() {
            return Err("No data to write");
        }

        shlog_debug!(
            "Writing memory at address: 0x{:x}, size: {} bytes",
            address_umem,
            data.len()
        );

        // Write memory
        process
            .0
            .write_raw(Address::from(address_umem), data)
            .map_err(|e| {
                shlog_error!("Failed to write memory: {}", e);
                "Failed to write memory to process."
            })?;

        // Return success
        self.output_status = Var::new_bool(true).into();
        Ok(None)
    }
}

// Define the BatchWriteMemory Shard for more efficient writing
#[derive(shards::shard)]
#[shard_info(
    "Memflow.BatchWriteMemory",
    "Writes memory to multiple addresses in a process using batched operations."
)]
struct MemflowBatchWriteMemoryShard {
    #[shard_required]
    required: ExposedTypes,

    // Parameters - table of addresses and data
    #[shard_param("Writes", "Table of memory writes with 'address' and 'data' fields.", [common_type::any_table, common_type::any_table_var])]
    writes: ParamVar,

    #[shard_param("Process", "The Memflow Process instance to write to.", [*MEMFLOW_PROCESS_TYPE, *MEMFLOW_PROCESS_TYPE_VAR])]
    process_instance: ParamVar,
}

impl Default for MemflowBatchWriteMemoryShard {
    fn default() -> Self {
        Self {
            required: ExposedTypes::new(),
            writes: ParamVar::default(),
            process_instance: ParamVar::default(),
        }
    }
}

#[shards::shard_impl]
impl Shard for MemflowBatchWriteMemoryShard {
    fn input_types(&mut self) -> &Types {
        &ANY_TYPES
    }

    fn output_types(&mut self) -> &Types {
        &ANY_TYPES
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
        if self.writes.is_none() {
            return Err("Missing 'writes' parameter");
        }
        self.cleanup_helper(ctx)?;
        Ok(())
    }

    fn activate(
        &mut self,
        _context: &Context,
        _input: &Var,
    ) -> std::result::Result<Option<Var>, &str> {
        // Get the Process instance from parameter
        let process_var = &self.process_instance.get();
        let process = unsafe {
            &mut *Var::from_ref_counted_object::<memflow_process_wrapper::MemflowProcessWrapper>(
                process_var,
                &*MEMFLOW_PROCESS_TYPE,
            )?
        };

        // Get writes table
        let writes_var = self.writes.get();
        let writes_table = writes_var.as_table()?;

        shlog_debug!("Performing batch memory write operation");

        // Prepare data for batch operations
        struct WriteOp {
            address: umem,
            data: Vec<u8>,
        }

        let mut write_ops = Vec::new();

        // Collect all write operations first
        for (key, _) in writes_table.iter() {
            let write_entry = writes_table.get(key).unwrap();
            let write_table = write_entry.as_table()?;

            // Get address and data from the table
            let address_var = write_table
                .get(Var::ephemeral_string("address"))
                .ok_or("Missing 'address' field in write entry")?;
            let data_var = write_table
                .get(Var::ephemeral_string("data"))
                .ok_or("Missing 'data' field in write entry")?;

            let address: i64 = address_var.as_ref().try_into()?;
            let data: &[u8] = data_var.try_into()?;

            if data.is_empty() {
                return Err("Empty data in write entry");
            }

            let address_umem = address as umem;

            // Create write operation
            write_ops.push(WriteOp {
                address: address_umem,
                data: data.to_vec(),
            });
        }

        // Now perform the batch write
        {
            let mut batcher = process.0.batcher();

            // Set up all write operations in the batcher
            for op in &write_ops {
                batcher.write_raw_into(Address::from(op.address), &op.data);
            }

            // Execute all write operations in batch
            batcher.commit_rw().map_err(|e| {
                shlog_error!("Failed to execute batch memory write: {}", e);
                "Failed to write memory to process."
            })?;
        }

        Ok(None)
    }
}

// Define the MemoryScan Shard for basic memory scanning
#[derive(shards::shard)]
#[shard_info(
    "Memflow.MemoryScan",
    "Scans process memory for specific values or patterns."
)]
struct MemflowMemoryScanShard {
    #[shard_required]
    required: ExposedTypes,

    // Parameters
    #[shard_param("ValueType", "Type of value to scan for: 'int', 'float', 'double', 'string', 'bytes'.", [common_type::string, common_type::string_var])]
    value_type: ParamVar,

    #[shard_param("Value", "Value to scan for.", [common_type::any, common_type::any_var])]
    value: ParamVar,

    #[shard_param("Alignment", "Memory alignment for the scan (default: 1).", [common_type::none, common_type::int, common_type::int_var])]
    alignment: ParamVar,

    #[shard_param("MinSize", "Minimum size of memory regions to scan (default: 4096).", [common_type::none, common_type::int, common_type::int_var])]
    min_size: ParamVar,

    #[shard_param("MaxSize", "Maximum size of memory regions to scan (default: no limit).", [common_type::none, common_type::int, common_type::int_var])]
    max_size: ParamVar,

    #[shard_param("Protection", "Memory protection to filter by (e.g., 'r--', 'rw-', 'r-x').", [common_type::none, common_type::string, common_type::string_var])]
    protection: ParamVar,

    #[shard_param("PreviousScan", "Results from a previous scan for incremental scanning.", [common_type::none, common_type::any_table, common_type::any_table_var])]
    previous_scan: ParamVar,

    #[shard_param("CompareType", "For incremental scans: 'equal', 'notequal', 'greater', 'less', 'changed', 'unchanged'.", [common_type::none, common_type::string, common_type::string_var])]
    compare_type: ParamVar,

    // Output results
    scan_results: AutoSeqVar,
}

impl Default for MemflowMemoryScanShard {
    fn default() -> Self {
        Self {
            required: ExposedTypes::new(),
            value_type: ParamVar::new(Var::ephemeral_string("int")),
            value: ParamVar::default(),
            alignment: ParamVar::new(1.into()),
            min_size: ParamVar::new(4096.into()),
            max_size: ParamVar::default(),
            protection: ParamVar::default(),
            previous_scan: ParamVar::default(),
            compare_type: ParamVar::default(),
            scan_results: AutoSeqVar::new(),
        }
    }
}

#[shards::shard_impl]
impl Shard for MemflowMemoryScanShard {
    fn input_types(&mut self) -> &Types {
        &MEMFLOW_PROCESS_TYPES // Takes process as input
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
        self.scan_results = AutoSeqVar::new();
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
            &mut *Var::from_ref_counted_object::<memflow_process_wrapper::MemflowProcessWrapper>(
                input,
                &*MEMFLOW_PROCESS_TYPE,
            )?
        };

        // Get parameters
        let value_type: &str = self.value_type.get().as_ref().try_into()?;
        let alignment: i64 = self.alignment.get().as_ref().try_into().unwrap_or(1);
        let min_size: i64 = self.min_size.get().as_ref().try_into().unwrap_or(4096);
        let max_size: Option<i64> = if self.max_size.get().is_none() {
            None
        } else {
            Some(self.max_size.get().as_ref().try_into()?)
        };

        // Parse protection filter if provided
        let protection_filter = if self.protection.get().is_none() {
            None
        } else {
            let prot_str: &str = self.protection.get().as_ref().try_into()?;
            Some(prot_str)
        };

        // Get memory maps with filtering
        let maps = process.0.mapped_mem_vec(0);
        let filtered_maps: Vec<_> = maps
            .into_iter()
            .filter(|map| {
                // Filter by size
                let size = map.1.to_umem() as i64;
                if size < min_size {
                    return false;
                }
                if let Some(max) = max_size {
                    if size > max {
                        return false;
                    }
                }

                // Filter by protection
                if let Some(prot_filter) = protection_filter {
                    if !protection_filter_matches(map.2, prot_filter) {
                        return false;
                    }
                }

                true
            })
            .collect();

        shlog_debug!(
            "Scanning memory with value type: {}, filtered to {} regions",
            value_type,
            filtered_maps.len()
        );

        // Prepare the value to search for
        let search_value = match value_type {
            "int" => {
                let val: i64 = self.value.get().as_ref().try_into()?;
                ScanValue::Integer(val)
            }
            "float" => {
                let val: f32 = self.value.get().as_ref().try_into()?;
                ScanValue::Float(val)
            }
            "double" => {
                let val: f64 = self.value.get().as_ref().try_into()?;
                ScanValue::Double(val)
            }
            "string" => {
                let val: &str = self.value.get().as_ref().try_into()?;
                ScanValue::String(val.to_string())
            }
            "bytes" => {
                let val: &[u8] = self.value.get().as_ref().try_into()?;
                ScanValue::Bytes(val.to_vec())
            }
            _ => return Err("Unsupported value type"),
        };

        // Check if this is an incremental scan
        let incremental_scan = !self.previous_scan.get().is_none();
        let compare_type = if incremental_scan {
            let compare_type_str: &str = self.compare_type.get().as_ref().try_into()?;
            Some(match compare_type_str {
                "equal" => CompareType::Equal,
                "notequal" => CompareType::NotEqual,
                "greater" => CompareType::Greater,
                "less" => CompareType::Less,
                "changed" => CompareType::Changed,
                "unchanged" => CompareType::Unchanged,
                _ => return Err("Unsupported compare type"),
            })
        } else {
            None
        };

        // Get previous scan results if this is an incremental scan
        let previous_results = if incremental_scan {
            let prev_var = self.previous_scan.get();
            let prev_table = prev_var.as_table()?;
            Some(prev_table)
        } else {
            None
        };

        // Perform the scan
        self.scan_results.0.clear();

        let alignment_usize = alignment as usize;

        for map in filtered_maps {
            let base_addr = map.0.to_umem();
            let size = map.1.to_umem() as usize;

            // Skip regions that are too small
            if size < search_value.size() {
                continue;
            }

            // Read the memory region
            let mut buffer = vec![0u8; size];
            match process
                .0
                .read_raw_into(Address::from(base_addr), &mut buffer)
            {
                Ok(_) => {
                    // Scan the buffer for matches
                    let matches = scan_buffer(
                        &buffer,
                        &search_value,
                        alignment_usize,
                        base_addr,
                        previous_results,
                        compare_type.as_ref(),
                    );

                    for result in matches {
                        let address: Var = result.address.into();
                        let value = match &search_value {
                            ScanValue::Integer(_) => Var::new_int(result.value_int),
                            ScanValue::Float(_) => Var::new_float(result.value_float.into()),
                            ScanValue::Double(_) => Var::new_float(result.value_double),
                            ScanValue::String(_) => Var::ephemeral_string(&result.value_string),
                            ScanValue::Bytes(_) => {
                                Var::ephemeral_slice(result.value_bytes.as_slice())
                            }
                        };

                        let mut result_entry = AutoTableVar::new();
                        result_entry.0.insert_fast_static("address", &address);
                        result_entry.0.insert_fast_static("value", &value);

                        self.scan_results.0.emplace_table(result_entry);
                    }
                }
                Err(e) => {
                    shlog_debug!("Failed to read memory region at 0x{:x}: {}", base_addr, e);
                    continue;
                }
            }
        }

        Ok(Some(self.scan_results.0 .0))
    }
}

// Helper enum for scan value types
enum ScanValue {
    Integer(i64),
    Float(f32),
    Double(f64),
    String(String),
    Bytes(Vec<u8>),
}

impl ScanValue {
    fn size(&self) -> usize {
        match self {
            ScanValue::Integer(_) => std::mem::size_of::<i64>(),
            ScanValue::Float(_) => std::mem::size_of::<f32>(),
            ScanValue::Double(_) => std::mem::size_of::<f64>(),
            ScanValue::String(s) => s.len(),
            ScanValue::Bytes(b) => b.len(),
        }
    }
}

// Helper enum for comparison types in incremental scans
enum CompareType {
    Equal,
    NotEqual,
    Greater,
    Less,
    Changed,
    Unchanged,
}

// Helper struct for scan results
struct ScanResult {
    address: i64,
    value_int: i64,
    value_float: f32,
    value_double: f64,
    value_string: String,
    value_bytes: Vec<u8>,
}

// Helper function to scan a buffer for matches
fn scan_buffer(
    buffer: &[u8],
    search_value: &ScanValue,
    alignment: usize,
    base_addr: umem,
    previous_results: Option<&TableVar>,
    compare_type: Option<&CompareType>,
) -> Vec<ScanResult> {
    let mut results = Vec::new();
    let value_size = search_value.size();

    // If this is an incremental scan, we only check addresses from previous results
    if let (Some(prev_results), Some(compare_type)) = (previous_results, compare_type) {
        for (key, _) in prev_results.iter() {
            let entry = prev_results.get(key).unwrap();
            let entry_table = match entry.as_table() {
                Ok(t) => t,
                Err(_) => continue,
            };

            let addr_var = match entry_table.get(Var::ephemeral_string("address")) {
                Some(v) => v,
                None => continue,
            };

            let addr: i64 = match addr_var.as_ref().try_into() {
                Ok(a) => a,
                Err(_) => continue,
            };

            let offset = (addr as umem - base_addr) as usize;
            if offset + value_size > buffer.len() {
                continue;
            }

            let prev_value = match entry_table.get(Var::ephemeral_string("value")) {
                Some(v) => v,
                None => continue,
            };

            let matches = match search_value {
                ScanValue::Integer(search_int) => {
                    if offset + std::mem::size_of::<i64>() > buffer.len() {
                        continue;
                    }
                    let current_value = i64::from_ne_bytes(
                        buffer[offset..offset + std::mem::size_of::<i64>()]
                            .try_into()
                            .unwrap_or([0; 8]),
                    );
                    let prev_int: i64 = match prev_value.as_ref().try_into() {
                        Ok(v) => v,
                        Err(_) => continue,
                    };

                    match compare_type {
                        CompareType::Equal => current_value == *search_int,
                        CompareType::NotEqual => current_value != *search_int,
                        CompareType::Greater => current_value > *search_int,
                        CompareType::Less => current_value < *search_int,
                        CompareType::Changed => current_value != prev_int,
                        CompareType::Unchanged => current_value == prev_int,
                    }
                }
                // Similar implementations for other types...
                _ => false, // Simplified for now
            };

            if matches {
                // Add to results
                let result = create_scan_result(buffer, offset, addr, search_value);
                results.push(result);
            }
        }
    } else {
        // First scan - check all memory
        for offset in (0..buffer.len().saturating_sub(value_size)).step_by(alignment) {
            let matches = match search_value {
                ScanValue::Integer(val) => {
                    if offset + std::mem::size_of::<i64>() > buffer.len() {
                        continue;
                    }
                    let current_value = i64::from_ne_bytes(
                        buffer[offset..offset + std::mem::size_of::<i64>()]
                            .try_into()
                            .unwrap_or([0; 8]),
                    );
                    current_value == *val
                }
                ScanValue::Float(val) => {
                    if offset + std::mem::size_of::<f32>() > buffer.len() {
                        continue;
                    }
                    let current_value = f32::from_ne_bytes(
                        buffer[offset..offset + std::mem::size_of::<f32>()]
                            .try_into()
                            .unwrap_or([0; 4]),
                    );
                    (current_value - *val).abs() < f32::EPSILON
                }
                ScanValue::Double(val) => {
                    if offset + std::mem::size_of::<f64>() > buffer.len() {
                        continue;
                    }
                    let current_value = f64::from_ne_bytes(
                        buffer[offset..offset + std::mem::size_of::<f64>()]
                            .try_into()
                            .unwrap_or([0; 8]),
                    );
                    (current_value - *val).abs() < f64::EPSILON
                }
                ScanValue::String(val) => {
                    if offset + val.len() > buffer.len() {
                        continue;
                    }
                    let slice = &buffer[offset..offset + val.len()];
                    slice == val.as_bytes()
                }
                ScanValue::Bytes(val) => {
                    if offset + val.len() > buffer.len() {
                        continue;
                    }
                    let slice = &buffer[offset..offset + val.len()];
                    slice == val.as_slice()
                }
            };

            if matches {
                let addr = base_addr + offset as umem;
                let result = create_scan_result(buffer, offset, addr as i64, search_value);
                results.push(result);
            }
        }
    }

    results
}

// Helper function to create a scan result
fn create_scan_result(
    buffer: &[u8],
    offset: usize,
    address: i64,
    search_value: &ScanValue,
) -> ScanResult {
    let mut result = ScanResult {
        address,
        value_int: 0,
        value_float: 0.0,
        value_double: 0.0,
        value_string: String::new(),
        value_bytes: Vec::new(),
    };

    match search_value {
        ScanValue::Integer(_) => {
            if offset + std::mem::size_of::<i64>() <= buffer.len() {
                result.value_int = i64::from_ne_bytes(
                    buffer[offset..offset + std::mem::size_of::<i64>()]
                        .try_into()
                        .unwrap_or([0; 8]),
                );
            }
        }
        ScanValue::Float(_) => {
            if offset + std::mem::size_of::<f32>() <= buffer.len() {
                result.value_float = f32::from_ne_bytes(
                    buffer[offset..offset + std::mem::size_of::<f32>()]
                        .try_into()
                        .unwrap_or([0; 4]),
                );
            }
        }
        ScanValue::Double(_) => {
            if offset + std::mem::size_of::<f64>() <= buffer.len() {
                result.value_double = f64::from_ne_bytes(
                    buffer[offset..offset + std::mem::size_of::<f64>()]
                        .try_into()
                        .unwrap_or([0; 8]),
                );
            }
        }
        ScanValue::String(val) => {
            if offset + val.len() <= buffer.len() {
                let slice = &buffer[offset..offset + val.len()];
                result.value_string = String::from_utf8_lossy(slice).to_string();
            }
        }
        ScanValue::Bytes(val) => {
            if offset + val.len() <= buffer.len() {
                result.value_bytes = buffer[offset..offset + val.len()].to_vec();
            }
        }
    }

    result
}

// Define a more advanced memory scanner for pattern matching
#[derive(shards::shard)]
#[shard_info(
    "Memflow.PatternScan",
    "Scans process memory for byte patterns with wildcards."
)]
struct MemflowPatternScanShard {
    #[shard_required]
    required: ExposedTypes,

    // Parameters
    #[shard_param("Pattern", "Byte pattern to scan for (e.g., '48 8B ? ? 89 7C').", [common_type::string, common_type::string_var])]
    pattern: ParamVar,

    #[shard_param("MinSize", "Minimum size of memory regions to scan (default: 4096).", [common_type::none, common_type::int, common_type::int_var])]
    min_size: ParamVar,

    #[shard_param("Protection", "Memory protection to filter by (e.g., 'r--', 'rw-', 'r-x').", [common_type::none, common_type::string, common_type::string_var])]
    protection: ParamVar,

    // Output results
    scan_results: AutoSeqVar,
}

impl Default for MemflowPatternScanShard {
    fn default() -> Self {
        Self {
            required: ExposedTypes::new(),
            pattern: ParamVar::default(),
            min_size: ParamVar::new(4096.into()),
            protection: ParamVar::default(),
            scan_results: AutoSeqVar::new(),
        }
    }
}

#[shards::shard_impl]
impl Shard for MemflowPatternScanShard {
    fn input_types(&mut self) -> &Types {
        &MEMFLOW_PROCESS_TYPES // Takes process as input
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
        self.scan_results = AutoSeqVar::new();
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
            &mut *Var::from_ref_counted_object::<memflow_process_wrapper::MemflowProcessWrapper>(
                input,
                &*MEMFLOW_PROCESS_TYPE,
            )?
        };

        // Get parameters
        let pattern_str: &str = self.pattern.get().as_ref().try_into()?;
        let min_size: i64 = self.min_size.get().as_ref().try_into().unwrap_or(4096);

        // Parse protection filter if provided
        let protection_filter = if self.protection.get().is_none() {
            None
        } else {
            let prot_str: &str = self.protection.get().as_ref().try_into()?;
            Some(prot_str)
        };

        // Parse the pattern
        let pattern = parse_pattern(pattern_str).map_err(|e| e)?;

        if pattern.is_empty() {
            return Err("Empty pattern");
        }

        shlog_debug!("Scanning memory with pattern: {}", pattern_str);

        // Get memory maps with filtering
        let maps = process.0.mapped_mem_vec(0);
        let filtered_maps: Vec<_> = maps
            .into_iter()
            .filter(|map| {
                // Filter by size
                let size = map.1.to_umem() as i64;
                if size < min_size {
                    return false;
                }

                // Filter by protection
                if let Some(prot_filter) = protection_filter {
                    if !protection_filter_matches(map.2, prot_filter) {
                        return false;
                    }
                }

                true
            })
            .collect();

        shlog_debug!("Filtered to {} memory regions", filtered_maps.len());

        self.scan_results.0.clear();

        for map in filtered_maps {
            let base_addr = map.0.to_umem();
            let size = map.1.to_umem() as usize;

            // Skip regions that are too small
            if size < pattern.len() {
                continue;
            }

            // Read the memory region
            let mut buffer = vec![0u8; size];
            match process
                .0
                .read_raw_into(Address::from(base_addr), &mut buffer)
            {
                Ok(_) => {
                    // Scan the buffer for pattern matches
                    let matches = scan_pattern(&buffer, &pattern, base_addr);
                    for match_ in matches {
                        let addr_var: Var = match_.into();
                        self.scan_results.0.push(&addr_var);
                    }
                }
                Err(e) => {
                    shlog_debug!("Failed to read memory region at 0x{:x}: {}", base_addr, e);
                    continue;
                }
            }
        }

        Ok(Some(self.scan_results.0 .0))
    }
}

// Pattern element can be either a specific byte or a wildcard
enum PatternElement {
    Byte(u8),
    Wildcard,
}

// Parse a pattern string into a vector of pattern elements
fn parse_pattern(pattern: &str) -> std::result::Result<Vec<PatternElement>, &'static str> {
    let mut result = Vec::new();
    let parts: Vec<&str> = pattern.split_whitespace().collect();

    for part in parts {
        if part == "?" {
            result.push(PatternElement::Wildcard);
        } else {
            // Try to parse as hex byte
            match u8::from_str_radix(part, 16) {
                Ok(byte) => result.push(PatternElement::Byte(byte)),
                Err(_) => return Err("Invalid pattern format"),
            }
        }
    }

    Ok(result)
}

// Scan a buffer for pattern matches
fn scan_pattern(buffer: &[u8], pattern: &[PatternElement], base_addr: umem) -> Vec<i64> {
    let mut results = Vec::new();

    'outer: for i in 0..buffer.len().saturating_sub(pattern.len()) {
        for (j, element) in pattern.iter().enumerate() {
            match element {
                PatternElement::Byte(byte) => {
                    if buffer[i + j] != *byte {
                        continue 'outer;
                    }
                }
                PatternElement::Wildcard => {
                    // Wildcard matches any byte
                }
            }
        }

        // If we get here, the pattern matched
        let addr = base_addr + i as umem;
        results.push(addr as i64);
    }

    results
}

// 6. Registration
#[ctor]
fn register_memflow_shards() {
    shards::core::init(); // Ensure core is initialized

    shlog_debug!("Registering Memflow Shards...");

    register_shard::<MemflowOsShard>();
    register_shard::<MemflowProcessListShard>();
    register_shard::<MemflowProcessShard>();
    register_shard::<MemflowMemMapShard>();
    register_shard::<MemflowKernelModuleListShard>();
    register_shard::<MemflowModuleInfoShard>();
    register_shard::<MemflowReadMemoryShard>();
    register_shard::<MemflowBatchReadMemoryShard>();
    register_shard::<MemflowProcessModuleListShard>();
    register_shard::<MemflowWriteMemoryShard>();
    register_shard::<MemflowBatchWriteMemoryShard>();
    register_shard::<MemflowMemoryScanShard>();
    register_shard::<MemflowPatternScanShard>();
    register_shard::<xref_shard::MemflowFunctionXrefShard>();

    shlog_debug!("Memflow Shards registered.");
}
