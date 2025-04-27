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
    Type,
    Types,
    Var,
    ANYS_TYPES,
    ANY_TABLE_TYPES,
    BYTES_TYPES,
    NONE_TYPES, // Input type
};
use shards::{fourCharacterCode, shlog_debug, shlog_error};

use ctor::ctor;
use lazy_static::lazy_static;

use memflow::prelude::v1::*;

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

mod memflow_process_wrapper {
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

    // Output status
    output_status: ClonedVar,
}

impl Default for MemflowBatchWriteMemoryShard {
    fn default() -> Self {
        Self {
            required: ExposedTypes::new(),
            writes: ParamVar::default(),
            process_instance: ParamVar::default(),
            output_status: ClonedVar::default(),
        }
    }
}

#[shards::shard_impl]
impl Shard for MemflowBatchWriteMemoryShard {
    fn input_types(&mut self) -> &Types {
        &NONE_TYPES // Takes no input, all data comes from parameters
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
        if self.writes.is_none() {
            return Err("Missing 'writes' parameter");
        }
        self.output_status = ClonedVar::default();
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

        // Return success
        self.output_status = Var::new_bool(true).into();
        Ok(None)
    }
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

    shlog_debug!("Memflow Shards registered.");
}
