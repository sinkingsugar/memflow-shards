use shards::core::register_shard;
use shards::ref_counted_object_type_impl;
use shards::shard::Shard;
use shards::types::{
    common_type, AutoSeqVar, AutoTableVar, ClonedVar, Context, ExposedTypes, InstanceData, ParamVar, Type, Types, Var, ANYS_TYPES, ANY_TABLE_TYPES, NONE_TYPES // Input type
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
            let address_str = format!("0x{:x}", map.0);
            let size_str = format!("0x{:x}", map.1);
            let prot = format!("{:?}", map.2);

            // Create column values
            let address_var = Var::ephemeral_string(&address_str);
            let size_var = Var::ephemeral_string(&size_str);
            let prot_var = Var::ephemeral_string(&prot);

            // Insert into table
            let mut tab = AutoTableVar::new();
            tab.0.insert_fast_static("address", &address_var);
            tab.0.insert_fast_static("size", &size_var);
            tab.0.insert_fast_static("protection", &prot_var);
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
            let name = Var::ephemeral_string(&module.name);
            // let base_addr: Var = module.base.to_string();
            // let base = Var::ephemeral_string(&base_addr);
            let size: Var = module.size.into();
            let path = Var::ephemeral_string(&module.path);

            // Insert into table
            let mut tab = AutoTableVar::new();
            tab.0.insert_fast_static("name", &name);
            // self.module_list.0.insert_fast_static("base", &base);
            tab.0.insert_fast_static("size", &size);
            tab.0.insert_fast_static("path", &path);

            self.module_list.0.emplace_table(tab);

            // // Store the internal address if available
            // if let Some(addr) = module.address {
            //     let addr_str = format!("0x{:x}", addr.as_u64());
            //     let addr_var = Var::ephemeral_string(&addr_str);
            //     self.module_list.0.insert_fast_static("address", &addr_var);
            // }
        }

        Ok(Some(self.module_list.0 .0))
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

    shlog_debug!("Memflow Shards registered.");
}
