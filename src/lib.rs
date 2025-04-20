use shards::core::register_shard;
use shards::ref_counted_object_type_impl;
use shards::shard::Shard;
use shards::types::{
    common_type,
    ClonedVar,
    Context,
    ExposedTypes,
    InstanceData,
    Type,
    Types,
    Var,
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
    // The Shards Type descriptor for the Inventory object
    pub static ref MEMFLOW_OS_TYPE: Type = Type::object(*MEMFLOW_VENDOR_ID, *MEMFLOW_OS_TYPE_ID);
    // A vector containing the type, useful for input/output_types
    pub static ref MEMFLOW_OS_TYPES: Vec<Type> = vec![*MEMFLOW_OS_TYPE];
}

// Wrapper struct to hold the OsInstanceArcBox
#[derive(Clone)] // Clone is needed because OsInstanceArcBox is Clone
pub struct MemflowOsWrapper(pub OsInstanceArcBox<'static>);

// 3. Implement Shards object handling for the wrapper
ref_counted_object_type_impl!(MemflowOsWrapper);

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
    #[shard_param("Connector", "The name of the memflow connector to use.", [common_type::string])]
    connector_name: ClonedVar,
    #[shard_param("Os", "The name of the OS plugin to use (e.g., 'win32', 'linux').", [common_type::string])]
    os_name: ClonedVar,

    // Store the output OS object
    output_os: ClonedVar,
}

impl Default for MemflowOsShard {
    fn default() -> Self {
        let default_connector_name = Var::ephemeral_string("kvm");
        let default_os_name = Var::ephemeral_string("win32");
        Self {
            required: ExposedTypes::new(),
            connector_name: default_connector_name.into(),
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

    fn compose(&mut self, _data: &InstanceData) -> std::result::Result<Type, &str> {
        // No specific composition logic needed here yet, just return output type
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
        let connector_name: &str = self.connector_name.0.as_ref().try_into()?;
        let os_name: &str = self.os_name.0.as_ref().try_into()?;

        shlog_debug!(
            "Attempting to create OS instance: connector='{}', os='{}'",
            connector_name,
            os_name
        );

        // Create inventory and OS instance
        let inventory = Inventory::scan();
        let os = inventory
            .builder()
            .connector(connector_name)
            .os(os_name)
            .build()
            .map_err(|e| {
                shlog_error!("Failed to create OS instance: {}", e);
                "Failed to create OS instance."
            })?;
        self.output_os = Var::new_ref_counted(MemflowOsWrapper(os), &MEMFLOW_OS_TYPE).into();
        Ok(Some(self.output_os.0))
    }
}

// 6. Registration
#[ctor]
fn register_memflow_shards() {
    shards::core::init(); // Ensure core is initialized
    shlog_debug!("Registering Memflow Shards...");
    register_shard::<MemflowOsShard>();
    shlog_debug!("Memflow Shards registered.");
}
