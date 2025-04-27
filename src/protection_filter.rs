use memflow::prelude::v1::*;

// Helper function to convert PageType to rwx format string
pub fn page_type_to_rwx(page_type: PageType) -> String {
    // Check for read/write/execute permissions
    let has_read = true; // Assume readable if mapped
    let has_write = page_type.contains(PageType::WRITEABLE);
    let has_exec = !page_type.contains(PageType::NOEXEC);
    
    // Convert to rwx format string
    format!("{}{}{}", 
        if has_read { "r" } else { "-" },
        if has_write { "w" } else { "-" },
        if has_exec { "x" } else { "-" }
    )
}

// Helper function to check if a protection filter matches a page type
pub fn protection_filter_matches(page_type: PageType, filter: &str) -> bool {
    let rwx = page_type_to_rwx(page_type);
    rwx.contains(filter)
}