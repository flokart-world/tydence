# Tydence Coding Conventions

This document outlines the coding conventions and style guidelines for the tydence Rust codebase.

## Variable Naming

### 1. Avoid single-letter variables
- Bad: `e`, `i`, `n`
- Good: `error`, `index`, `count`
- Exception: Domain-standard coordinate/axis names (e.g., `x`, `y`, `z`)

### 2. Use descriptive names for errors
- Bad: `e`, `err`
- Good: `serve_error`, `shutdown_error`, `cleanup_error`
- Describe what operation failed

### 3. Prefer full words over abbreviations
- Bad: `err`, `idx`, `ctx`, `msg`, `tx`, `rx`
- Good: `error`, `index`, `context`, `message`, `sender`, `receiver`
- Only abbreviate genuinely long words (e.g., `configuration` → `config`)
- Avoid domain-specific abbreviations from other fields (tx/rx from telecom)
- See [standard-abbreviations.md](standard-abbreviations.md) for the list of accepted abbreviations

**Exceptions to abbreviation rules:**
- **Rust standard trait methods**: Keep `len()`, `is_empty()`, etc. as-is
- **Common prefixes**: `max_`, `min_`, `num_` are acceptable when the meaning is clear
- **Well-established patterns**: `max_connections`, `min_size`, `num_retries`
- These exceptions follow Rust ecosystem conventions and improve consistency

### 4. Avoid variable shadowing
- Each variable should have a unique, descriptive name
- Don't reuse variable names in nested scopes
- Especially important for error handling

### 5. Progressive naming for validated values
- Example: `optional_params` → `existing_params` after validation
- Makes the state of data clear at each point in the code

## Grep-ability

- Variable names should be meaningful even when seen out of context
- When you see `{error}` or `error.into()` in grep results, it should be clear what it represents
- This improves code maintainability and debugging

## Comments

### 1. Comments should explain WHY, not WHAT
- Bad: `// Create TokenStore wrapped in Arc for sharing`
- Good: `// Arc needed because the stamper and verifier share the same store`

### 2. Refactor instead of commenting
- If code needs WHAT comments to be understood, extract it into a well-named function
- Function names should make the code self-documenting

### 3. Accuracy is critical
- Never write misleading comments like "will be used for" when already in use
- Keep comments updated or remove them

## Type Naming

- Use specific, domain-relevant names
- Bad: `SharedResources`, `CommonData`, `AppState`
- Good: `ManifestBuilder`, `TokenStore`, `TsaClient`
- The name should clearly indicate the type's purpose and scope

## Variable Naming - Role-Based Philosophy

- **Variables should express their role/purpose, not just their type**
- Bad (type-based, redundant):
  ```rust
  fn save_data(string: String)  // What string?
  fn process(hashmap: HashMap<String, Value>)  // What does this map represent?
  fn handle(vec: Vec<u8>)  // What's in the vector?
  ```
- Good (role-based, meaningful):
  ```rust
  fn save_data(username: String)
  fn process(user_permissions: HashMap<String, Value>)
  fn handle(image_bytes: Vec<u8>)
  ```
- When the type already clearly expresses the role, shorter names are acceptable:
  ```rust
  impl Config {
      fn merge(&mut self, other: &Config)  // 'other' is clear in context
  }
  ```

## Testing Discipline

- Always run tests after making changes
- Never mark a task as complete without verifying tests pass
- Check for both compilation and test success
- **Name tests to clearly describe what is being verified and how they differ from other tests**
  - Bad: `test_search`, `test_filter`, `test_error`
  - Good: `search_returns_empty_for_unknown_scope`, `filter_rejects_invalid_date_format`
  - The name should read as a specification — what behavior is expected under what condition
- **Avoid `if` statements in tests**
  - `if` statements can cause false positives (test passes when condition is never met)
  - Use explicit assertions or separate test cases instead
  - Example of what to avoid:
    ```rust
    // BAD: May pass even if condition never executes
    if result.field == "expected" {
        assert!(result.valid);
    }
    ```
  - Better approach:
    ```rust
    // GOOD: Explicit assertion that always runs
    let matching_result = results.iter()
        .find(|r| r.field == "expected")
        .expect("Expected result not found");
    assert!(matching_result.valid);
    ```

## Function Parameters

- Maximum 3 parameters (excluding self) for functions
- Always consider refactoring, even with fewer parameters
- When 2 or more parameters have the same type, consider struct refactoring
  - Example: `fn process(&self, input: String, output: String)` → consider a struct for the two Strings
- For self + 3 parameters (4 total), use allow with inline comment:
  ```rust
  #[allow(clippy::too_many_arguments)] // self + 3 params for internal method
  fn internal_method(&self, a: Type1, b: Type2, c: Type3) { ... }
  ```
- The comment must be on the same line for grep visibility

## Design Principles

### 1. Separation of Concerns
- Separate different responsibilities into distinct components
- Protocol/transport layer should be independent from business logic
- State management should be isolated from I/O operations
- Each module should have a single, well-defined purpose

### 2. Clear Ownership
- Be explicit about ownership and borrowing
- Avoid patterns that obscure ownership (like `(*arc).clone()`)

### 3. Avoid Recursion
- Prefer iterative approaches over recursive implementations
- Use work queues or stacks for tree/graph traversal
- Recursion can cause stack overflow and is harder to reason about
- Stack frame construction/destruction adds performance overhead
- **Note on tail recursion**: Rust does NOT guarantee tail call optimization (TCO)
  - Even tail-recursive functions may consume stack space
  - TCO depends on compiler optimizations which are not guaranteed
  - Only use tail recursion when absolutely necessary and verify optimization with assembly output
- If recursion is unavoidable, add TODO comment for future refactoring

## Definition Ordering

### 1. Bottom-up organization
- **All definitions** (constants, types, traits, functions, and impl blocks) placed before their first use
- Allows linear top-to-bottom reading without jumping
- No need for layer labels or separator comments

### 2. impl blocks
- `impl` blocks follow bottom-up ordering for placement
- Methods within `impl` blocks also follow bottom-up ordering
- Helper methods defined before methods that use them

## Module Organization Guidelines

### Basic Structure

Every Rust module file follows this two-part structure:

1. **Definitions for Production Use**
   - All imports (external, workspace, module)
   - All type definitions, constants, traits
   - All functions and implementations
   - Everything that gets compiled into the final binary
   - **Must follow the import order described in the sections below**

2. **Test code**
   ```rust
   #[cfg(test)]
   mod tests {
       use super::*;

       #[test]
       fn parses_valid_input_correctly() {
           // test implementation
       }
   }
   ```
   - Always comes at the end of the file
   - Wrapped in `#[cfg(test)]` to exclude from production builds
   - Can import everything from parent module with `use super::*`

### Import Order for Production Definitions in Regular Module Files

For regular module files (not mod.rs, lib.rs, or main.rs), use this simpler structure:

1. **External imports** (standard library and external crates)
   ```rust
   use anyhow::Result;
   use serde::Serialize;
   use std::collections::HashSet;
   use std::sync::Arc;
   ```

2. **Workspace library imports** (e.g., `tydence::`)
   ```rust
   use tydence::manifest::Manifest;
   use tydence::token::TokenStore;
   ```

3. **Module imports** (from other modules in the same crate)
   ```rust
   use super::filter::FilterOperator;  // parent module (preferred)
   use super::storage::TokenStore;     // sibling via parent's use
   // Avoid crate:: for internal modules - use super:: instead
   ```

4. **Definitions** (constants, types, traits, functions, and impl blocks for this module)
   ```rust
   const BUFFER_SIZE: usize = 1024;
   type NodeId = u64;

   trait Parser {
       fn parse(&self, input: &str) -> Result<Value>;
   }

   struct DataProcessor {
       buffer: Vec<u8>,
   }

   impl DataProcessor {
       fn new() -> Self {
           Self { buffer: Vec::with_capacity(BUFFER_SIZE) }
       }
   }

   fn calculate_hash(data: &[u8]) -> u64 {
       // implementation
   }
   ```

### Import/Declaration Order for Production Definitions in Module Root Files

For module root files (mod.rs, lib.rs, main.rs) that declare submodules:

1. **Imports and definitions for child modules** (following the same order as regular modules)
   ```rust
   // External imports needed for the definitions below
   use anyhow::Result;  // for Validator trait
   use std::collections::HashMap;  // for SessionData type alias

   // Constants and type definitions (including re-exports for child modules)
   pub use super::metadata;  // Re-export for child modules
   pub use super::common::types;  // Re-export for child modules

   pub type SessionId = String;
   pub type SessionData = HashMap<String, String>;

   pub const SESSION_MANIFEST_DOCTYPE: &str = "session-manifest";
   pub const SESSION_CHUNK_DOCTYPE: &str = "session-chunk";

   pub trait Validator {
       fn validate(&self) -> Result<()>;
   }
   ```

2. **Module declarations** (`mod` statements)
   ```rust
   mod bit_utils;
   mod compiled_filter;
   mod cursor;
   ```

3. **Test module declarations** (`#[cfg(test)]`) - Exception: separate test files
   ```rust
   #[cfg(test)]
   mod cursor_test;  // Links to cursor_test.rs file
   #[cfg(test)]
   mod datetime_filter_test;  // Links to datetime_filter_test.rs file
   ```
   - Note: These declare **separate test files**, not inline test code
   - Unlike inline `mod tests { }`, these must be declared with other `mod` statements
   - Still wrapped in `#[cfg(test)]` to exclude from production builds

4. **Imports and definitions for rest of this module** (following the same order as regular modules)
   ```rust
   // External imports for this module's implementation
   use tokio::sync::Mutex;
   use std::time::Duration;

   // Workspace imports for this module's implementation
   use tydence::encoding::encode_path;

   // Module imports including from local modules declared above
   use cursor::{CursorArray, CursorStore};
   use field_validator::collect_field_suggestions_for_targets;

   // Definitions (re-exports, types, constants, traits, functions)
   pub use cursor::CursorStore;  // Re-export from child module
   pub use compiled_filter::Filter;  // Re-export from child module

   const MAX_CURSOR_COUNT: usize = 100;  // Module-internal constant

   pub struct Manager {  // Public struct for external use
       store: CursorStore,
       max_count: usize,
   }

   pub fn create_manager() -> Manager {  // Public function
       Manager {
           store: CursorStore::new(),
           max_count: MAX_CURSOR_COUNT,
       }
   }
   ```

### Principles

- **Hierarchical organization**: From lower layers to higher layers (external → workspace library → binary internals)
- **Group related items**: Combine imports from the same source in a single use statement
- **Clear separation**: Add blank lines between sections for visual clarity
- **No explanatory comments**: Section comments are unnecessary as the order is self-documenting
- **Note**: Comments shown in the examples above (e.g., `// External imports`) are for documentation clarity only - do not include them in actual code

## Internal Module Reference Convention

### Core Rules

1. **Use `super::` for internal module references**
   - All references within the same crate should use `super::`
   - Do not use `crate::` for internal modules

2. **Prohibit multi-level parent references**
   - `super::super::` and deeper are forbidden
   - If you need something from a grandparent, the parent should import it first

3. **Parent module (mod.rs) as dependency manager**
   - Parent modules must explicitly import sibling modules they want to share
   - Use `use super::sibling;` (not `pub use`) for internal dependency management
   - Use `pub use` separately for external API exposure

### Implementation Example

```rust
// verify/mod.rs
// Internal dependency management - make siblings available to children
use super::manifest;
use super::token;
use super::tsa;

mod chain;
mod policy;
mod report;

// External API exposure - selective public exports
pub use report::{VerifyReport, VerifyReportConfig};

// verify/policy.rs
// Access siblings through parent's imports
use super::chain::StampChain;      // OK: parent imported this
use super::token::TokenStore;      // OK: parent imported this
// use crate::token::TokenStore;    // ❌ Don't use crate::
// use super::super::common;        // ❌ Multi-level forbidden
```

### Benefits

- **Dependency visibility**: All dependencies are visible in mod.rs
- **Layer enforcement**: Prevents cross-cutting dependencies
- **Maintainability**: Module moves only require mod.rs changes
- **Clear separation**: Internal dependencies vs external API are distinct

### Migration Strategy

- Apply immediately to new code
- Migrate existing code opportunistically when making changes
- Focus on high-traffic modules first
