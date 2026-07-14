# Standard Abbreviations

This document defines the standard abbreviations used in the tydence codebase.

## Principles

1. **Meaningful Savings**: Abbreviations should save at least 3-4 characters
2. **Clarity**: The abbreviation must be unambiguous and widely recognized
3. **Consistency**: Use the same abbreviation throughout the codebase
4. **Standard Library Precedence**: Follow Rust standard library conventions when established

## Evaluation Criteria

| Characters Saved | Recommendation |
|-----------------|----------------|
| 5+ | Strongly recommended |
| 4 | Recommended |
| 3 | Acceptable if clear |
| 2 | Generally avoid |
| 1 | Never use |

## Recommended Abbreviations

These abbreviations save significant characters and are unambiguous:

| Full Word | Abbreviation | Saved | Notes |
|-----------|--------------|-------|-------|
| argument | arg | 5 | Universal standard |
| arguments | args | 5 | Established plural form |
| configuration | config | 7 | Universal standard |
| destination | dest/dst | 7/8 | dest is common, dst pairs well with src |
| directory | dir | 6 | Unix/Linux standard |
| document | doc | 5 | Rust standard (cargo doc) |
| environment | env | 8 | Universal standard |
| initialize | init | 6 | Universal standard |
| parameter | param | 4 | Universal standard |
| parameters | params | 4 | Established plural form |
| previous | prev | 4 | Clear and common |
| reference | ref | 6 | Rust keyword |
| source | src | 3 | Universal standard |
| temporary | tmp | 6 | Unix/Linux standard |

## Acceptable Abbreviations

These are established by convention despite limited savings:

| Full Word | Abbreviation | Saved | Notes |
|-----------|--------------|-------|-------|
| buffer | buf | 3 | Rust standard (PathBuf, etc.) |
| error | err | 2 | Rust Result convention |
| function | func/fn | 4/6 | Use fn for types, func for variables |
| iterator | iter | 4 | Rust standard |
| length | len | 3 | Rust standard method |
| message | msg | 4 | Common but full word preferred |
| string | str | 3 | Rust standard type |

## Context-Specific Abbreviations

Acceptable in specific contexts:

| Full Word | Abbreviation | Context |
|-----------|--------------|---------|
| character | ch | When processing strings (stdlib convention) |
| number | num_* | As prefix (num_elements, num_items) |

## Non-Recommended Abbreviations

Avoid these due to insufficient savings or lack of clarity:

| Full Word | Abbreviation | Saved | Why Avoid |
|-----------|--------------|-------|-----------|
| context | ctx | 4 | 'x' overloaded, visually unclear |
| count | cnt | 2 | Too little saved, use full word |
| current | cur | 4 | Can be ambiguous (cursor?) |
| index | i, j, k | - | Unclear which is which, use descriptive names |
| index | idx | 2 | Too little saved |
| messages | msgs | 4 | Awkward consonant cluster, use 'messages' |
| number | num | 3 | Unclear alone, OK as prefix (num_items) |
| result | res | 3 | Conflicts with resource/response |
| value | val | 2 | Too little saved |

## Special Cases

### Rust-Specific
- Use `impl` for implementation (Rust keyword)
- Use `pub` for public (Rust keyword)
- Use `mod` for module (Rust keyword)
- Use `fn` for function types (Rust keyword)

### Domain-Specific
Project-specific abbreviations should be documented here as they emerge.

## Guidelines for New Abbreviations

Before introducing a new abbreviation:

1. Check if it saves at least 3 characters
2. Verify it's unambiguous in context
3. Look for standard library or common usage
4. Consider if the full word improves clarity
5. Document it in this file if adopted

## Examples

```rust
// Good
fn load_config(config: &Config) { }
fn get_prev_value() -> String { }
fn handle_client_message(request: Message) { }
fn copy_file(src: &Path, dst: &Path) { }
let num_elements = vec.len();
for row_index in 0..rows { }
for column_index in 0..columns { }

// Avoid
fn get_idx() -> usize { }  // Use: get_index()
fn calc_val() -> i32 { }   // Use: calculate_value()
fn inc_cnt() { }           // Use: increment_count()
fn process_ctx(ctx: &Context) { }  // Use: process_context()
for i in 0..n {  // Use: descriptive name
    for j in 0..m {  // Which is which?
    }
}
```
