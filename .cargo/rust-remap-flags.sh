#!/usr/bin/env bash
# Construct ordered source-root mappings for Rust and native release compilers [D243].

# Append longest-first mappings to the named caller array. Only a shell
# identifier is accepted; path values stay quoted data even under Bash 3.2.
infraternal_append_path_remap_flags() {
    local destination_name="$1" flag_prefix="$2" root="$3" cargo_root="$4" target_root="$5" rustup_root="$6"
    local registry index key_root key_destination previous_root previous_destination
    [[ "$destination_name" =~ ^[a-zA-Z_][a-zA-Z_0-9]*$ ]] || {
        printf 'invalid remap destination array name\n' >&2; return 2;
    }
    local -a roots=() destinations=()

    # Generic wrapper calls get a deterministic longest-first sequence. Static
    # Rust release flags use an explicit order so registry overrides follow CARGO_HOME.
    for registry in "$cargo_root"/registry/src/*; do
        [[ ! -d "$registry" ]] || { roots+=("$registry"); destinations+=("/cargo"); }
    done
    roots+=("$root" "$cargo_root" "$target_root")
    destinations+=("/infraternal" "/cargo" "/build")
    if [[ -n "$rustup_root" ]]; then
        roots+=("$rustup_root")
        destinations+=("/rustup")
    fi

    for ((index = 1; index < ${#roots[@]}; index += 1)); do
        key_root="${roots[index]}"
        key_destination="${destinations[index]}"
        local insertion=$((index - 1))
        while ((insertion >= 0)) && ((${#roots[insertion]} < ${#key_root})); do
            previous_root="${roots[insertion]}"
            previous_destination="${destinations[insertion]}"
            roots[insertion + 1]="$previous_root"
            destinations[insertion + 1]="$previous_destination"
            insertion=$((insertion - 1))
        done
        roots[insertion + 1]="$key_root"
        destinations[insertion + 1]="$key_destination"
    done

    for ((index = 0; index < ${#roots[@]}; index += 1)); do
        # Bash 3.2 has no namerefs. Expand only the validated identifier here;
        # the second evaluation expands the quoted values without parsing them.
        eval "$destination_name+=(\"\$flag_prefix\${roots[index]}=\${destinations[index]}\")"
    done
}
