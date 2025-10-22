#!/usr/bin/env python3
"""
Generate JSON schema reference documentation from Syft schema files.

This script parses Syft's JSON schema and generates comprehensive HTML tables
documenting all type definitions, organized into Core Types and Ecosystem Types.

Outputs:
- Reference docs: content/docs/reference/syft/json/{VERSION}.md
  - Core Types section: Document, Package, Location, etc.
  - Ecosystem Types section: AlpmDbEntry, ApkDbEntry, etc.
  - Each type gets a table with: Field Name, Type, Required?, Description

The script automatically categorizes types by examining the Package.metadata
field's anyOf union to identify ecosystem-specific metadata types.
"""

import json
import re
import sys
from pathlib import Path
from typing import Any

import click
from utils.config import get_generated_comment, paths
from utils.logging import setup_logging


def load_json_schema(schema_path: Path, logger) -> tuple[dict, str]:
    """
    load and parse JSON schema file, extracting version from $id field.

    Args:
        schema_path: path to JSON schema file
        logger: logger instance

    Returns:
        tuple of (schema dict, major version string)

    Raises:
        SystemExit if schema file not found or version cannot be extracted
    """
    if not schema_path.exists():
        logger.error(f"Schema file not found: {schema_path}")
        sys.exit(1)

    logger.debug(f"Loading schema from {schema_path}")

    with open(schema_path) as f:
        schema = json.load(f)

    # extract major version from $id field
    # example: "anchore.io/schema/syft/json/16.0.40/document" -> "16"
    schema_id = schema.get("$id", "")
    if not schema_id:
        logger.error("Schema file missing $id field")
        sys.exit(1)

    # extract version from pattern like "json/16.0.40/document"
    version_match = re.search(r"/json/(\d+)\.\d+\.\d+/", schema_id)
    if not version_match:
        logger.error(f"Cannot extract version from schema $id: {schema_id}")
        sys.exit(1)

    major_version = version_match.group(1)
    logger.info(f"Detected schema major version: {major_version}")

    return schema, major_version


def find_referenced_types(
    def_schema: dict, all_defs: dict, visited: set[str] | None = None
) -> set[str]:
    """
    recursively find all types referenced by a definition.

    Args:
        def_schema: definition schema dict
        all_defs: all schema definitions
        visited: set of already visited type names (to avoid circular references)

    Returns:
        set of referenced type names
    """
    if visited is None:
        visited = set()

    referenced = set()

    # helper to extract type name from $ref
    def extract_ref(ref_dict):
        if not isinstance(ref_dict, dict):
            return None
        ref = ref_dict.get("$ref", "")
        if ref.startswith("#/$defs/"):
            return ref.replace("#/$defs/", "")
        return None

    # helper to process a field spec
    def process_field_spec(field_spec) -> None:
        if not isinstance(field_spec, dict):
            return

        # check direct $ref
        ref_name = extract_ref(field_spec)
        if ref_name and ref_name not in visited and ref_name in all_defs:
            referenced.add(ref_name)
            visited.add(ref_name)
            # recurse into referenced type
            referenced.update(
                find_referenced_types(all_defs[ref_name], all_defs, visited)
            )

        # check array items
        if field_spec.get("type") == "array" and "items" in field_spec:
            process_field_spec(field_spec["items"])

        # check anyOf/oneOf unions
        for union_key in ["anyOf", "oneOf"]:
            if union_key in field_spec:
                for option in field_spec[union_key]:
                    process_field_spec(option)

    # process all properties
    for field_spec in def_schema.get("properties", {}).values():
        process_field_spec(field_spec)

    return referenced


def build_type_dependency_graph(
    all_defs: dict, ecosystem_types: set[str]
) -> dict[str, Any]:
    """
    build dependency graph to show ecosystem-related types.

    ecosystem-related types are types directly referenced by ecosystem types.
    these will be shown as nested subsections under their parent ecosystem type.

    Note: We don't try to categorize types as "exclusively ecosystem-only" because
    the Document type indirectly references all ecosystem types through Package.metadata,
    making everything "shared". Instead, we just show related types under their ecosystem.

    Args:
        all_defs: all schema definitions
        ecosystem_types: set of ecosystem type names

    Returns:
        dict with categorization:
        {
            "core_only": [type names not in ecosystem],
            "ecosystem_related": {ecosystem_type: [types it references]},
            "shared": []  # always empty, kept for compatibility
        }
    """
    # find all types referenced by each ecosystem type
    ecosystem_refs = {}
    all_ecosystem_refs = set()

    for eco_type in ecosystem_types:
        if eco_type in all_defs:
            refs = find_referenced_types(all_defs[eco_type], all_defs)
            ecosystem_refs[eco_type] = refs
            all_ecosystem_refs.update(refs)

    # build ecosystem_related dict with all referenced types
    ecosystem_related = {}
    for eco_type, refs in ecosystem_refs.items():
        if refs:
            # show all types this ecosystem references (even if shared with core)
            ecosystem_related[eco_type] = sorted(refs)

    # core types are everything not in ecosystem types or their references
    core_only = [
        name
        for name in all_defs.keys()
        if name not in ecosystem_types and name not in all_ecosystem_refs
    ]

    return {
        "core_only": sorted(core_only),
        "ecosystem_related": ecosystem_related,
        "shared": [],  # empty - we show everything under ecosystem types
    }


def categorize_definitions(schema: dict, logger) -> dict[str, Any]:
    """
    categorize schema definitions into Core Types, Ecosystem Types, and related types.

    ecosystem types are identified by examining Package.metadata.anyOf union.
    related types are types ONLY referenced by ecosystem types.
    core types are everything else (including shared types used by both).

    Args:
        schema: parsed JSON schema dict
        logger: logger instance

    Returns:
        dict with keys:
        - "core": list of core type names (includes shared types)
        - "ecosystem": list of ecosystem type names
        - "ecosystem_related": dict mapping ecosystem type -> list of related types
    """
    all_defs = schema.get("$defs", {})
    ecosystem_types = set()

    # find Package definition
    package_def = all_defs.get("Package")
    if not package_def:
        logger.warning("Package definition not found in schema")
        return {
            "core": list(all_defs.keys()),
            "ecosystem": [],
            "ecosystem_related": {},
        }

    # find metadata field's anyOf union
    metadata_field = package_def.get("properties", {}).get("metadata", {})
    any_of = metadata_field.get("anyOf", [])

    # extract ecosystem type names from anyOf (excluding "null" type)
    for option in any_of:
        if option.get("type") == "null":
            continue

        ref = option.get("$ref", "")
        # extract type name from "#/$defs/TypeName"
        if ref.startswith("#/$defs/"):
            type_name = ref.replace("#/$defs/", "")
            ecosystem_types.add(type_name)

    # build dependency graph to properly categorize types
    dep_graph = build_type_dependency_graph(all_defs, ecosystem_types)

    # core types = types not in ecosystem + shared types (excluding Document)
    core_types = [t for t in (dep_graph["core_only"] + dep_graph["shared"]) if t != "Document"]

    logger.debug(
        f"Categorized {len(core_types)} core types, "
        f"{len(ecosystem_types)} ecosystem types, "
        f"{sum(len(v) for v in dep_graph['ecosystem_related'].values())} ecosystem-related types"
    )

    return {
        "document": ["Document"],  # Document gets its own section
        "core": sorted(core_types),
        "ecosystem": sorted(ecosystem_types),
        "ecosystem_related": dep_graph["ecosystem_related"],
    }


def get_documented_types(categories: dict[str, Any], all_defs: dict) -> set[str]:
    """
    collect all type names that will be documented on the page.

    only includes types that have fields (types without fields are skipped in HTML generation).

    Args:
        categories: categorization dict from categorize_definitions()
        all_defs: all schema definitions

    Returns:
        set of type names that have documentation sections
    """
    documented = set()

    def has_fields(type_name: str) -> bool:
        """check if type has any fields"""
        type_def = all_defs.get(type_name)
        if not type_def:
            return False
        properties = type_def.get("properties", {})
        return len(properties) > 0

    # add Document (if it has fields)
    for type_name in categories.get("document", []):
        if has_fields(type_name):
            documented.add(type_name)

    # add core types (if they have fields)
    for type_name in categories.get("core", []):
        if has_fields(type_name):
            documented.add(type_name)

    # add ecosystem types (if they have fields)
    for type_name in categories.get("ecosystem", []):
        if has_fields(type_name):
            documented.add(type_name)

    # add ecosystem-related types (if they have fields)
    ecosystem_related = categories.get("ecosystem_related", {})
    for related_types in ecosystem_related.values():
        for type_name in related_types:
            if has_fields(type_name):
                documented.add(type_name)

    return documented


def expand_type_reference(type_spec: Any, all_defs: dict) -> str:
    """
    expand type specification to human-readable type string.

    handles:
    - primitives: "string", "integer", "boolean"
    - references: {"$ref": "#/$defs/Foo"} -> "Foo"
    - arrays: {"type": "array", "items": {...}} -> "Array<Type>"
    - unions: {"anyOf": [...]} or {"oneOf": [...]}

    Args:
        type_spec: type specification (dict or string)
        all_defs: all schema definitions for resolving references

    Returns:
        human-readable type string
    """
    # handle string type specifications
    if isinstance(type_spec, str):
        return type_spec

    # handle dict type specifications
    if isinstance(type_spec, dict):
        # handle $ref
        if "$ref" in type_spec:
            ref = type_spec["$ref"]
            if ref.startswith("#/$defs/"):
                return ref.replace("#/$defs/", "")
            return ref

        # handle primitive types
        if "type" in type_spec:
            type_value = type_spec["type"]

            # handle arrays
            if type_value == "array":
                items = type_spec.get("items", {})
                item_type = expand_type_reference(items, all_defs)
                return f"Array&lt;{item_type}&gt;"

            # handle primitives
            return type_value

        # handle anyOf unions
        if "anyOf" in type_spec:
            options = type_spec["anyOf"]
            # filter out null types for cleaner display
            non_null_options = [
                opt for opt in options if not (isinstance(opt, dict) and opt.get("type") == "null")
            ]
            if len(non_null_options) == 1:
                return expand_type_reference(non_null_options[0], all_defs)
            elif non_null_options:
                option_types = [expand_type_reference(opt, all_defs) for opt in non_null_options]
                return " | ".join(option_types)

        # handle oneOf unions
        if "oneOf" in type_spec:
            options = type_spec["oneOf"]
            option_types = [expand_type_reference(opt, all_defs) for opt in options]
            return " | ".join(option_types)

    return "unknown"


def clean_type_description(type_name: str, description: str) -> str:
    """
    clean type-level description by removing redundant type name prefix.

    if description starts with the type name, removes it and capitalizes
    the first letter of the remaining text.

    Args:
        type_name: name of the type definition
        description: original description text

    Returns:
        cleaned description text

    Examples:
        >>> clean_type_description("PhpComposerAuthors", "PhpComposerAuthors represents author info...")
        "Represents author info..."
        >>> clean_type_description("Package", "represents a package")
        "represents a package"
    """
    if not description:
        return description

    # split description into words
    words = description.split(None, 1)  # split on first whitespace only
    if not words:
        return description

    first_word = words[0]

    # check if first word matches type name (case-insensitive)
    if first_word.lower() == type_name.lower():
        # remove type name and capitalize remainder
        if len(words) > 1:
            remainder = words[1]
            # capitalize first letter
            if remainder:
                return remainder[0].upper() + remainder[1:]
            return remainder
        # description was just the type name
        return ""

    # no match, return original
    return description


def linkify_type_string(type_str: str, documented_types: set[str]) -> str:
    """
    add hyperlinks to type references that are documented on the page.

    handles simple types, arrays, and unions. Preserves HTML entities.
    primitives and undocumented types are left as plain text.

    Args:
        type_str: type string from expand_type_reference (may contain HTML entities)
        documented_types: set of type names that have documentation sections

    Returns:
        type string with documented types wrapped in anchor links

    Examples:
        >>> linkify_type_string("Package", {"Package"})
        '<a href="#package">Package</a>'
        >>> linkify_type_string("Array&lt;Location&gt;", {"Location"})
        'Array&lt;<a href="#location">Location</a>&gt;'
        >>> linkify_type_string("string | Package", {"Package"})
        'string | <a href="#package">Package</a>'
    """
    # primitive types that should never be linked
    primitives = {"string", "integer", "boolean", "object", "null", "number", "array"}

    # helper to linkify a single type name
    def linkify_single(name: str) -> str:
        name = name.strip()
        if not name or name in primitives or name not in documented_types:
            return name
        return f'<a href="#{name.lower()}">{name}</a>'

    # handle union types (split by " | ")
    if " | " in type_str:
        parts = type_str.split(" | ")
        linked_parts = []
        for part in parts:
            # each part might be an array or simple type
            if part.startswith("Array&lt;") and part.endswith("&gt;"):
                # extract inner type from Array&lt;Type&gt;
                inner = part[9:-4]  # remove "Array&lt;" and "&gt;"
                linked_inner = linkify_single(inner)
                linked_parts.append(f"Array&lt;{linked_inner}&gt;")
            else:
                linked_parts.append(linkify_single(part))
        return " | ".join(linked_parts)

    # handle array types
    if type_str.startswith("Array&lt;") and type_str.endswith("&gt;"):
        inner = type_str[9:-4]  # remove "Array&lt;" and "&gt;"
        # inner might itself be a union
        if " | " in inner:
            parts = inner.split(" | ")
            linked_parts = [linkify_single(p) for p in parts]
            return f"Array&lt;{' | '.join(linked_parts)}&gt;"
        else:
            linked_inner = linkify_single(inner)
            return f"Array&lt;{linked_inner}&gt;"

    # simple type
    return linkify_single(type_str)


def should_replace_field_with_link(
    def_name: str, field_name: str, field_spec: dict
) -> bool:
    """
    determine if a field should be replaced with a link to Ecosystem Types section.

    specifically checks for Package.metadata field which has a large anyOf union.

    Args:
        def_name: name of the type definition
        field_name: name of the field
        field_spec: field specification dict

    Returns:
        True if field should show link instead of full type
    """
    # check if this is the Package.metadata field
    if def_name == "Package" and field_name == "metadata":
        # check if it has anyOf with multiple options (ecosystem types)
        any_of = field_spec.get("anyOf", [])
        # if there are many options (more than just null), this is the ecosystem union
        non_null_options = [
            opt for opt in any_of if not (isinstance(opt, dict) and opt.get("type") == "null")
        ]
        return len(non_null_options) > 5  # arbitrary threshold
    return False


def parse_definition(
    def_name: str, def_schema: dict, all_defs: dict
) -> dict[str, Any]:
    """
    parse a schema definition to extract structured information.

    Args:
        def_name: name of the definition
        def_schema: definition schema dict
        all_defs: all schema definitions for resolving references

    Returns:
        dict with:
        - name: definition name
        - description: type-level description (if exists)
        - fields: list of field dicts with name, type, required, description
    """
    result = {
        "name": def_name,
        "description": clean_type_description(def_name, def_schema.get("description", "")),
        "fields": [],
    }

    properties = def_schema.get("properties", {})
    required_fields = set(def_schema.get("required", []))

    for field_name, field_spec in properties.items():
        # handle edge case where field_spec might be a boolean or other primitive
        if not isinstance(field_spec, dict):
            # skip non-dict field specs (shouldn't happen in well-formed schemas)
            continue

        # check if this field should be replaced with a link
        if should_replace_field_with_link(def_name, field_name, field_spec):
            field_type = "ECOSYSTEM_TYPES_LINK"  # special marker
            field_desc = ""  # clear description for this special field
        else:
            field_type = expand_type_reference(field_spec, all_defs)
            field_desc = field_spec.get("description", "")

        is_required = field_name in required_fields

        result["fields"].append(
            {
                "name": field_name,
                "type": field_type,
                "required": is_required,
                "description": field_desc,
            }
        )

    return result


def generate_type_section_html(
    type_names: list[str],
    all_defs: dict,
    section_title: str,
    logger,
    documented_types: set[str],
    related_types_map: dict[str, list[str]] | None = None,
) -> list[str]:
    """
    generate HTML for a section of type definitions.

    Args:
        type_names: list of type names to include
        all_defs: all schema definitions
        section_title: section heading (e.g., "Core Types", "Ecosystem Types")
        logger: logger instance
        documented_types: set of type names that have documentation sections
        related_types_map: optional dict mapping type names to their related types
                          (used for ecosystem types to show related types with h4)

    Returns:
        list of HTML lines
    """
    html_lines = []

    # generate markdown h2 header with custom anchor ID
    anchor_id = section_title.lower().replace(" ", "-")
    html_lines.append(f'## {section_title} {{#{anchor_id}}}\n')

    for type_name in type_names:
        type_def = all_defs.get(type_name)
        if not type_def:
            logger.warning(f"Definition not found: {type_name}")
            continue

        parsed = parse_definition(type_name, type_def, all_defs)

        # skip types with no fields entirely
        if not parsed["fields"]:
            continue

        # type heading with anchor (markdown h3)
        html_lines.append(f'### {type_name} {{#{type_name.lower()}}}\n')

        # type description (if exists)
        if parsed["description"]:
            html_lines.append(f'<p>{parsed["description"]}</p>\n')

        # table header
        html_lines.append('<table class="schema-table">')
        html_lines.append("  <thead>")
        html_lines.append("    <tr>")
        html_lines.append('      <th class="col-field-name">Field Name</th>')
        html_lines.append('      <th class="col-type">Type</th>')
        html_lines.append('      <th class="col-required">Required?</th>')
        html_lines.append('      <th class="col-description">Description</th>')
        html_lines.append("    </tr>")
        html_lines.append("  </thead>")
        html_lines.append("  <tbody>")

        # table rows
        for field in parsed["fields"]:
            html_lines.append("    <tr>")
            html_lines.append(
                f'      <td class="col-field-name"><code>{field["name"]}</code></td>'
            )

            # handle special ecosystem types link
            if field["type"] == "ECOSYSTEM_TYPES_LINK":
                html_lines.append(
                    '      <td class="col-type"><em><a href="#ecosystem-types">see Ecosystem Types section</a></em></td>'
                )
            else:
                # linkify type references and wrap in code tags
                linked_type = linkify_type_string(field["type"], documented_types)
                html_lines.append(
                    f'      <td class="col-type"><code>{linked_type}</code></td>'
                )

            # required indicator
            required_indicator = "✓" if field["required"] else ""
            html_lines.append(
                f'      <td class="col-required">{required_indicator}</td>'
            )

            html_lines.append(
                f'      <td class="col-description">{field["description"]}</td>'
            )
            html_lines.append("    </tr>")

        # close table
        html_lines.append("  </tbody>")
        html_lines.append("</table>\n")

        # if this is an ecosystem type with related types, show them with h4
        if related_types_map and type_name in related_types_map:
            related_types = related_types_map[type_name]
            for related_type_name in related_types:
                related_def = all_defs.get(related_type_name)
                if not related_def:
                    logger.warning(f"Related type not found: {related_type_name}")
                    continue

                related_parsed = parse_definition(
                    related_type_name, related_def, all_defs
                )

                # skip related types with no fields entirely
                if not related_parsed["fields"]:
                    continue

                # related type heading with markdown h4
                html_lines.append(
                    f'#### {related_type_name} {{#{related_type_name.lower()}}}\n'
                )

                # type description (if exists)
                if related_parsed["description"]:
                    html_lines.append(f'<p>{related_parsed["description"]}</p>\n')

                # table (same structure as main types)
                html_lines.append('<table class="schema-table">')
                html_lines.append("  <thead>")
                html_lines.append("    <tr>")
                html_lines.append('      <th class="col-field-name">Field Name</th>')
                html_lines.append('      <th class="col-type">Type</th>')
                html_lines.append('      <th class="col-required">Required?</th>')
                html_lines.append('      <th class="col-description">Description</th>')
                html_lines.append("    </tr>")
                html_lines.append("  </thead>")
                html_lines.append("  <tbody>")

                for field in related_parsed["fields"]:
                    html_lines.append("    <tr>")
                    html_lines.append(
                        f'      <td class="col-field-name"><code>{field["name"]}</code></td>'
                    )
                    # linkify type references
                    linked_type = linkify_type_string(field["type"], documented_types)
                    html_lines.append(
                        f'      <td class="col-type"><code>{linked_type}</code></td>'
                    )

                    required_indicator = "✓" if field["required"] else ""
                    html_lines.append(
                        f'      <td class="col-required">{required_indicator}</td>'
                    )

                    html_lines.append(
                        f'      <td class="col-description">{field["description"]}</td>'
                    )
                    html_lines.append("    </tr>")

                html_lines.append("  </tbody>")
                html_lines.append("</table>\n")

    return html_lines


def generate_schema_documentation(
    schema: dict, major_version: str, output_dir: Path, is_latest: bool, logger
) -> None:
    """
    generate complete schema reference documentation.

    Args:
        schema: parsed JSON schema dict
        major_version: major version string (e.g., "16")
        output_dir: output directory for generated file
        is_latest: whether to add /latest alias to front matter
        logger: logger instance
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / f"{major_version}.md"

    logger.info(f"Generating documentation for schema v{major_version}")

    # categorize definitions
    categories = categorize_definitions(schema, logger)
    all_defs = schema.get("$defs", {})

    # collect all documented types for linkification
    documented_types = get_documented_types(categories, all_defs)

    # generate front matter (must be first - no comments before it)
    front_matter_lines = [
        "+++",
        f'title = "v{major_version}"',
        f'description = "Complete reference for Syft JSON schema version {major_version}"',
        f"weight = {major_version}",
        'type = "docs"',
        f'url = "/docs/reference/syft/json/{major_version}"',
    ]

    if is_latest:
        front_matter_lines.append('aliases = ["/docs/reference/syft/json/latest"]')
        front_matter_lines.append("")
        front_matter_lines.append("[params]")
        front_matter_lines.append('sidebar_badge = "latest"')

    front_matter_lines.append("+++")

    # generate comment (after front matter)
    comment = get_generated_comment("scripts/generate_reference_syft_json_schema.py", "html")
    comment += "<!-- markdownlint-disable MD013 MD033 -->\n"

    # generate content sections
    content_lines = []

    # document section (single type, no h3 to avoid redundant "Document" heading)
    doc_html = []
    doc_html.append('## Document {#document}\n')

    # get and parse Document definition
    doc_def = all_defs.get("Document")
    if doc_def:
        parsed = parse_definition("Document", doc_def, all_defs)

        # type description (if exists)
        if parsed["description"]:
            doc_html.append(f'<p>{parsed["description"]}</p>\n')

        # generate table (same structure as in generate_type_section_html)
        if parsed["fields"]:
            doc_html.append('<table class="schema-table">')
            doc_html.append("  <thead>")
            doc_html.append("    <tr>")
            doc_html.append('      <th class="col-field-name">Field Name</th>')
            doc_html.append('      <th class="col-type">Type</th>')
            doc_html.append('      <th class="col-required">Required?</th>')
            doc_html.append('      <th class="col-description">Description</th>')
            doc_html.append("    </tr>")
            doc_html.append("  </thead>")
            doc_html.append("  <tbody>")

            for field in parsed["fields"]:
                doc_html.append("    <tr>")
                doc_html.append(
                    f'      <td class="col-field-name"><code>{field["name"]}</code></td>'
                )
                # linkify type references
                linked_type = linkify_type_string(field["type"], documented_types)
                doc_html.append(
                    f'      <td class="col-type"><code>{linked_type}</code></td>'
                )

                required_indicator = "✓" if field["required"] else ""
                doc_html.append(
                    f'      <td class="col-required">{required_indicator}</td>'
                )

                doc_html.append(
                    f'      <td class="col-description">{field["description"]}</td>'
                )
                doc_html.append("    </tr>")

            doc_html.append("  </tbody>")
            doc_html.append("</table>\n")
        else:
            doc_html.append("<p><em>No fields defined</em></p>\n")
    else:
        logger.warning("Document definition not found")

    content_lines.extend(doc_html)

    # core types section
    content_lines.extend(
        generate_type_section_html(
            categories["core"], all_defs, "Core Types", logger, documented_types
        )
    )

    # ecosystem types section (with related types)
    content_lines.extend(
        generate_type_section_html(
            categories["ecosystem"],
            all_defs,
            "Ecosystem Types",
            logger,
            documented_types,
            related_types_map=categories["ecosystem_related"],
        )
    )

    # write file (front matter must be first)
    with open(output_file, "w") as f:
        f.write("\n".join(front_matter_lines) + "\n\n")
        f.write(comment)
        f.write("\n".join(content_lines))

    logger.info(f"Generated {output_file}")


@click.command()
@click.option(
    "--schema",
    type=click.Path(exists=True, path_type=Path),
    default=paths.default_schema_file,
    help="Path to Syft JSON schema file",
)
@click.option(
    "--latest",
    is_flag=True,
    help="Add alias for /docs/reference/syft/json/latest path",
)
@click.option(
    "--update",
    is_flag=True,
    help="Update documentation even if output file already exists",
)
@click.option(
    "-v",
    "--verbose",
    count=True,
    help="Increase verbosity (use -v for info, -vv for debug)",
)
def main(schema: Path, latest: bool, update: bool, verbose: int) -> None:
    """Generate JSON schema reference documentation from Syft schema files."""
    logger = setup_logging(verbose, __file__)

    # load schema and extract version
    schema_data, major_version = load_json_schema(schema, logger)

    # check if output already exists
    output_file = paths.json_reference_dir / f"{major_version}.md"
    if output_file.exists() and not update:
        logger.info(f"Output file already exists: {output_file} (use --update to regenerate)")
        return

    # generate documentation
    generate_schema_documentation(
        schema_data, major_version, paths.json_reference_dir, latest, logger
    )

    logger.info("Generation complete!")


if __name__ == "__main__":
    main()
