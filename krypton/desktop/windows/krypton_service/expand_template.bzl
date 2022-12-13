"""Rule for specialized expansion of template files. This performs a simple
search over the template file for the keys $VERSION, $VS_VERSION, and
$COPYRIGHT_YEAR and replaces them with the corresponding values, derived from
the version provided. Supports make variables.

Typical usage:
  load("//privacy/net/krypton/desktop/windows/krypton_service:expand_template.bzl", "expand_dfs_template")
  expand_template(
      name = "ExpandMyTemplate",
      out = "my.txt",
      template = "my.template",
      version = varref("VERSION"),
      copyright_year = varref("COPYRIGHT_YEAR"),
  )

Args:
  name: The name of the rule.
  out: The destination of the expanded file
  template: The template file to expand
  version: A string containing the version number. Supports make variables.
  copyright_year: A string containing the copyright year
  is_executable: A boolean indicating whether the output file should be executable
"""

def expand_template_impl(ctx):
    version = ctx.expand_make_variables(
        "expand_dfs_template",
        ctx.attr.version,
        {},
    )
    vs_version = version.replace(".", ",")
    copyright_year = ctx.expand_make_variables(
        "expand_dfs_template",
        ctx.attr.copyright_year,
        {},
    )
    ctx.actions.expand_template(
        template = ctx.file.template,
        output = ctx.outputs.out,
        substitutions = {
            "$VERSION": version,
            "$VS_VERSION": vs_version,
            "$COPYRIGHT_YEAR": copyright_year,
        },
        is_executable = ctx.attr.is_executable,
    )

expand_template = rule(
    implementation = expand_template_impl,
    attrs = {
        "template": attr.label(mandatory = True, allow_single_file = True),
        "version": attr.string(mandatory = False),
        "copyright_year": attr.string(mandatory = False),
        "out": attr.output(mandatory = True),
        "is_executable": attr.bool(default = False, mandatory = False),
    },
)
