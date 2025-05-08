# Usage Guide

This guide will help you understand how to use the Cookie Confusion Toolkit (CCT) for security testing of cookie handling implementations.

## Command-Line Interface

The toolkit provides a command-line interface (CLI) for easy usage. The main entry point is the `cct` command.

### General Syntax

```
cct [global options] command [command options] target
```

Where:
- `[global options]` are options that apply to all commands
- `command` is the specific module to run (cookiebomb, clientfork, serverdrift, bypassgen, or full)
- `[command options]` are options specific to the chosen command
- `target` is the URL of the target website to test

### Global Options

- `-v`, `--verbose`: Enable verbose output
- `--version`: Show the version number and exit
- `--log-file FILE`: Specify a log file to write output
- `--output-dir DIR`: Specify the directory for results (default: ./results)
- `--auth-file FILE`: Specify an authentication file
- `--rate-limit SECONDS`: Set the delay between requests in seconds (default: 1.0)

### Commands

The toolkit is divided into four main modules, each accessible as a subcommand:

1. `cookiebomb`: Generate degenerate cookie jars to test parsing inconsistencies
2. `clientfork`: Emulate browser cookie handling to detect client-side inconsistencies
3. `serverdrift`: Test server-side cookie parsing inconsistencies
4. `bypassgen`: Generate exploit chains based on parsing inconsistencies
5. `full`: Run all modules in sequence

## Basic Usage Examples

### Running a Full Scan

To run all modules against a target:

```bash
cct full https://example.com
```

This will run all tests and generate comprehensive results in the ./results directory.

### Testing Cookie Key Collisions

To test cookie name collision handling:

```bash
cct cookiebomb --test key_collisions https://example.com
```

### Testing Browser Cookie Handling

To test how different browsers handle cookies:

```bash
cct clientfork --test cookie_policy https://example.com
```

### Testing Server Cookie Parsing

To test server-side cookie parsing:

```bash
cct serverdrift --test malformed_cookies https://example.com
```

### Generating Exploit Chains

To generate potential exploit chains based on previous test results:

```bash
cct bypassgen https://example.com
```

## Module-Specific Options

### CookieBomb Options

```bash
cct cookiebomb [options] target
```

- `--cookie-names NAME [NAME ...]`: Cookie names to test (default: session, sessionid, SESSIONID)
- `--test {all,key_collisions,overlong_values,path_scoping,whitespace_ambiguity}`: Specific test to run (default: all)

### ClientFork Options

```bash
cct clientfork [options] target
```

- `--browsers BROWSER [BROWSER ...]`: Browsers to test (default: auto-detect)
- `--no-headless`: Disable headless browser mode
- `--test {all,header_injection,cookie_policy,cookie_shadowing}`: Specific test to run (default: all)

### ServerDrift Options

```bash
cct serverdrift [options] target
```

- `--cookie-name NAME`: Cookie name to use for testing (default: session)
- `--test {all,key_overwrite,attribute_truncation,samesite_domain_logic,malformed_cookies}`: Specific test to run (default: all)

### BypassGen Options

```bash
cct bypassgen [options] target
```

- `--results-dir DIR`: Directory containing test results (default: output-dir)
- `--verify`: Verify generated exploits
- `--exploit {all,session_fixation,csrf_disable,jwt_shadowing,path_override,casing_inversion,quote_leak,delimiter_exploit,shadow_cookie}`: Specific exploit to generate (default: all)

## Authentication File

The toolkit supports an authentication file to verify you have permission to test the target. Create a JSON file with the following structure:

```json
{
  "authorized_targets": [
    "example.com",
    "test.mycompany.com"
  ]
}
```

Then use it with the `--auth-file` option:

```bash
cct --auth-file auth.json full https://example.com
```

## Output and Results

Results are saved in the output directory (default: ./results) in JSON format. Each module saves its results in a separate file named after the module and target hostname.

For example:
- `cookiebomb_example.com_1714577823.json`
- `clientfork_example.com_1714577845.json`
- `serverdrift_example.com_1714577867.json`
- `bypassgen_example.com_1714577890.json`

The BypassGen module also creates HTML proof-of-concept files in the `html_exploits` subdirectory.

## Interpreting Results

Each module generates detailed results that can be reviewed to understand potential vulnerabilities:

1. **CookieBomb**: Look for inconsistencies in cookie handling, such as unexpected truncation, key collisions, or path handling.

2. **ClientFork**: Review browser-specific behaviors that might lead to security issues, particularly focusing on cases where browsers handle cookies differently.

3. **ServerDrift**: Analyze server-side parsing behaviors, especially cases where the server handles malformed or edge-case cookies in unexpected ways.

4. **BypassGen**: Examine the generated exploit chains and proof-of-concept HTML files to understand potential attack vectors.

## Ethical Usage

Remember to use this toolkit responsibly and ethically:

1. Only test systems you own or have explicit permission to test
2. Follow responsible disclosure processes for any vulnerabilities discovered
3. Be mindful of the impact your testing may have on production systems
4. Do not use the toolkit for unauthorized access or exploitation

## Advanced Usage

### Custom Tests

You can create custom tests by modifying the appropriate module files. Each module is designed to be extensible.

### Integrating with CI/CD

The toolkit can be integrated into CI/CD pipelines for continuous security testing. Use the JSON output format to parse results programmatically.

### Parallel Testing

For testing multiple targets, you can run multiple instances of the toolkit in parallel, each in its own directory.

## Troubleshooting

If you encounter issues during testing:

1. Enable verbose mode with `-v` to see more detailed output
2. Check the log file if you specified one with `--log-file`
3. Verify that you have the necessary permissions and authentication
4. Ensure your target is accessible and responding to requests
5. Check for rate limiting or blocking behavior from the target

## Next Steps

- Review the [Module Documentation](./modules/README.md) for detailed information about each module
- Check the [Research Background](./research_background.md) to understand the underlying issues
- See the [Remediation Strategies](./remediation.md) for guidance on fixing vulnerabilities
