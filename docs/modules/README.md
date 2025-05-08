# Module Documentation

This directory contains detailed documentation for each module in the Cookie Confusion Toolkit.

## Overview

The toolkit is divided into four main modules, each responsible for a specific aspect of cookie security testing:

1. [CookieBomb](cookiebomb.md): Generate degenerate cookie jars to test parsing inconsistencies
2. [ClientFork](clientfork.md): Emulate browser cookie handling to detect client-side inconsistencies
3. [ServerDrift](serverdrift.md): Test server-side cookie parsing inconsistencies
4. [BypassGen](bypassgen.md): Generate exploit chains based on parsing inconsistencies

## Module Interactions

These modules are designed to work together in a research workflow:

1. **CookieBomb** identifies basic parsing issues by generating many edge-case cookies
2. **ClientFork** tests how different browsers handle these cookies
3. **ServerDrift** examines server-side parsing behaviors 
4. **BypassGen** combines the findings to generate potential exploit chains

While each module can be used independently, the most comprehensive security assessment comes from using them together.

## Common Utilities

All modules share common utilities for:

- HTTP requests and response handling
- Cookie parsing and manipulation
- Result storage and analysis
- Authentication and authorization

See the [Utils Documentation](utils.md) for details on these shared components.

## Using Module APIs

Each module can be used programmatically in your own Python code:

```python
from cookie_confusion_toolkit import CookieBomb, ClientFork, ServerDrift, BypassGen

# Initialize a module
cookiebomb = CookieBomb(
    target="https://example.com",
    output_dir="./results",
    verbose=True
)

# Run tests
results = cookiebomb.run_all_tests()

# Access specific test results
collision_results = results["tests"]["key_collisions"]
```

## Extending the Modules

Each module is designed to be extensible. You can add new test types or modify existing ones by:

1. Subclassing the module class
2. Adding new test methods
3. Registering tests with the module's test runner

See the individual module documentation for specific extension points.
