<!--
Copyright AGNTCY Contributors (https://github.com/agntcy)
SPDX-License-Identifier: Apache-2.0
-->

# Examples

Runnable, self-contained programs that demonstrate patterns which are **not part
of the AI Catalog specification** and therefore intentionally live outside the
SDK's supported API. Treat them as reference code to copy and adapt, not as a
stable interface.

| Example | Description |
| --- | --- |
| [`oci/`](./oci) | Pack an AI Catalog document into an OCI image layout on disk. Corresponds to the spec's informative "mapping to OCI" — not a normative part of the format. |

Run one with:

```bash
go run ./examples/oci
```
