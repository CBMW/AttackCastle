# Adapter SDK Notes

Adapters implement a simple contract:

- input: `AdapterContext`, `RunData`
- output: `AdapterResult`
- metadata: `capability`, `noise_score`, `cost_score`
- optional planner hint: `preview_commands(context, run_data)`

`AdapterResult` can include:

- assets, services, web apps, technologies, TLS records
- observations and evidence
- tool execution metadata
- facts, warnings, and errors

Guidelines:

- always preserve source tool attribution
- write raw artifacts before parsing where possible
- return partial results even on soft failures
- keep adapter logic isolated from report/findings code
