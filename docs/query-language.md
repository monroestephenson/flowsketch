# FlowSketch query language (v0)

Queries are YAML documents. One query per file. The CLI validates and plans
a query before running it — `flowsketch validate` and `flowsketch explain`
show exactly what a query will cost and how accurate it will be.

## Full example

```yaml
name: suspected_scanners        # required; [a-zA-Z0-9_-]+
window:
  size: 60s                     # required; ns/us/ms/s/m/h units
  slide: 10s                    # optional; default = size (tumbling);
                                # size must be a multiple of slide
match:                          # optional filter (alias: where)
  protocol: tcp                 # name (tcp/udp/icmp/icmpv6) or number
  dst.port: [22, 80, 443]       # single port or list
  src.port: 1234
  interfaces: [2]               # interface indexes
groupBy:                        # logical fields to group results by
  - src.ip
measure:                        # required
  type: distinct_count          # count | sum | heavy_hitters | distinct_count
  field: dst.ip                 # for distinct_count
  error:
    epsilon: 0.02               # error target (see accuracy-contracts.md)
    delta: 0.01                 # failure probability (counting sketches)
alertIf:                        # optional: only emit estimates crossing it
  gt: 500
export:
  prometheus: true
  maxSeries: 500                # hard cap on exported series per window
resources:
  maxMemory: 64MiB              # plan budget; over-budget queries are rejected
```

`alertIf.lt` is supported only for ungrouped queries. Grouped plans retain a
bounded top-k/key set, so they cannot soundly enumerate every low-valued or
absent group; the planner rejects that combination instead of silently making
the low-threshold alert unreachable. Grouped `alertIf.gt` remains supported.

## Fields

```
src.ip  dst.ip  src.port  dst.port  protocol  tcp.flags  direction
bytes  packets  interface.index  node.id
```

## Measures

| type             | extra keys        | meaning                                  |
| ---------------- | ----------------- | ---------------------------------------- |
| `count`          | —                 | events per group                         |
| `sum`            | `value` (bytes/packets) | summed value per group             |
| `heavy_hitters`  | `value`, `limit`  | top-`limit` groups by summed value       |
| `distinct_count` | `field`           | approx. distinct `field` values per group|
| `entropy`        | `field`           | empirical entropy (bits) of `field` — ungrouped only |
| `quantile`       | `field`, `q`      | value at quantile `q` of a numeric field — ungrouped only |

## Windows

`slide == size` is a tumbling window. `slide < size` is a sliding window,
implemented as a ring of `size / slide` tumbling buckets whose sketches are
merged at each slide boundary. Estimates are emitted once per slide.

## Validation rules

- unknown fields, measure types, and YAML keys are rejected
- `size` must be a positive multiple of `slide`
- `heavy_hitters` requires `groupBy` (the identities being ranked)
- `distinct_count`'s `field` must not also appear in `groupBy`
- `entropy` and `quantile` reject `groupBy` (bounded keyed distribution
  sketches are a later phase); `q` must be in [0, 1]
- `epsilon`/`delta` must be in (0, 1); `maxSeries` must be positive
- plans whose estimated memory exceeds `resources.maxMemory` are rejected
  at plan time with a suggestion (loosen epsilon, shrink window, raise budget)

## What v0 deliberately does not have

No SQL, cross-query joins, payload predicates, or per-packet sampling controls.
Sampling, when required, must happen upstream and be reflected in how results
are interpreted.
