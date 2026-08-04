# Deprecations

This doc lists deprecated features in `rekor`.
You can read more about Sigstore's deprecation policy [here](https://docs.sigstore.dev/api-stability)!

| **Feature Being Deprecated**               | **API Stability Level** | **Earliest Date of Removal** |
|--------------------------------------------|-------------------------|------------------------------|
| Specifying URLs inline in proposed entries | Experimental/Beta/GA    | DD/MM/YY                     |
| `search_index.mysql.max_open_connections`  | Experimental/Beta/GA    | DD/MM/YY                     |
| `search_index.mysql.max_idle_connections`  | Experimental/Beta/GA    | DD/MM/YY                     |

## `search_index.mysql.max_open_connections` and `search_index.mysql.max_idle_connections`

The MySQL search index now uses separate connection pools for reads and writes, so that a
burst of index writes cannot starve the lookups that serve `/api/v1/index/retrieve`. Each
pool is sized independently by `search_index.mysql.read.*` and `search_index.mysql.write.*`.

The two keys above sized the single pool that preceded the split. They are still honored: the
value is split 70/30 between the write and read pools (rounded down, with a floor of 1) so that
the total connection budget is preserved. For example, `max_open_connections: 10` becomes 7
write plus 3 read.

**Do not mix the deprecated keys with the per-pool keys.** If any `read.*` or `write.*` key is
set, the deprecated keys are ignored entirely and a warning is logged at startup.

To size each pool precisely, replace the deprecated keys with explicit per-pool limits:

```yaml
search_index:
  mysql:
    read:
      max_open_connections: 3
      max_idle_connections: 3
    write:
      max_open_connections: 7
      max_idle_connections: 7
```

An index insert is far slower than a lookup's primary-key range scan, so the write pool deserves the
larger share.
