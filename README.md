# py_reverse_dns

A small reverse DNS resolver that performs PTR lookups and forward-confirms each name to detect spoofed PTR entries.

```python
from py_reverse_dns import Resolver, Result

resolver = Resolver()
result: Result = resolver.resolve("8.8.8.8")
print(result.confirmed)      # host names that resolve back to 8.8.8.8
print(result.unconfirmed)    # PTR names that did not forward-resolve
print(result.error)          # "" unless the input was not an IP
```

## Why this exists

A bare reverse lookup returns whatever PTR record the owner of an IP's
in-addr.arpa zone chose to publish. Those names are frequently wrong,
stale, or deliberately misleading. Forward-confirmation resolves each
PTR host name back to a list of addresses and only keeps names whose
list includes the original IP. The trade-off is extra DNS queries: each
confirmed name costs one forward lookup, which is slower but far harder
to spoof.

The library uses the standard-library `socket` module only and accepts
a custom resolver function so tests can run with no network access.

## Edge you will hit

`socket.getaddrinfo` with `AI_NUMERICHOST` is used to guarantee the input
is treated as an address literal, never re-parsed as a host name.
`socket.getnameinfo` performs the PTR query itself and is a module-level
function in `socket`, so injecting a fake for it must be done by
patching the module rather than through the constructor. The
constructor only controls the forward-resolution path.
