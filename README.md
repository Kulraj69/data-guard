# data-guard

Deterministic PII/secret detection and reversible redaction middleware for
agent pipelines. Offline, standard library only, no model calls.

Corresponds to the "Inter-Agent Security & PII Proxy" idea from Suraj
Sharma's Agentic AI Engineer list: sit between agents (or between agent and
model) and stop sensitive values from crossing the boundary in the clear.

```python
from data_guard import Redactor

guard = Redactor()
safe, findings = guard.redact("refund 4111 1111 1111 1111, email kulraj@example.com")
# -> "refund [CARD_1], email [EMAIL_1]"
answer = call_model(safe)             # model never sees the raw values
final = guard.restore(answer)         # placeholders swapped back
```

Detectors: credit cards (Luhn-validated to reject lookalike numbers), AWS
access key IDs, JWTs, bearer tokens, emails, SSNs, IPv4 addresses, phone
patterns. Placeholders are stable per value, so repeated mentions stay
linked without exposing data.

Honest scope: rule-based detection is defense in depth, not a guarantee of
complete PII removal. Obfuscated or unusual formats will pass through; pair
with policy controls for high-stakes flows.

## Tests

```
python3 -m unittest discover -s tests
```
