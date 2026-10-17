package gateway

import rego.v1

# This module restricts an already permitted read. It cannot grant access.
resource_columns := {
    "customers": ["id", "department", "name", "email", "salary", "national_id"],
    "financial": ["id", "department", "period", "revenue"],
    "production": ["id", "department", "event", "severity"],
}

mask := ["email", "salary", "national_id"] if {
    input.resource == "customers"
    input.subject.role != "admin"
} else := []

scope := {"kind": "all"} if {
    input.subject.role == "admin"
} else := {"kind": "department", "value": input.subject.department}

view_plan := {
    "version": 1,
    "resource": input.resource,
    "columns": resource_columns[input.resource],
    "mask": mask,
    "row_scope": scope,
    "limit": 100,
} if {
    input.decision == "ALLOW"
    input.resource in {"customers", "financial", "production"}
}
