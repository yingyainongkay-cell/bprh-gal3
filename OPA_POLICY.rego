# OPA_POLICY.rego — Sovereign SEOS / Claude-A contract
# Input: top-level handoff envelope plus input.user.tenant_id from a verified JWT;
#        optional input.approval issued by the approval system and bound to task_id.
# Query: data.sovereign.decision
# Output: {allow, human_approval_required, required_approvals, reasons}
#
# IMPORTANT: OPA evaluates claims; the enforcement point must validate the JWT,
# supply input.user.tenant_id from trusted verification, validate the envelope
# schema before evaluation, and fail closed on OPA errors/timeouts.

package sovereign

import rego.v1

default allow := false

default human_approval_required := false
default required_approvals := []

risk_rank := {"low": 0, "medium": 1, "high": 2, "critical": 3}

action_agent := {
    "authorize_generation": "policy_agent",
    "generate_code": "code_agent",
    "review_security": "security_agent",
    "research": "research_agent",
    "validate": "validator_agent",
    "approve": "human_approval_agent",
    "audit": "audit_agent",
}

user_facing_actions := {"authorize_generation", "generate_code", "review_security", "research", "validate"}
system_actions := {"approve", "audit"}

# High/critical requests require approval, but authorize_generation may proceed
# to the approval workflow. This reports the requirement; it does not gate it.
human_approval_required if {
    risk_rank[input.risk_level] >= risk_rank.high
    input.action != "audit"
}

required_approvals := ["human_approval"] if human_approval_required

# input.user.tenant_id is supplied by trusted JWT verification. Never trust the
# context tenant claim alone.
tenant_ok if {
    is_string(input.user.tenant_id)
    input.user.tenant_id != ""
    is_string(input.context.tenant_id)
    input.context.tenant_id == input.user.tenant_id
    data.sovereign_data.user_tenants[input.context.user_id] == input.user.tenant_id
}

identity_ok if {
    is_string(input.task_id)
    input.task_id != ""
    input.agent == "orchestrator"
    input.callback == "orchestrator"
    input.next_agent == action_agent[input.action]
    risk_rank[input.risk_level] >= 0
    is_string(input.context.user_id)
    is_string(input.context.role)
    is_string(input.context.session_id)
    is_string(input.context.auth_method)
    input.payload.task_type in data.sovereign_data.role_permissions[input.context.role].task_types
    risk_rank[input.risk_level] <= risk_rank[data.sovereign_data.role_permissions[input.context.role].max_risk]
}

role_action_ok if {
    input.action in user_facing_actions
    input.action in data.sovereign_data.role_permissions[input.context.role].actions
}

role_action_ok if input.action in system_actions

deadline_ok if input.action == "audit"
deadline_ok if time.parse_rfc3339_ns(input.deadline) > time.now_ns()

constraints_ok if {
    is_number(input.constraints.max_tokens)
    input.constraints.max_tokens > 0
    is_number(input.constraints.temperature)
    input.constraints.temperature >= 0
    is_array(input.constraints.allowed_tools)
    is_array(input.constraints.forbidden_actions)
}

# An approval is accepted only when it is approved, task-bound, from a tenant
# allowlisted approver, timestamped, and carries an audit reason.
approval_valid if {
    input.approval.status == "APPROVED"
    input.approval.task_id == input.task_id
    input.approval.approver in data.sovereign_data.approvers[input.user.tenant_id]
    time.parse_rfc3339_ns(input.approval.approved_at) > 0
    is_string(input.approval.reason)
    input.approval.reason != ""
}

# Audit writes are never blocked by missing approval; prompt must be SHA-256.
action_ok if {
    input.action == "audit"
    regex.match(`^[0-9a-f]{64}$`, input.payload.user_request)
}

# A write_file capability enabled for generate_code is treated as a side effect.
# It is permitted only with valid task-bound approval.
write_file_enabled if {
    input.action == "generate_code"
    not "write_file" in input.constraints.forbidden_actions
}

action_ok if {
    input.action == "generate_code"
    input.constraints.temperature <= 0.3
    not write_file_enabled
}

action_ok if {
    input.action == "generate_code"
    input.constraints.temperature <= 0.3
    write_file_enabled
    approval_valid
}

action_ok if input.action == "authorize_generation"
action_ok if input.action == "review_security"
action_ok if input.action == "research"
action_ok if input.action == "validate"
action_ok if {
    input.action == "approve"
    human_approval_required
}

allow if {
    tenant_ok
    identity_ok
    role_action_ok
    deadline_ok
    constraints_ok
    action_ok
}

reasons contains "cross-tenant access denied" if not tenant_ok
reasons contains "identity, role, or routing denied" if not identity_ok
reasons contains "action not permitted for role" if not role_action_ok
reasons contains "deadline expired or invalid" if not deadline_ok
reasons contains "invalid constraints" if not constraints_ok
reasons contains "side effect requires approved human approval" if {
    write_file_enabled
    not approval_valid
}
reasons contains "action requirements not satisfied" if not action_ok

decision := {
    "allow": allow,
    "human_approval_required": human_approval_required,
    "required_approvals": required_approvals,
    "reasons": reasons,
}
