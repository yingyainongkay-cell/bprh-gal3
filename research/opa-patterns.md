# OPA Rego Patterns for Multi-Tenant AuthZ

## OPA และ Rego v1
OPA 1.0 ทำให้ Rego v1 เป็น syntax เริ่มต้น — `if`, `contains`, `in` เป็น keyword ในตัว ไม่ต้อง import `future.keywords` [22][24]
แนะนำใช้ `opa check --strict` และ `opa fmt --rego-v1` ใน CI [25][27]

## Allow/Deny Pattern
แยก `allow` และ `deny` ชัดเจน แล้ว default deny:

```rego
package authz

default allow := false

allow if {
  input.user.tenant_id == input.resource.tenant_id
  input.user.role == "admin"
}

deny contains msg if {
  input.user.tenant_id != input.resource.tenant_id
  msg := "cross-tenant access denied"
}
