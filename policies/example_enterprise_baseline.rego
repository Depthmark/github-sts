package sts.enterprise.v1

import rego.v1

config := data.sts.enterprise_config.v1

metadata := {
	"contract_version": "v1",
	"policy_revision": "1",
	"controls": ["immutable_identity", "permission_boundary"],
	"admission": {
		"app": "default",
		"identity": "ci",
		"source": {
			"owner_id": "123456",
			"repository_id": "456789",
		},
		"target": {
			"owner_id": "123456",
			"repository_id": "456789",
		},
		"permissions": {"contents": "read"},
	},
}

permission_rank := {
	"read": 1,
	"write": 2,
	"admin": 3,
}

default decision := {
	"allow": false,
	"reasons": ["exchange input does not satisfy the enterprise contract"],
	"rule_id": "sts.input.invalid",
	"rule_name": "Enterprise input contract",
}

decision := {
	"allow": false,
	"reasons": ["source-to-target relationship is not authorized by the target trust policy"],
	"rule_id": "sts.relationship.source_target",
	"rule_name": "Target-owned immutable relationship",
} if {
	valid_input
	not policy_relationship_allowed
}

decision := {
	"allow": false,
	"reasons": ["app, target, or identity is absent from enterprise guardrails"],
	"rule_id": "sts.context.unknown",
	"rule_name": "Enterprise context allowlist",
} if {
	valid_input
	policy_relationship_allowed
	not central_context_allowed
}

decision := {
	"allow": false,
	"reasons": ["cross-organization relationship has no exact enterprise exception"],
	"rule_id": "sts.relationship.cross_org",
	"rule_name": "Cross-organization exception",
} if {
	valid_input
	policy_relationship_allowed
	central_context_allowed
	not organization_relationship_allowed
}

decision := {
	"allow": false,
	"reasons": ["requested permissions exceed the applicable enterprise ceiling"],
	"rule_id": "sts.permissions.exceeds_ceiling",
	"rule_name": "Layered permission ceiling",
} if {
	valid_input
	policy_relationship_allowed
	central_context_allowed
	organization_relationship_allowed
	not all_permissions_allowed
}

decision := {
	"allow": true,
	"reasons": ["immutable relationship and enterprise permission ceilings satisfied"],
	"rule_id": "sts.enterprise.allow",
	"rule_name": "Enterprise authorization",
} if {
	valid_input
	policy_relationship_allowed
	central_context_allowed
	same_owner
	base_permissions_allowed
}

decision := {
	"allow": true,
	"reasons": ["immutable cross-organization exception and permission ceilings satisfied"],
	"rule_id": "sts.enterprise.allow",
	"rule_name": "Enterprise authorization",
	"exception_id": exception.exception_id,
} if {
	valid_input
	policy_relationship_allowed
	central_context_allowed
	not same_owner
	base_permissions_allowed
	some exception in matching_cross_org_exceptions
	permissions_within(input.requested.permissions, exception.permission_ceiling)
}

valid_input if {
	is_object(input)
	input.mode == "exchange"

	is_object(input.request)
	nonempty_string(input.request.scope)
	nonempty_string(input.request.app)
	nonempty_string(input.request.identity)

	is_object(input.source_identity)
	input.source_identity.version == "v1"
	input.source_identity.issuer == "https://token.actions.githubusercontent.com"
	nonempty_string(input.source_identity.repository_owner)
	valid_id(input.source_identity.repository_owner_id)
	nonempty_string(input.source_identity.repository)
	valid_id(input.source_identity.repository_id)

	is_object(input.target_identity)
	input.target_identity.version == "v1"
	input.target_identity.scope == input.request.scope
	nonempty_string(input.target_identity.repository_owner)
	valid_id(input.target_identity.repository_owner_id)
	input.target_identity.repository == input.request.scope
	valid_id(input.target_identity.repository_id)

	is_object(input.yaml_policy)
	is_object(input.yaml_policy.github)
	is_array(input.yaml_policy.github.sources)
	count(input.yaml_policy.github.sources) > 0
	is_object(input.yaml_policy.github.target)

	is_object(input.requested)
	is_object(input.requested.permissions)
	count(input.requested.permissions) > 0
	input.requested.organization_wide == false
	input.requested.repository_ids == [input.target_identity.repository_id]

	is_object(input.authorization)
	is_array(input.authorization.cross_org_exceptions)
}

policy_relationship_allowed if {
	some source in input.yaml_policy.github.sources
	source.owner_id == input.source_identity.repository_owner_id
	source.repository_id == input.source_identity.repository_id
	input.yaml_policy.github.target.owner_id == input.target_identity.repository_owner_id
	input.yaml_policy.github.target.repository_id == input.target_identity.repository_id
}

app_config := config.apps[input.request.app]

target_config := app_config.targets[input.target_identity.repository_owner_id].repositories[input.target_identity.repository_id]

identity_config := target_config.identities[input.request.identity]

central_context_allowed if {
	config.contract_version == "v1"
	config.approved_source_owner_ids[input.source_identity.repository_owner_id] == true
	config.approved_target_owner_ids[input.target_identity.repository_owner_id] == true
	is_object(app_config)
	is_object(target_config)
	is_object(identity_config)
}

same_owner if {
	input.source_identity.repository_owner_id == input.target_identity.repository_owner_id
}

organization_relationship_allowed if same_owner

organization_relationship_allowed if {
	not same_owner
	count(matching_cross_org_exceptions) > 0
}

all_permissions_allowed if {
	base_permissions_allowed
	same_owner
}

all_permissions_allowed if {
	base_permissions_allowed
	not same_owner
	some exception in matching_cross_org_exceptions
	permissions_within(input.requested.permissions, exception.permission_ceiling)
}

base_permissions_allowed if {
	permissions_within(input.requested.permissions, app_config.permission_ceiling)
	target_ceiling := object.get(target_config, "permission_ceiling", app_config.permission_ceiling)
	permissions_within(input.requested.permissions, target_ceiling)
	identity_ceiling := object.get(identity_config, "permission_ceiling", target_ceiling)
	permissions_within(input.requested.permissions, identity_ceiling)
}

matching_cross_org_exceptions contains exception if {
	some exception in input.authorization.cross_org_exceptions
	exception.source.owner_id == input.source_identity.repository_owner_id
	exception.source.repository_id == input.source_identity.repository_id
	exception.target.owner_id == input.target_identity.repository_owner_id
	exception.target.repository_id == input.target_identity.repository_id
	exception.app == input.request.app
	exception.identity == input.request.identity
	exception.rule_id == "sts.relationship.cross_org"
}

inventory contains exception if {
	some exception in config.cross_org_exceptions
}

permissions_within(requested, ceiling) if {
	is_object(requested)
	count(requested) > 0
	is_object(ceiling)
	every permission, requested_level in requested {
		is_string(requested_level)
		maximum_level := ceiling[permission]
		is_string(maximum_level)
		permission_rank[requested_level] <= permission_rank[maximum_level]
	}
}

nonempty_string(value) if {
	is_string(value)
	value != ""
}

valid_id(value) if {
	is_string(value)
	regex.match("^0*[1-9][0-9]*$", value)
}
