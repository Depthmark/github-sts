package sts.enterprise.v1

import rego.v1

valid_input_fixture := {
	"mode": "exchange",
	"request": {
		"scope": "example-org/example-repo",
		"app": "default",
		"identity": "ci",
	},
	"source_identity": {
		"version": "v1",
		"issuer": "https://token.actions.githubusercontent.com",
		"repository_owner": "example-org",
		"repository_owner_id": "123456",
		"repository": "example-org/example-repo",
		"repository_id": "456789",
	},
	"target_identity": {
		"version": "v1",
		"scope": "example-org/example-repo",
		"repository_owner": "example-org",
		"repository_owner_id": "123456",
		"repository": "example-org/example-repo",
		"repository_id": "456789",
	},
	"yaml_policy": {"github": {
		"sources": [{"owner_id": "123456", "repository_id": "456789"}],
		"target": {"owner_id": "123456", "repository_id": "456789"},
	}},
	"requested": {
		"permissions": {"contents": "read"},
		"repository_ids": ["456789"],
		"organization_wide": false,
	},
	"authorization": {"cross_org_exceptions": []},
}

test_ci_example_relationship_allows if {
	result := decision with input as valid_input_fixture
	result.allow
	result.rule_id == "sts.enterprise.allow"
}

test_empty_input_denies if {
	result := decision with input as {}
	not result.allow
	result.rule_id == "sts.input.invalid"
}

test_wrong_mode_denies if {
	candidate := object.union(valid_input_fixture, {"mode": "validate"})
	result := decision with input as candidate
	not result.allow
	result.rule_id == "sts.input.invalid"
}

test_missing_source_identity_denies if {
	candidate := object.remove(valid_input_fixture, {"source_identity"})
	result := decision with input as candidate
	not result.allow
	result.rule_id == "sts.input.invalid"
}

test_numeric_source_id_denies if {
	source := object.union(valid_input_fixture.source_identity, {"repository_id": 456789})
	candidate := object.union(valid_input_fixture, {"source_identity": source})
	result := decision with input as candidate
	not result.allow
	result.rule_id == "sts.input.invalid"
}

test_source_absent_from_target_policy_denies if {
	github_policy := object.union(valid_input_fixture.yaml_policy.github, {"sources": [{"owner_id": "123456", "repository_id": "999"}]})
	yaml_policy := object.union(valid_input_fixture.yaml_policy, {"github": github_policy})
	candidate := object.union(valid_input_fixture, {"yaml_policy": yaml_policy})
	result := decision with input as candidate
	not result.allow
	result.rule_id == "sts.relationship.source_target"
}

test_target_policy_id_mismatch_denies if {
	github_policy := object.union(valid_input_fixture.yaml_policy.github, {"target": {"owner_id": "123456", "repository_id": "999"}})
	yaml_policy := object.union(valid_input_fixture.yaml_policy, {"github": github_policy})
	candidate := object.union(valid_input_fixture, {"yaml_policy": yaml_policy})
	result := decision with input as candidate
	not result.allow
	result.rule_id == "sts.relationship.source_target"
}

test_unknown_app_denies if {
	request := object.union(valid_input_fixture.request, {"app": "unknown"})
	candidate := object.union(valid_input_fixture, {"request": request})
	result := decision with input as candidate
	not result.allow
	result.rule_id == "sts.context.unknown"
}

test_unknown_identity_denies if {
	request := object.union(valid_input_fixture.request, {"identity": "unknown"})
	candidate := object.union(valid_input_fixture, {"request": request})
	result := decision with input as candidate
	not result.allow
	result.rule_id == "sts.context.unknown"
}

test_permission_absent_from_ceiling_denies if {
	requested := object.union(valid_input_fixture.requested, {"permissions": {"administration": "write"}})
	candidate := object.union(valid_input_fixture, {"requested": requested})
	result := decision with input as candidate
	not result.allow
	result.rule_id == "sts.permissions.exceeds_ceiling"
}

test_permission_above_ceiling_denies if {
	requested := object.union(valid_input_fixture.requested, {"permissions": {"contents": "admin"}})
	candidate := object.union(valid_input_fixture, {"requested": requested})
	result := decision with input as candidate
	not result.allow
	result.rule_id == "sts.permissions.exceeds_ceiling"
}

test_unknown_permission_level_denies if {
	requested := object.union(valid_input_fixture.requested, {"permissions": {"contents": "owner"}})
	candidate := object.union(valid_input_fixture, {"requested": requested})
	result := decision with input as candidate
	not result.allow
	result.rule_id == "sts.permissions.exceeds_ceiling"
}

test_requested_permissions_are_authoritative if {
	yaml_policy := object.union(valid_input_fixture.yaml_policy, {"permissions": {"contents": "read"}})
	requested := object.union(valid_input_fixture.requested, {"permissions": {"contents": "admin"}})
	candidate := object.union(valid_input_fixture, {
		"yaml_policy": yaml_policy,
		"requested": requested,
	})
	result := decision with input as candidate
	not result.allow
	result.rule_id == "sts.permissions.exceeds_ceiling"
}

test_ci_example_read_allowed_at_ceiling if {
	requested := object.union(valid_input_fixture.requested, {"permissions": {"contents": "read"}})
	candidate := object.union(valid_input_fixture, {"requested": requested})
	result := decision with input as candidate
	result.allow
}

test_deploy_example_allows if {
	result := decision with input as deploy_input
	result.allow
}

test_cross_repo_ci_example_allows if {
	target_identity := {
		"version": "v1",
		"scope": "example-org/backend",
		"repository_owner": "example-org",
		"repository_owner_id": "123456",
		"repository": "example-org/backend",
		"repository_id": "456791",
	}
	yaml_policy := {"github": {
		"sources": [
			{"owner_id": "123456", "repository_id": "456789"},
			{"owner_id": "123456", "repository_id": "456790"},
		],
		"target": {"owner_id": "123456", "repository_id": "456791"},
	}}
	request := object.union(valid_input_fixture.request, {
		"scope": "example-org/backend",
		"identity": "cross-repo-ci",
	})
	requested := object.union(valid_input_fixture.requested, {
		"permissions": {"contents": "read", "pull_requests": "write"},
		"repository_ids": ["456791"],
	})
	candidate := object.union(valid_input_fixture, {
		"request": request,
		"target_identity": target_identity,
		"yaml_policy": yaml_policy,
		"requested": requested,
	})

	result := decision with input as candidate
	result.allow
}

test_identity_ceiling_can_only_narrow if {
	narrow_identity := {"permission_ceiling": {"contents": "read"}}
	narrow_target := object.union(
		data.sts.enterprise_config.v1.apps.default.targets["123456"].repositories["456789"],
		{"identities": {"deploy": narrow_identity}},
	)
	narrow_repositories := {"456789": narrow_target}
	narrow_owner := {"repositories": narrow_repositories}
	narrow_app := object.union(data.sts.enterprise_config.v1.apps.default, {"targets": {"123456": narrow_owner}})
	narrow_apps := {"default": narrow_app}
	narrow_config := object.union(data.sts.enterprise_config.v1, {"apps": narrow_apps})

	result := decision
		with input as deploy_write_input
		with data.sts.enterprise_config.v1 as narrow_config
	not result.allow
	result.rule_id == "sts.permissions.exceeds_ceiling"
}

test_cross_org_denies_without_exception if {
	candidate := cross_org_input
	result := decision
		with input as candidate
		with data.sts.enterprise_config.v1 as cross_org_config
	not result.allow
	result.rule_id == "sts.relationship.cross_org"
}

test_cross_org_exact_exception_allows if {
	candidate := object.union(cross_org_input, {"authorization": {"cross_org_exceptions": [cross_org_exception]}})
	result := decision
		with input as candidate
		with data.sts.enterprise_config.v1 as cross_org_config
	result.allow
	result.exception_id == "xorg-test"
}

test_cross_org_exception_cannot_exceed_its_ceiling if {
	restricted := object.union(cross_org_exception, {"permission_ceiling": {
		"contents": "read",
		"deployments": "read",
		"statuses": "read",
	}})
	candidate := object.union(cross_org_input, {"authorization": {"cross_org_exceptions": [restricted]}})
	result := decision
		with input as candidate
		with data.sts.enterprise_config.v1 as cross_org_config
	not result.allow
	result.rule_id == "sts.permissions.exceeds_ceiling"
}

test_organization_wide_request_denies if {
	requested := object.union(valid_input_fixture.requested, {
		"repository_ids": [],
		"organization_wide": true,
	})
	candidate := object.union(valid_input_fixture, {"requested": requested})
	result := decision with input as candidate
	not result.allow
	result.rule_id == "sts.input.invalid"
}

deploy_input := object.union(valid_input_fixture, {
	"request": object.union(valid_input_fixture.request, {"identity": "deploy"}),
	"requested": object.union(valid_input_fixture.requested, {"permissions": {
		"contents": "read",
		"deployments": "write",
		"statuses": "write",
	}}),
})

deploy_write_input := object.union(deploy_input, {"requested": object.union(deploy_input.requested, {"permissions": {
	"contents": "write",
	"deployments": "write",
	"statuses": "write",
}})})

cross_org_input := object.union(deploy_input, {
	"source_identity": object.union(valid_input_fixture.source_identity, {
		"repository_owner": "other-example-org",
		"repository_owner_id": "9001",
		"repository": "other-example-org/source",
		"repository_id": "9002",
	}),
	"yaml_policy": {"github": {
		"sources": [{"owner_id": "9001", "repository_id": "9002"}],
		"target": {"owner_id": "123456", "repository_id": "456789"},
	}},
})

cross_org_exception := {
	"exception_id": "xorg-test",
	"rule_id": "sts.relationship.cross_org",
	"source": {"owner_id": "9001", "repository_id": "9002"},
	"target": {"owner_id": "123456", "repository_id": "456789"},
	"app": "default",
	"identity": "deploy",
	"permission_ceiling": {
		"contents": "read",
		"deployments": "write",
		"statuses": "write",
	},
	"owner": "platform@example.com",
	"approved_by": "security@example.com",
	"reason": "test migration",
	"created_at": "2026-08-01T00:00:00Z",
	"expires_at": "2026-08-20T00:00:00Z",
}

cross_org_config := object.union(data.sts.enterprise_config.v1, {"approved_source_owner_ids": {
	"123456": true,
	"9001": true,
}})
