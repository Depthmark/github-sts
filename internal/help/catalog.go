package help

// catalog maps each exchange error code and policy diagnostic code to its
// help text. An entry depends on the code alone: it never quotes a request,
// a token or a policy, because the response must stay as generic as the code
// (ADR 0012). French wording follows docs/scripts/translate-glossary.json,
// and parameter and field names stay as the API spells them.
var catalog = map[string]Text{
	// Exchange error codes, in the order of the API reference.
	"bad_request": {
		English: "The request is malformed: check that scope is an exact owner/repository, identity is set, the JSON body is valid, and every requested permission is within the trust policy. The error field names the cause.",
		French:  "La requête est malformée : vérifiez que scope est un dépôt exact propriétaire/dépôt, que identity est renseigné, que le corps JSON est valide et que chaque permission demandée reste dans la politique de confiance. Le champ error en donne la cause.",
	},
	"oidc_invalid": {
		English: "The OIDC token was rejected: it is missing, expired, malformed, badly signed or from an issuer this server does not allow. Request a fresh token from your identity provider and send it as a Bearer token.",
		French:  "Le jeton OIDC a été rejeté : il est absent, expiré, malformé, mal signé ou vient d'un émetteur que ce serveur n'autorise pas. Demandez un nouveau jeton à votre fournisseur d'identité et envoyez-le comme jeton Bearer.",
	},
	"github_identity_invalid": {
		English: "The GitHub Actions token lacks the immutable ID claims, or its repository claims contradict each other. Check the repository's OIDC settings, including immutable subject claims, and give the trace_id to your github-sts operator if it persists.",
		French:  "Le jeton GitHub Actions n'a pas les revendications d'identifiants immuables, ou ses revendications de dépôt se contredisent. Vérifiez les paramètres OIDC du dépôt, dont les sujets immuables, et transmettez le trace_id à l'opérateur de github-sts si l'erreur persiste.",
	},
	"audience_mismatch": {
		English: "The token's audience does not match the trust policy. Request the token with the policy's audience value, for example core.getIDToken('<audience>') in GitHub Actions.",
		French:  "L'audience du jeton ne correspond pas à la politique de confiance. Demandez le jeton avec la valeur audience de la politique, par exemple core.getIDToken('<audience>') dans GitHub Actions.",
	},
	"app_unknown": {
		English: "This server has no GitHub App by the name in app. Check the spelling, or omit app when the server has a single App.",
		French:  "Ce serveur n'a aucune GitHub App du nom indiqué dans app. Vérifiez l'orthographe, ou omettez app si le serveur n'a qu'une seule App.",
	},
	"issuer_not_enabled": {
		English: "The token's issuer is not enabled for the requested App. Request an App this issuer is enabled for, or ask your github-sts operator to add the App to the issuer's apps list.",
		French:  "L'émetteur du jeton n'est pas activé pour l'App demandée. Demandez une App pour laquelle cet émetteur est activé, ou demandez à l'opérateur de github-sts d'ajouter l'App à la liste apps de l'émetteur.",
	},
	"policy_not_found": {
		English: "No trust policy exists for this scope, app and identity. Add {base_path}/{app}/{identity}.sts.yaml, where base_path is .github/sts by default, to the target repository, or to the organization policy repository if the server uses one.",
		French:  "Aucune politique de confiance n'existe pour ces scope, app et identity. Ajoutez {base_path}/{app}/{identity}.sts.yaml, où base_path vaut .github/sts par défaut, au dépôt cible, ou au dépôt de politiques d'organisation si le serveur en utilise un.",
	},
	"trust_policy_invalid": {
		English: "The trust policy file exists but breaks the policy contract: it is malformed, has no workload selector, or lacks the github block a GitHub issuer needs. Validate it with POST /sts/v1/trust-policy/validate and fix what it reports.",
		French:  "Le fichier de politique de confiance existe mais enfreint le contrat de politique : il est malformé, n'a aucun sélecteur de charge de travail, ou il lui manque le bloc github qu'exige un émetteur GitHub. Validez-le avec POST /sts/v1/trust-policy/validate et corrigez ce qui est signalé.",
	},
	"policy_denied": {
		English: "A valid trust policy did not match this workload: its subject, a claim_pattern, the source repository or the target repository differs. Compare the policy with your token's claims, and give the trace_id to your github-sts operator for the exact mismatch.",
		French:  "Une politique de confiance valide ne correspond pas à cette charge de travail : son subject, un claim_pattern, le dépôt source ou le dépôt cible diffère. Comparez la politique aux revendications de votre jeton, et transmettez le trace_id à l'opérateur de github-sts pour l'écart exact.",
	},
	"org_policy_denied": {
		English: "The trust policy allowed this exchange, but an enterprise bundle denied it. Give the trace_id to your github-sts operator: the audit log names the bundle rule behind the denial.",
		French:  "La politique de confiance autorisait cet échange, mais un bundle d'entreprise l'a refusé. Transmettez le trace_id à l'opérateur de github-sts : le journal d'audit nomme la règle du bundle à l'origine du refus.",
	},
	"method_not_allowed": {
		English: "This endpoint does not accept that HTTP method. Use GET or POST for /sts/exchange, and POST for /sts/v1/trust-policy/validate.",
		French:  "Ce point de terminaison n'accepte pas cette méthode HTTP. Utilisez GET ou POST pour /sts/exchange, et POST pour /sts/v1/trust-policy/validate.",
	},
	"replay_detected": {
		English: "This OIDC token was already exchanged, and each token works once. Request a fresh OIDC token to exchange, and reuse the GitHub token you already received until it expires.",
		French:  "Ce jeton OIDC a déjà été échangé, et chaque jeton ne sert qu'une fois. Demandez un nouveau jeton OIDC à échanger, et réutilisez le jeton GitHub déjà reçu jusqu'à son expiration.",
	},
	"oidc_unavailable": {
		English: "The server could not fetch your token issuer's signing keys, so it did not judge the token. Retry after Retry-After seconds with the same token, and tell your github-sts operator if it persists.",
		French:  "Le serveur n'a pas pu récupérer les clés de signature de l'émetteur de votre jeton, et n'a donc pas évalué le jeton. Réessayez après Retry-After secondes avec le même jeton, et prévenez l'opérateur de github-sts si l'erreur persiste.",
	},
	"bundle_stale": {
		English: "An enterprise bundle on the server is out of date, so the server refuses exchanges until it refreshes. Retry later, and tell your github-sts operator if it persists.",
		French:  "Un bundle d'entreprise du serveur n'est plus à jour, et le serveur refuse les échanges jusqu'à son rafraîchissement. Réessayez plus tard, et prévenez l'opérateur de github-sts si l'erreur persiste.",
	},
	"bundle_unavailable": {
		English: "The server could not prove that its mandatory enterprise baseline took part, so it refused the exchange. Retry later, and tell your github-sts operator if it persists.",
		French:  "Le serveur n'a pas pu prouver la participation de sa base de référence d'entreprise obligatoire, et a donc refusé l'échange. Réessayez plus tard, et prévenez l'opérateur de github-sts si l'erreur persiste.",
	},
	"bundle_evaluation_failed": {
		English: "An enterprise bundle failed while evaluating this exchange. Retry once, and give the trace_id to your github-sts operator if it fails again.",
		French:  "Un bundle d'entreprise a échoué pendant l'évaluation de cet échange. Réessayez une fois, et transmettez le trace_id à l'opérateur de github-sts si l'échec se répète.",
	},
	"internal_error": {
		English: "The server hit an internal problem that your request did not cause. Give the trace_id to your github-sts operator.",
		French:  "Le serveur a rencontré un problème interne que votre requête n'a pas causé. Transmettez le trace_id à l'opérateur de github-sts.",
	},
	"upstream_error": {
		English: "The server could not read the trust policy or mint the token at GitHub. When Retry-After is present, wait that many seconds and retry; otherwise give the trace_id to your github-sts operator.",
		French:  "Le serveur n'a pas pu lire la politique de confiance ou émettre le jeton auprès de GitHub. Si Retry-After est présent, attendez ce nombre de secondes puis réessayez ; sinon, transmettez le trace_id à l'opérateur de github-sts.",
	},

	// Policy diagnostic codes from /sts/v1/trust-policy/validate.
	"yaml_parse_error": {
		English: "The file is not valid YAML. Fix the syntax that message points to.",
		French:  "Le fichier n'est pas un YAML valide. Corrigez la syntaxe qu'indique message.",
	},
	"invalid_document": {
		English: "A trust policy must be a YAML mapping of fields, such as issuer: and audience:, not a list or a single value.",
		French:  "Une politique de confiance doit être un mappage YAML de champs, comme issuer: et audience:, et non une liste ou une valeur seule.",
	},
	"policy_validation_error": {
		English: "The policy breaks a rule the exchange enforces. Fix what message describes; the trust policy reference lists every field and rule.",
		French:  "La politique enfreint une règle appliquée lors de l'échange. Corrigez ce que décrit message ; la référence des politiques de confiance liste chaque champ et chaque règle.",
	},
	"unknown_field": {
		English: "This field is not part of the trust policy schema. Check its spelling, or remove it.",
		French:  "Ce champ ne fait pas partie du schéma de politique de confiance. Vérifiez son orthographe, ou retirez-le.",
	},
	"subject_conflict": {
		English: "subject and subject_pattern cannot both be set. Keep subject for an exact match, or subject_pattern for a regular expression.",
		French:  "subject et subject_pattern ne peuvent pas être définis ensemble. Gardez subject pour une correspondance exacte, ou subject_pattern pour une expression régulière.",
	},
	"repositories_unsupported": {
		English: "repositories is not supported while organization-level scopes are disabled. Remove it, request an exact repository scope, and bind the repository with github.target.",
		French:  "repositories n'est pas pris en charge tant que les portées d'organisation sont désactivées. Retirez-le, demandez une portée de dépôt exacte, et liez le dépôt avec github.target.",
	},
}
