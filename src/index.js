//#region src/worker.ts
var rolePermissions = {
	office: [
		"view_invoices",
		"view_client_records",
		"approve_status_changes"
	],
	engineer: [
		"view_service_reports",
		"view_engineer_jobs",
		"update_job_status"
	]
};
function isValidRole(value) {
	return value === "office" || value === "engineer";
}
function buildAuthResult(role) {
	return {
		authenticated: true,
		userType: role,
		classification: role,
		agentState: {
			role,
			source: "cloudflare-worker-poc",
			permissions: rolePermissions[role]
		}
	};
}
function jsonResponse(data, status = 200) {
	return new Response(JSON.stringify(data, null, 2), {
		status,
		headers: {
			"content-type": "application/json;charset=UTF-8",
			"access-control-allow-origin": "*",
			"access-control-allow-methods": "GET, POST, OPTIONS",
			"access-control-allow-headers": "content-type"
		}
	});
}
//#endregion
//#region \0virtual:cloudflare/worker-entry
var worker_entry_default = { async fetch(request) {
	const url = new URL(request.url);
	if (request.method === "OPTIONS") return jsonResponse({}, 204);
	if (url.pathname === "/api/health") return jsonResponse({
		ok: true,
		service: "auth-role-worker-poc"
	});
	if (url.pathname === "/api/auth/selected-role" && request.method === "GET") {
		const role = url.searchParams.get("role");
		if (!isValidRole(role)) return jsonResponse({
			authenticated: false,
			error: "Invalid role. Expected 'office' or 'engineer'."
		}, 400);
		return jsonResponse(buildAuthResult(role));
	}
	return jsonResponse({ error: "Not found" }, 404);
} };
//#endregion
export { worker_entry_default as default };
