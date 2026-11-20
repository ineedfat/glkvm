"use strict";

const $ = id => document.getElementById(id);
const status = $("status");

async function request(path, payload) {
	const options = {credentials: "same-origin"};
	if (payload !== undefined) {
		options.method = "POST";
		options.headers = {"Content-Type": "application/json"};
		options.body = JSON.stringify(payload);
	}
	const response = await fetch(`/mcp/admin/${path}`, options);
	const text = await response.text();
	if (!response.ok) {
		if (response.status === 401 || response.status === 403) {
			throw new Error("Sign in to the KVM web interface in this browser, then refresh this page.");
		}
		throw new Error(text || `Request failed (${response.status})`);
	}
	return text ? JSON.parse(text) : {};
}

function makeButton(label, action, className = "") {
	const button = document.createElement("button");
	button.type = "button";
	button.textContent = label;
	button.className = className;
	button.addEventListener("click", action);
	return button;
}

function renderPairings(items) {
	const container = $("pairings");
	container.replaceChildren();
	if (!items.length) {
		container.textContent = "None";
		return;
	}
	for (const item of items) {
		const row = document.createElement("div");
		row.className = "row";
		const details = document.createElement("p");
		details.textContent = `${item.name} · code ${item.verification_code} · ${item.ip} · expires in ${item.expires_in}s`;
		row.append(details);
		row.append(
			makeButton("Approve", () => update(`pairings/approve`, {pairing_id: item.id})),
			makeButton("Deny", () => update(`pairings/deny`, {pairing_id: item.id}, "secondary")),
		);
		container.append(row);
	}
}

function renderAgents(items) {
	const container = $("agents");
	container.replaceChildren();
	if (!items.length) {
		container.textContent = "None";
		return;
	}
	for (const item of items) {
		const row = document.createElement("div");
		row.className = "row";
		const lastSeen = item.last_seen ? new Date(item.last_seen * 1000).toLocaleString() : "never";
		const details = document.createElement("p");
		details.textContent = `${item.name} · ${item.enabled ? "enabled" : "disabled"} · last seen ${lastSeen}`;
		row.append(details, makeButton(
			item.enabled ? "Turn off" : "Turn on",
			() => update("agents/toggle", {agent_id: item.id, enabled: !item.enabled}),
			item.enabled ? "secondary" : "",
		));
		container.append(row);
	}
}

async function refresh() {
	try {
		const state = await request("state");
		$("enabled").checked = state.settings.enabled;
		$("networks").value = state.settings.trusted_networks.join("\n");
		$("lease-timeout").value = state.settings.lease_timeout;
		$("max-upload").value = state.settings.max_upload_gb;
		renderPairings(state.pairings);
		renderAgents(state.agents);
		const active = state.controller && state.agents.find(agent => agent.id === state.controller.agent_id);
		$("controller").textContent = active
			? `Current controller: ${active.name} · lease expires in ${state.controller.expires_in}s`
			: "No active controller.";
		status.textContent = "Settings loaded.";
	} catch (error) {
		status.textContent = error.message;
	}
}

async function update(path, payload, className) {
	try {
		await request(path, payload);
		status.textContent = "Change saved.";
		await refresh();
	} catch (error) {
		status.textContent = error.message;
	}
}

$("settings-form").addEventListener("submit", async event => {
	event.preventDefault();
	const payload = {
		enabled: $("enabled").checked,
		trusted_networks: $("networks").value.split(/\r?\n|,/).map(value => value.trim()).filter(Boolean),
		lease_timeout: Number($("lease-timeout").value),
		max_upload_gb: Number($("max-upload").value),
	};
	await update("settings", payload);
});
$("refresh").addEventListener("click", refresh);
refresh();
