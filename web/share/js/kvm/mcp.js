"use strict";

import {tools, $} from "../tools.js";

export function initMcp() {
	const status = $("mcp-status");
	const showStatus = text => { status.textContent = text; };
	const post = (path, value, callback) => tools.httpPost(
		path, null, http => {
			if (http.status < 200 || http.status >= 300) {
				showStatus(`Request failed (${http.status}): ${http.responseText}`);
				return;
			}
			callback(http.responseText ? JSON.parse(http.responseText) : {});
		}, JSON.stringify(value), "application/json");

	const refresh = () => tools.httpGet("mcp/admin/state", null, http => {
		if (http.status < 200 || http.status >= 300) {
			showStatus(`Could not load MCP settings (${http.status})`);
			return;
		}
		const state = JSON.parse(http.responseText);
		$("mcp-enabled").checked = state.settings.enabled;
		$("mcp-networks").value = state.settings.trusted_networks.join("\n");
		$("mcp-lease-timeout").value = state.settings.lease_timeout;
		$("mcp-max-upload").value = state.settings.max_upload_gb;
		const pairings = $("mcp-pairings");
		pairings.replaceChildren();
		for (const item of state.pairings) {
			const row = document.createElement("p");
			const title = document.createElement("span");
			title.textContent = `${item.name} · code ${item.verification_code} · ${item.ip} · ${item.expires_in}s `;
			row.append(title);
			for (const [label, endpoint] of [["Approve", "approve"], ["Deny", "deny"]]) {
				const button = document.createElement("button");
				button.textContent = label;
				button.addEventListener("click", () => post(`mcp/admin/pairings/${endpoint}`, {pairing_id: item.id}, refresh));
				row.append(button, document.createTextNode(" "));
			}
			pairings.append(row);
		}
		const agents = $("mcp-agents");
		agents.replaceChildren();
		for (const item of state.agents) {
			const row = document.createElement("p");
			const label = document.createElement("span");
			label.textContent = `${item.name} · ${item.enabled ? "enabled" : "disabled"} · last seen ${item.last_seen ?? "never"} `;
			const toggle = document.createElement("button");
			toggle.textContent = item.enabled ? "Turn off" : "Turn on";
			toggle.addEventListener("click", () => post("mcp/admin/agents/toggle", {agent_id: item.id, enabled: !item.enabled}, refresh));
			row.append(label, toggle);
			agents.append(row);
		}
		const lease = state.controller;
		$("mcp-controller").textContent = lease
			? `Current controller: ${state.agents.find(agent => agent.id === lease.agent_id)?.name ?? "paired agent"} · lease expires in ${lease.expires_in}s`
			: "Current controller: none";
		showStatus("Settings loaded.");
	});

	$("mcp-save").addEventListener("click", () => post("mcp/admin/settings", {
		enabled: $("mcp-enabled").checked,
		trusted_networks: $("mcp-networks").value.split(/\r?\n|,/).map(value => value.trim()).filter(Boolean),
		lease_timeout: Number($("mcp-lease-timeout").value),
		max_upload_gb: Number($("mcp-max-upload").value),
	}, () => { showStatus("MCP settings saved."); refresh(); }));
	$("mcp-refresh").addEventListener("click", refresh);
	$("system-tool-mcp").querySelector("button").addEventListener("click", refresh);
}
