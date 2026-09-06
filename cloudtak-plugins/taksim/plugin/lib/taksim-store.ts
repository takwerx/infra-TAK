// SPDX-License-Identifier: AGPL-3.0-or-later
// The PluginAPI handle install() received, for the component to reach the map. Kept as a
// plain module variable on purpose (not reactive state — it holds the Vue app itself).
import type { PluginAPI } from '../../../plugin.ts';
import type { Map as MapLibreMap } from 'maplibre-gl';

let pluginApi: PluginAPI | null = null;

export function setPluginApi(api: PluginAPI): void {
    pluginApi = api;
}

export function getMap(): MapLibreMap {
    if (!pluginApi) throw new Error('TAK Simulator plugin is not installed');
    return pluginApi.map;
}
