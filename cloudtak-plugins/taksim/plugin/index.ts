// SPDX-License-Identifier: AGPL-3.0-or-later
// infra-TAK — TAK Simulator CloudTAK plugin (PLAN v10.1.61 companion, W11)
// Copyright (C) 2026 Andreas Johansson (TAKWERX)
//
// A sidebar tool that lets a demo director design and drive a simulation on the CloudTAK
// map: drop a sweeping radar, aircraft, vessels and ground units, steer them live, fire
// chat / CASEVAC / 911, save the layout as a scenario, and clear everything with one
// button. Nothing is sent from the browser: every action goes to the engine on the box
// (simulator/engine) through the server route (server/plugin-taksim.ts), so all traffic
// stays on the engine's lane(s) — the `simulation` channel unless a real channel was
// deliberately confirmed.
import type { App } from 'vue';
import { markRaw } from 'vue';
import type { PluginAPI, PluginInstance, MenuItemConfig } from '../../plugin.ts';
import { IconRadar } from '@tabler/icons-vue';
import TakSimMain from './components/TakSimMain.vue';
import { setPluginApi } from './lib/taksim-store.ts';
import { dockSim } from './lib/float-pane.ts';

const MENU_KEY = 'plugin-taksim';
const ROUTE_NAME = 'home-menu-taksim';

export default class TakSimPlugin implements PluginInstance {
    api: PluginAPI;

    constructor(api: PluginAPI) {
        this.api = api;
    }

    static async install(app: App, api: PluginAPI): Promise<TakSimPlugin> {
        void app;
        setPluginApi(api);
        api.routes.add(
            { path: 'taksim', name: ROUTE_NAME, component: TakSimMain },
            'home-menu'
        );
        return new TakSimPlugin(api);
    }

    async enable(): Promise<void> {
        this.api.menu.add({
            key: MENU_KEY,
            label: 'TAK Simulator',
            route: ROUTE_NAME,
            tooltip: 'TAK Simulator',
            description: 'Design and direct a simulation on the map — radar, aircraft, vessels, ground units',
            icon: markRaw(IconRadar) as unknown as MenuItemIconType,
        } as MenuItemConfig);
    }

    async disable(): Promise<void> {
        // Only the menu item. CloudTAK calls disable() on every page load before enable()
        // (the isLoaded watcher fires immediately with isLoaded=false); removing the route
        // here would make the following enable() fail with "route not found".
        try {
            this.api.menu.remove(MENU_KEY);
        } catch {
            /* ignore */
        }
        // Also retract the floating pane if detached (a no-op on the load-time disable()).
        try {
            dockSim();
        } catch {
            /* ignore */
        }
    }
}

type MenuItemIconType = NonNullable<Parameters<PluginAPI['menu']['add']>[0]['icon']>;
