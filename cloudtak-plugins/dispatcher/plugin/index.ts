import type { App } from 'vue';
import { markRaw } from 'vue';
import type { PluginAPI, PluginInstance } from '../../plugin.ts';
import type { MenuItemConfig } from '../../plugin.ts';
import { IconBuildingEstate } from '@tabler/icons-vue';
import CadMain from './components/CadMain.vue';

const MENU_KEY   = 'plugin-dispatcher';
const ROUTE_NAME = 'home-menu-dispatcher';

export default class DispatcherPlugin implements PluginInstance {
    api: PluginAPI;

    constructor(api: PluginAPI) {
        this.api = api;
    }

    static async install(app: App, api: PluginAPI): Promise<DispatcherPlugin> {
        void app;
        api.routes.add(
            { path: 'dispatcher', name: ROUTE_NAME, component: CadMain },
            'home-menu'
        );
        return new DispatcherPlugin(api);
    }

    async enable(): Promise<void> {
        this.api.menu.add({
            key:         MENU_KEY,
            label:       'Dispatcher',
            route:       ROUTE_NAME,
            tooltip:     'CloudTAK Dispatcher',
            description: 'Dispatch incidents on the map — works standalone or with TAK-CAD server plugin',
            icon:        markRaw(IconBuildingEstate) as unknown as MenuItemIconType,
        } as MenuItemConfig);
    }

    async disable(): Promise<void> {
        // Only remove the menu item. Do NOT remove the route: CloudTAK calls
        // disable() on every page load before enable() (the isLoaded watcher
        // fires immediately with isLoaded=false), so removing the route here
        // makes the subsequent enable() menu.add fail with "route not found".
        // The route is registered once in install() and left in place — same
        // pattern as the working ping plugin.
        try { this.api.menu.remove(MENU_KEY); } catch { /* ignore */ }
    }
}

type MenuItemIconType = NonNullable<Parameters<PluginAPI['menu']['add']>[0]['icon']>;
