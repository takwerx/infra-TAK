import type { App } from 'vue';
import { markRaw } from 'vue';
import type { PluginAPI, PluginInstance } from '@tak-ps/cloudtak';
import { IconBuildingEstate } from '@tabler/icons-vue';
import CadMain from './components/CadMain.vue';

const MENU_KEY   = 'plugin-takcad';
const ROUTE_NAME = 'home-menu-takcad';

export default class TakCadPlugin implements PluginInstance {
    api: PluginAPI;

    constructor(api: PluginAPI) {
        this.api = api;
    }

    static async install(app: App, api: PluginAPI): Promise<TakCadPlugin> {
        void app;
        api.routes.add(
            { path: 'takcad', name: ROUTE_NAME, component: CadMain },
            'home-menu'
        );
        return new TakCadPlugin(api);
    }

    async enable(): Promise<void> {
        this.api.menu.add({
            key:         MENU_KEY,
            label:       'TAK CAD',
            route:       ROUTE_NAME,
            tooltip:     'TAK CAD Dispatcher',
            description: 'Computer-Aided Dispatch — manage incidents, vehicles, and personnel',
            icon:        markRaw(IconBuildingEstate) as unknown as MenuItemIconType,
        } as MenuItemConfig);
    }

    async disable(): Promise<void> {
        try { this.api.menu.remove(MENU_KEY); }          catch { /* ignore */ }
        try { this.api.router.removeRoute(ROUTE_NAME); } catch { /* ignore */ }
    }
}

type MenuItemIconType = NonNullable<Parameters<PluginAPI['menu']['add']>[0]['icon']>;
type MenuItemConfig   = Parameters<PluginAPI['menu']['add']>[0];
