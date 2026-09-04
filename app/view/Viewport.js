/*
(C) 2014 by Daniel Brunkhorst <daniel.brunkhorst@web.de>
            Heinz Knutzen     <heinz.knutzen@gmail.com>

https://github.com/hknutzen/Netspoc-Web

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.
You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

Ext.define(
    'PolicyWeb.view.Viewport',
    {
	extend   : 'Ext.container.Viewport',
        alias    : 'widget.mainview',
	layout   : 'fit',
        
	initComponent : function() {
            this.items = this.buildViewport();
            this.callParent(arguments);
        },

        buildViewport : function () {

            var darkMode = window.PolicyWebTheme &&
                window.PolicyWebTheme.isDark();

            var cardPanel = {
                xtype          : 'panel',
                layout         : 'card',
                activeItem     : 0,
                layoutConfig   : { deferredRender : true },
                border         : false,
                items          :  [
                    // Index of items must be the same as
                    // index of buttons in toolbar below.
                    { xtype : 'serviceview' },
                    { xtype : 'networkview' },
                    { xtype : 'diffview'    },
                    { xtype : 'accountview' },
                    { xtype : 'requestsview' },
                    { xtype : 'devicesview' },
                    { xtype : 'adminview' }
                ],
                tbar   : [
                    {
                        id           : 'btn_services_tab',
                        text         : 'Dienste, Freischaltungen',
                        iconCls      : 'icon-chart_curve',
                        toggleGroup  : 'navGrp',
                        enableToggle : true,
                        pressed      : true
                    },
                    {
                        id           : 'btn_own_networks_tab',
                        text         : 'Eigene Netze',
                        iconCls      : 'icon-computer_connect',
                        toggleGroup  : 'navGrp',
                        enableToggle : true
                    },
                    {
                        id           : 'btn_diff_tab',
                        text         : 'Diff',
                        iconCls      : 'icon-chart_curve_edit',
                        toggleGroup  : 'navGrp',
                        enableToggle : true
                    },
                    {
                        id           : 'btn_entitlement_tab',
                        text         : 'Berechtigungen',
                        iconCls      : 'icon-group',
                        toggleGroup  : 'navGrp',
                        enableToggle : true
                    },
                    {
                        id           : 'btn_requests_tab',
                        text         : 'Antragswesen',
                        iconCls      : 'icon-page_edit',
                        toggleGroup  : 'navGrp',
                        enableToggle : true
                    },
                    {
                        id           : 'btn_devices_tab',
                        text         : 'Geräte',
                        iconCls      : 'icon-server',
                        toggleGroup  : 'navGrp',
                        enableToggle : true,
                        hidden       : true
                    },
                    {
                        id           : 'btn_admin_tab',
                        text         : 'Administration',
                        iconCls      : 'icon-wrench',
                        toggleGroup  : 'navGrp',
                        enableToggle : true,
                        hidden       : true
                    },
                    '->',
                    'Stand',
                    { 
                        id    : 'list_history',
                        xtype : 'historycombo' 
                    },
                    ' ',
                    'Verantwortungsbereich',
                    { 
                        id    : 'list_owner',
                        xtype : 'ownercombo' 
                    },
                    ' ',
                    {
                        id           : 'btn_theme',
                        iconCls      : darkMode ? 'icon-theme-light' : 'icon-theme-dark',
                        tooltip      : darkMode ?
                            'Light Mode aktivieren' : 'Dark Mode aktivieren'
                    },
                    ' ',
                    'Abmelden',
                    {
                        id      : 'btn_logout',
                        iconCls : 'icon-door_out',
                        scope   : this,
                        handler : this.fireLogoutEvent
                    },
                    {   
                        id      : 'btn_info',
                        iconCls : 'icon-info'
                    }
                ]
            };
            return cardPanel;
	},
        
        fireLogoutEvent : function() {
            this.fireEvent( 'logout' );
        }
    }
);
