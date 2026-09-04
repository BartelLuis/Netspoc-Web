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

var ip_search_tooltip;
var search_window;
var print_window;
var add_user_window;
var del_user_window;
var add_to_rule_window;
var del_from_rule_window;
var overview_window;
var graph_window;
var network_graph;
var cb_params_key2val = {
    'display_property': {
        'true': 'name',
        'false': 'ip'
    },
    'filter_rules': {
        'true': 1,
        'false': 0
    }
};

Ext.define(
    'PolicyWeb.controller.Service', {
    extend: 'Ext.app.Controller',
    views: ['panel.form.ServiceDetails'],
    models: ['Service', 'Overview'],
    stores: ['Service', 'AllServices', 'Rules', 'Users'],
    refs: [
        {
            selector: 'mainview > panel',
            ref: 'mainCardPanel'
        },
        {
            selector: 'servicelist',
            ref: 'servicesGrid'
        },
        {
            selector: 'servicerules',
            ref: 'rulesGrid'
        },
        {
            selector: 'servicedetails',
            ref: 'serviceDetailsForm'
        },
        {
            selector: 'servicedetails > fieldcontainer > button',
            ref: 'ownerTrigger'
        },
        {
            selector: 'servicedetails > fieldcontainer > textfield',
            ref: 'ownerTextfield'
        },
        {
            selector: 'servicedetails > fieldcontainer',
            ref: 'ownerField'
        },
        {
            selector: '#ownerEmails',
            ref: 'ownerEmails'
        },
        {
            selector: '#userEmails',
            ref: 'userDetailEmails'
        },
        {
            selector: 'serviceusers',
            ref: 'serviceUsersView'
        },
        {
            selector: 'serviceview',
            ref: 'serviceView'
        },
        {
            selector: 'serviceview cardprintactive',
            ref: 'detailsAndUserView'
        },
        {
            selector: 'searchwindow > panel',
            ref: 'searchCardPanel'
        },
        {
            selector: 'adduserwindow > form',
            ref: 'addUserFormPanel'
        },
        {
            selector: 'deluserwindow > form',
            ref: 'delUserFormPanel'
        },
        {
            selector: 'addtorulewindow > form',
            ref: 'addToRuleFormPanel'
        },
        {
            selector: 'delfromrulewindow > form',
            ref: 'delFromRuleFormPanel'
        },
        {
            selector: 'searchwindow > form',
            ref: 'searchFormPanel'
        },
        {
            selector: 'searchwindow > form > tabpanel',
            ref: 'searchTabPanel'
        },
        {
            selector: 'chooseservice[pressed="true"]',
            ref: 'chooseServiceButton'
        },
        {
            selector: 'serviceview > grid button[text="Suche"]',
            ref: 'searchServiceButton'
        },
        {
            selector: 'searchwindow > form button[text="Suche starten"]',
            ref: 'startSearchButton'
        },
        {
            selector: 'searchwindow > form checkboxgroup',
            ref: 'searchCheckboxGroup'
        }
    ],

    init: function () {
        this.control(
            {
                'serviceview > servicelist': {
                    select: this.onServiceSelected
                },
                'servicerules': {
                    printrules: this.onPrintRules,
                    selectionchange: this.onRuleRequestSelectionChange
                },
                'servicerules button[requestOperation]': {
                    click: this.onRuleRequestButtonClick
                },
                'serviceusers': {
                    select: this.onUserDetailsSelected
                },
                'servicedetails button': {
                    click: this.onTriggerClick
                },
                'serviceview checkbox': {
                    change: this.onCheckboxChange
                },
                'serviceview > grid chooseservice': {
                    click: this.onButtonClick
                },
                'serviceview > grid button[text="Suche"]': {
                    click: this.displaySearchWindow
                },
                'print-all-button': {
                    click: this.onPrintAllButtonClick
                },
                'expandedservices': {
                    beforeshow: this.onShowAllServices
                },
                'serviceview > grid button[iconCls="icon-map"]': {
                    click: this.onClickOverviewButton
                },
                'searchwindow > panel button[toggleGroup="navGrp"]': {
                    click: this.onNavButtonClick
                },
                'searchwindow > form button[text="Suche starten"]': {
                    click: this.onStartSearchButtonClick
                },
                'searchwindow > form > tabpanel fieldset > textfield': {
                    specialkey: this.onSearchWindowSpecialKey
                },
                'searchwindow > form > tabpanel': {
                    tabchange: this.onSearchWindowTabchange
                },
                'serviceview cardprintactive button[toggleGroup=polDVGrp]': {
                    click: this.onServiceDetailsButtonClick
                }
            }
        );
    },

    onLaunch: function () {

        var store = this.getServiceStore();
        store.on('load',
            function () {
                var count = store.getCount();
                var grid = this.getServicesGrid();
                var sv = this.getServiceView();
                var cardpanel = sv.down('cardprintactive');
                if (count === 0) {
                    this.clearDetails();
                }
                else {
                    this.getServicesGrid().select0();
                }
                // Display nr of services in header.
                grid.getView().getHeaderCt().getHeaderAtIndex(0).setText(
                    'Dienstname (Anzahl: ' + count + ')');
            },
            this
        );

        var userstore = this.getUsersStore();
        userstore.on('load',
            function (ustore) {
                var view = this.getServiceUsersView();
                var header = view.getView().getHeaderCt().getHeaderAtIndex(0);
                // A service selection may have changed while the previous
                // request was still running. Do not expose results belonging
                // to that previous service while the current request is
                // queued.
                if (ustore.policyWebDesiredKey !==
                    ustore.policyWebRequestKey) {
                    ustore.removeAll();
                    if (header) {
                        header.setText('Name (Anzahl: 0)');
                    }
                    this.getUserDetailEmails().clear();
                    return;
                }

                // Always select first user object.
                view.select0();
                if (header) {
                    header.setText(
                        'Name (Anzahl: ' + ustore.getCount() + ')');
                }
                if (ustore.getCount() === 0) {
                    this.getUserDetailEmails().clear();
                }
            },
            this
        );

        var rulesstore = this.getRulesStore();
        rulesstore.on('load',
            function () {
                var grid = this.getRulesGrid();
                if (grid) {
                    grid.select0();
                }
                this.updateRuleRequestButtons();
            },
            this
        );

        appstate.addListener(
            'changed',
            function () {
                if (appstate.getInitPhase()) { return; }
                this.updateRuleRequestButtons();
                this.loadServiceStoreWithParams();
            },
            this
        );
    },

    onRuleRequestSelectionChange: function () {
        this.updateRuleRequestButtons();
    },

    updateRuleRequestButtons: function () {
        var grid = this.getRulesGrid();
        if (!grid) {
            return;
        }
        var selected = grid.getSelectionModel().getSelection();
        var record = selected && selected[0];
        var current = appstate.isCurrentPolicy &&
            appstate.isCurrentPolicy();
        var selectedService = this.getSelectedServiceName();
        var hasIdentity = record && record.get('current') === true &&
            record.get('service_name') === selectedService &&
            record.get('active_owner') === appstate.getOwner() &&
            record.get('stable_rule_id') && record.get('base_version');
        var disabled = grid.getStore().isLoading() || !current || !hasIdentity;
        var tooltip = '';
        if (!current) {
            tooltip = 'Anträge sind nur für den aktuellen Policy-Stand möglich.';
        }
        else if (!record) {
            tooltip = 'Bitte zuerst eine Regel auswählen.';
        }
        else if (!hasIdentity) {
            tooltip = 'Die Regel besitzt keine stabile Identität oder Basisversion.';
        }
        Ext.Array.each(grid.query('button[requestOperation]'),
            function (button) {
                button.setDisabled(disabled);
                button.setTooltip(tooltip || 'Änderung für die ausgewählte Regel beantragen.');
            }
        );
    },

    ruleRequestValues: function (record, field) {
        var modelField = {
            sources: 'source_refs',
            destinations: 'destination_refs',
            protocols: 'protocol_refs'
        }[field];
        var values = modelField ? record.get(modelField) : [];
        if (!Ext.isArray(values)) {
            values = values ? [values] : [];
        }
        return Ext.Array.unique(Ext.Array.clean(Ext.Array.map(values,
            function (value) {
                return Ext.String.trim(String(value || ''));
            }
        )));
    },

    contextObjectReferences: function (data) {
        var values = [];
        var append = function (items, prefix) {
            Ext.Array.each(Ext.isArray(items) ? items : [], function (item) {
                var value;
                if (Ext.isString(item)) {
                    value = item;
                }
                else if (item) {
                    value = item.reference || item.ref || item.value ||
                        item.id || item.name;
                }
                value = Ext.String.trim(String(value || ''));
                if (value && prefix && value.indexOf(':') < 0) {
                    value = prefix + ':' + value;
                }
                if (/^(network|host|fqdn):/.test(value)) {
                    values.push(value);
                }
            });
        };
        append(data.object_refs || data.object_references || data.references ||
            data.objects);
        append(data.networks, 'network');
        append(data.hosts, 'host');
        append(data.fqdns, 'fqdn');
        values.sort();
        return Ext.Array.unique(values);
    },

    onRuleRequestButtonClick: function (button) {
        if (!appstate.isCurrentPolicy || !appstate.isCurrentPolicy()) {
            Ext.Msg.alert('Antrag nicht möglich',
                'Regeländerungen können nur für den aktuellen Policy-Stand beantragt werden.');
            this.updateRuleRequestButtons();
            return;
        }
        var grid = button.up('servicerules');
        var selected = grid.getSelectionModel().getSelection();
        var record = selected && selected[0];
        if (!record) {
            Ext.Msg.alert('Regel auswählen',
                'Bitte zuerst die zu ändernde Regel auswählen.');
            return;
        }
        var stableRuleID = record.get('stable_rule_id');
        var baseVersion = record.get('base_version');
        if (!stableRuleID || !baseVersion) {
            Ext.Msg.alert('Antrag nicht möglich',
                'Die Regel besitzt keine stabile Identität oder Basisversion. Bitte laden Sie die aktuelle Policy neu.');
            return;
        }

        var operation = button.requestOperation;
        var field = button.requestField;
        var serviceName = this.getSelectedServiceName();
        var activeOwner = appstate.getOwner();
        if (record.get('current') !== true ||
            record.get('service_name') !== serviceName ||
            record.get('active_owner') !== activeOwner) {
            Ext.Msg.alert('Auswahl oder Policystand geändert',
                'Die geladene Regel gehört nicht mehr zur aktuellen Auswahl oder zum aktuellen Policystand. Bitte laden Sie den Dienst neu.');
            this.updateRuleRequestButtons();
            return;
        }
        var currentValues = this.ruleRequestValues(record, field);
        if (operation === 'remove' && currentValues.length < 2) {
            Ext.Msg.alert('Antrag nicht möglich',
                'Das letzte Element einer Quelle, eines Ziels oder einer Portliste kann nicht entfernt werden.');
            return;
        }

        if (operation === 'add' && field !== 'protocols') {
            var controller = this;
            Ext.Ajax.request({
                url: 'backend6/requests/context',
                method: 'GET',
                params: {
                    active_owner: activeOwner,
                    base_version: baseVersion,
                    service: serviceName,
                    stable_rule_id: stableRuleID
                },
                success: function (response) {
                    var data;
                    try {
                        data = Ext.decode(response.responseText);
                    }
                    catch (error) {
                        Ext.Msg.alert('Antrag nicht möglich',
                            'Der Server hat ungültige Auswahldaten geliefert.');
                        return;
                    }
                    if (data.success === false) {
                        Ext.Msg.alert('Antrag nicht möglich',
                            Ext.String.htmlEncode(String(data.msg || data.message ||
                                'Die Auswahldaten für den Antrag konnten nicht geladen werden.')));
                        return;
                    }
                    if (data.current !== true || data.base_version !== baseVersion) {
                        Ext.Msg.alert('Policy inzwischen geändert',
                            'Die Basisversion der Regel ist nicht mehr aktuell. Bitte laden Sie die Policy neu.');
                        return;
                    }
                    var available = controller.contextObjectReferences(data);
                    if (field === 'sources') {
                        available = Ext.Array.filter(available,
                            function (value) {
                                return value.indexOf('fqdn:') !== 0;
                            }
                        );
                    }
                    var options = Ext.Array.difference(available, currentValues);
                    if (controller.getSelectedServiceName() !== serviceName ||
                        appstate.getOwner() !== activeOwner) {
                        return;
                    }
                    if (!options.length) {
                        Ext.Msg.alert('Antrag nicht möglich',
                            'Für diesen Verantwortungsbereich sind keine weiteren vorhandenen Objekte verfügbar.');
                        return;
                    }
                    controller.showRuleRequestWindow(
                        record, serviceName, activeOwner, operation, field,
                        options);
                },
                failure: function (response) {
                    controller.showRuleRequestFailure(response);
                }
            });
            return;
        }
        this.showRuleRequestWindow(record, serviceName, activeOwner, operation,
            field, operation === 'remove' ? currentValues : null);
    },

    showRuleRequestWindow: function (record, serviceName, activeOwner,
        operation, field, options) {
        var controller = this;
        var labels = {
            sources: 'Quelle',
            destinations: 'Ziel',
            protocols: 'Port/Protokoll'
        };
        var valueField;
        if (options) {
            var optionData = Ext.Array.map(options, function (value) {
                return { value: value };
            });
            valueField = {
                xtype: 'combo',
                name: 'value',
                fieldLabel: labels[field],
                store: Ext.create('Ext.data.Store', {
                    fields: ['value'],
                    data: optionData
                }),
                displayField: 'value',
                valueField: 'value',
                queryMode: 'local',
                forceSelection: true,
                editable: true,
                allowBlank: false,
                anchor: '100%'
            };
        }
        else {
            valueField = {
                xtype: 'textfield',
                name: 'value',
                fieldLabel: labels[field],
                emptyText: 'z. B. tcp 443 oder udp 53',
                allowBlank: false,
                maxLength: 128,
                anchor: '100%'
            };
        }
        var formPanel = Ext.create('Ext.form.Panel', {
            bodyPadding: 12,
            border: false,
            defaults: { labelWidth: 110 },
            items: [
                {
                    xtype: 'displayfield',
                    fieldLabel: 'Dienst',
                    value: Ext.String.htmlEncode(serviceName || '')
                },
                {
                    xtype: 'displayfield',
                    fieldLabel: 'Vorgang',
                    value: operation === 'add' ? 'Hinzufügen' : 'Entfernen'
                },
                valueField,
                {
                    xtype: 'textarea',
                    name: 'reason',
                    fieldLabel: 'Begründung',
                    allowBlank: false,
                    maxLength: 2000,
                    anchor: '100%',
                    height: 90
                }
            ]
        });
        var window = Ext.create('Ext.window.Window', {
            title: labels[field] +
                (operation === 'add' ? ' hinzufügen' : ' entfernen'),
            modal: true,
            resizable: false,
            width: 560,
            layout: 'fit',
            items: [formPanel],
            buttons: [
                {
                    text: 'Abbrechen',
                    handler: function () { window.close(); }
                },
                {
                    text: 'Antrag senden',
                    itemId: 'send-rule-request',
                    handler: function (sendButton) {
                        var form = formPanel.getForm();
                        if (!form.isValid()) {
                            return;
                        }
                        var values = form.getValues();
                        var value = Ext.String.trim(values.value || '');
                        var reason = Ext.String.trim(values.reason || '');
                        if (!value || !reason) {
                            Ext.Msg.alert('Pflichtangaben fehlen',
                                'Bitte geben Sie einen Wert und eine Begründung an.');
                            return;
                        }
                        sendButton.setDisabled(true);
                        controller.submitRuleRequest({
                            record: record,
                            service: serviceName,
                            activeOwner: activeOwner,
                            operation: operation,
                            field: field,
                            value: value,
                            reason: reason,
                            window: window,
                            button: sendButton
                        });
                    }
                }
            ]
        });
        window.show();
    },

    submitRuleRequest: function (request) {
        var controller = this;
        if (!appstate.isCurrentPolicy || !appstate.isCurrentPolicy() ||
            appstate.getOwner() !== request.activeOwner ||
            controller.getSelectedServiceName() !== request.service ||
            request.record.get('current') !== true ||
            request.record.get('service_name') !== request.service ||
            request.record.get('active_owner') !== request.activeOwner) {
            request.button.setDisabled(false);
            Ext.Msg.alert('Auswahl oder Policystand geändert',
                'Dienst, Verantwortungsbereich oder Policystand wurden geändert. Bitte schließen Sie den Dialog und starten Sie den Antrag erneut.');
            return;
        }
        var payload = {
            request_type: 'rule_change',
            active_owner: request.activeOwner,
            base_version: request.record.get('base_version'),
            reason: request.reason,
            rule_change: {
                service: request.service,
                stable_rule_id: request.record.get('stable_rule_id'),
                operation: request.operation,
                field: request.field,
                value: request.value
            }
        };
        Ext.Ajax.request({
            url: 'backend6/requests',
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            jsonData: payload,
            success: function (response) {
                var data = {};
                try { data = Ext.decode(response.responseText); }
                catch (error) { data = {}; }
                request.window.close();
                var id = data.request_id || data.id || '';
                Ext.Msg.alert('Antrag eingereicht',
                    'Der Regeländerungsantrag' +
                    (id ? ' ' + Ext.String.htmlEncode(String(id)) : '') +
                    ' wurde gespeichert.');
            },
            failure: function (response) {
                request.button.setDisabled(false);
                controller.showRuleRequestFailure(response);
            }
        });
    },

    showRuleRequestFailure: function (response) {
        var message = 'Der Antrag konnte nicht gespeichert werden.';
        try {
            var data = Ext.decode(response.responseText);
            message = data.msg || data.message || message;
        }
        catch (error) {
            // Keep the generic, non-sensitive error message.
        }
        Ext.Msg.alert('Antrag fehlgeschlagen',
            Ext.String.htmlEncode(String(message)));
    },

    onDeleteObjectFromRule: function (view, rowIndex, colIndex, item, e,
        record, row, action) {

        var label2field = {
            'Quelle': 'src',
            'Ziel': 'dst',
            'Protokoll': 'prt'
        };
        var rules_grid = this.getRulesGrid();
        var rules_store = rules_grid.getStore();
        var rec = rules_store.getAt(rowIndex);
        var controller = PolicyWeb.getApplication().getController('Service');

        del_from_rule_window.on(
            'beforeshow',
            function () {
                controller.disableUserRadios(del_from_rule_window, rec);
                var service = controller.getSelectedServiceName();
                var fieldset = del_from_rule_window.down('fieldset');
                var title = "Objekt aus Regel Nr." + (rowIndex + 1) +
                    " des Dienstes \"" + service + "\" entfernen";
                fieldset.setTitle(Ext.String.ellipsis(title, 70));
                var combo = del_from_rule_window.down('combo');
                var radio = del_from_rule_window.down('radio[boxLabel="Protokoll"]');
                var radiogroup = del_from_rule_window.down('radiogroup');
                radiogroup.on(
                    'change',
                    function () {
                        var selected = radio.getGroupValue();
                        var field = label2field[selected];
                        var re = /\s*<br>\s*/;
                        var raw_data = rec.get(field).split(re);
                        var to_array_of_hashes = function (item) {
                            return {
                                item: item
                            };
                        };
                        var combo_store = Ext.create(
                            'Ext.data.Store',
                            {
                                model: 'PolicyWeb.model.Item',
                                data: raw_data.map(to_array_of_hashes),
                                autoLoad: true
                            }
                        );
                        combo.bindStore(combo_store);
                        var records = combo_store.getRange(0, 0);
                        if (records.length > 0) {
                            combo.setValue(records[0].get('item'));
                        }
                        else {
                            combo.setValue('');
                        }
                    }
                );
                radio.setValue(true);
            }
        );
        del_from_rule_window.show();
    },

    disableUserRadios: function (window, rec) {
        var field2label = {
            'src': 'Quelle',
            'dst': 'Ziel'
        };
        var radio;
        if (rec.raw.has_user) {
            var what = rec.raw.has_user === 'both' ?
                ['src', 'dst'] : [rec.raw.has_user];
            for (var i = 0; i < what.length; i++) {
                var selector = 'radio[boxLabel="' + field2label[what[i]] + '"]';
                radio = window.down(selector);
                radio.disable();
            }
        }
    },

    onPrintRules: function () {
        // This overrides the standard printview mechanism, so
        // that we can add the service name to the grid of rules
        // to be printed.
        var service_name = this.getSelectedServiceName();
        if (service_name) {
            var rules_grid = this.getRulesGrid();
            Ext.ux.grid.Printer.mainTitle = 'Dienst: ' + service_name;
            Ext.ux.grid.Printer.print(rules_grid);
            Ext.ux.grid.Printer.mainTitle = '';
        }
    },

    loadServiceStoreWithParams: function () {
        // Take search and other params into account when
        // loading service-store.
        var store = this.getServiceStore();
        var relation = this.getCurrentRelation();
        var extra_params = store.getProxy().extraParams;
        var cb_params = this.getCheckboxParams();
        var search_params = this.getSearchParams();
        var params = Ext.merge(cb_params, extra_params);
        params = Ext.merge(params, search_params);
        params.relation = relation;
        store.load({ params: params });
    },

    getServiceDataParams: function () {
        var params = this.getCheckboxParams();
        var relation = this.getCurrentRelation();
        // The buttons "Eigene", "Genutzte" and "Nutzbare" have a
        // relation attribute. Only the search button has none.
        if (typeof relation === 'undefined' && params.filter_rules === 1) {
            params = Ext.merge(params, this.getSearchParams());
        }
        return params;
    },

    loadSelectedServiceUsers: function (serviceName, params, force) {
        var store = this.getUsersStore();
        var name = arguments.length > 0 ?
            serviceName : this.getSelectedServiceName();

        if (!name) {
            store.policyWebDesiredKey = null;
            store.policyWebQueuedLoad = null;
            store.policyWebLoadedKey = null;
            store.removeAll();
            this.getUserDetailEmails().clear();
            return;
        }

        params = Ext.merge({}, params || this.getServiceDataParams());
        // Pass the complete request context explicitly. This keeps lastOptions
        // useful and prevents a mutable proxy.extraParams object from binding
        // a response to a service selected later.
        params.service = name;
        params.active_owner = appstate.getOwner();
        params.history = appstate.getHistory();
        params.chosen_networks = appstate.getNetworks();

        var key = JSON.stringify(params);
        store.policyWebDesiredKey = key;

        if (!force && store.policyWebLoadedKey === key) {
            return;
        }
        if (store.isLoading()) {
            if (store.policyWebRequestKey !== key) {
                // Store.load does not discard an older Ajax response. Queue
                // the newest selection so requests cannot overwrite each
                // other out of order.
                store.policyWebQueuedLoad = {
                    name: name,
                    params: params,
                    key: key
                };
                store.removeAll();
                this.getUserDetailEmails().clear();
            }
            return;
        }

        store.policyWebQueuedLoad = null;
        store.policyWebRequestKey = key;
        store.getProxy().extraParams.service = name;
        store.load({
            params: params,
            scope: this,
            callback: function (records, operation, success) {
                var requestedKey = store.policyWebRequestKey;
                store.policyWebRequestKey = null;
                if (success && store.policyWebDesiredKey === requestedKey) {
                    store.policyWebLoadedKey = requestedKey;
                }
                else if (store.policyWebDesiredKey === requestedKey) {
                    store.policyWebLoadedKey = null;
                }

                var queued = store.policyWebQueuedLoad;
                store.policyWebQueuedLoad = null;
                if (queued && queued.key === store.policyWebDesiredKey) {
                    this.loadSelectedServiceUsers(
                        queued.name, queued.params, true);
                }
                else if (store.policyWebDesiredKey !== requestedKey) {
                    store.removeAll();
                    this.getUserDetailEmails().clear();
                }
            }
        });
    },

    onServiceSelected: function (rowmodel, service, index, eOpts) {
        // Load details, rules and emails of owners
        // for selected service.
        if (!service) {
            this.clearDetails();
            return;
        }
        this.getController('Main').closeOpenWindows();
        var all_owners = service.get('owner') || [];
        service.set('all_owners', all_owners);

        // Load details form with values from selected record.
        var form = this.getServiceDetailsForm();
        form.loadRecord(service);
        var name = service.get('name');
        var disabled = service.get('disabled');
        var disable_at = service.get('disable_at');

        // Handle multiple owners.
        var trigger = this.getOwnerTrigger();
        if (all_owners.length == 1) {
            // Hide trigger button if only one owner available.
            trigger.hide();
        }
        else {
            // Multiple owners available.
            trigger.show();
        }
        trigger.ownerCt.doLayout();
        // Show emails for first owner. Sets "owner1"-property
        // displayed as owner, too.
        this.onTriggerClick(); // manually call event handler

        // Show additional line if disabled and/or disable_at
        // attributes are present.
        var disabled_textfield = form.getForm().findField('disabled');
        if ((typeof disabled !== 'undefined' || typeof disable_at !== 'undefined') &&
            (disabled !== '' || disable_at !== '')) {
            var disabled_text = disable_at;
            if (typeof disabled !== 'undefined' && disabled !== '') {
                disabled_text = disabled_text + ' DEAKTIVIERT!';
            }
            if (!disabled_textfield) {
                disabled_textfield = {
                    xtype: 'textfield',
                    name: 'disabled',
                    fieldLabel: 'Deaktiviert ab',
                    allowBlank: false,  // requires a non-empty value
                    readOnly: true
                };
                form.addListener(
                    'add',
                    function (my_form, item_added) {
                        //debugger;
                        item_added.setRawValue(disabled_text);
                    });
                form.add(disabled_textfield);
            }
            else {
                disabled_textfield.setRawValue(disabled_text);
            }
        }
        else {
            // Textfield left over from previously selected service?
            // --> remove it.
            if (disabled_textfield) {
                form.remove(disabled_textfield.getId());
            }
        }

        // Load rules.
        var rules_store = this.getRulesStore();
        rules_store.removeAll();
        this.updateRuleRequestButtons();
        rules_store.getProxy().extraParams.service = name;
        var params = this.getServiceDataParams();
        rules_store.load({ params: params });

        // Load users.
        this.loadSelectedServiceUsers(name, params, true);
    },

    onTriggerClick: function () {
        var owner_field = this.getOwnerField();
        var owner_text = this.getOwnerTextfield();
        var formpanel = this.getServiceDetailsForm();
        var form = formpanel.getForm();
        var record = form.getRecord();
        if (record) {
            var array = record.get('all_owners');
            var owner1 = array.shift();
            var name = owner1.name;
            array.push(owner1);
            owner_field.setFieldLabel('Verantwortung:');
            owner_text.setValue(name);
            var emails = this.getOwnerEmails();
            emails.show(name);
        }
    },

    clearDetails: function () {
        var formpanel = this.getServiceDetailsForm();
        var form = formpanel.getForm();
        var trigger = this.getOwnerTrigger();
        form.reset(true);
        trigger.hide();
        trigger.ownerCt.doLayout();
        this.getRulesStore().removeAll();
        this.loadSelectedServiceUsers(null);
        this.getOwnerEmails().clear();
        this.getUserDetailEmails().clear();
    },

    onPrintAllButtonClick: function (button, event, eOpts) {
        if (!Ext.isObject(print_window)) {
            print_window = Ext.create(
                'PolicyWeb.view.window.ExpandedServices'
            );
        }
        print_window.show();
    },

    getSearchParams: function () {
        var search_params = {};
        var form;
        if (Ext.isObject(search_window)) {
            form = this.getSearchFormPanel().getForm();
            if (form.isValid()) {
                search_params = form.getValues();
                return this.removeNonActiveParams(search_params);
            }
        }
        return {};
    },

    onClickOverviewButton: function (button) {
        this.getOverviewData(button, 'graph');
    },

    getOverviewData: function (button, display_as) {

        if (Ext.isObject(graph_window)) {
            graph_window.close();
        }

        graph_window = Ext.create(
            'Ext.window.Window',
            {
                title: 'Überblick über Verbindungen',
                id: 'graph',
                height: 410,
                width: 910,
                items: [{ xtype: 'owncurrentresources' }]
            }
        );

        var res_panel = graph_window.down('owncurrentresources');
        var store = res_panel.getStore();
        var sc = PolicyWeb.getApplication().getController('Service');
        var params = sc.getServiceStore().getProxy().extraParams;
        params.relation = sc.getCurrentRelation();
        params.display_as = display_as;
        params = Ext.merge(
            params,
            sc.getSearchParams()
        );

        graph_window.on(
            'beforeshow',
            function () {
                store.on('load',
                    function () {
                        //console.dir( store.getRange() );
                    }
                );

                store.load({ params: params });
            }
        );

        graph_window.show();
    },

    drawGraph: function (dataset) {

        if (Ext.isObject(graph_window)) {
            graph_window.close();
        }

        graph_window = Ext.create(
            'Ext.window.Window',
            {
                title: 'Überblick über Verbindungen',
                id: 'graph',
                height: 410,
                width: 910
            }
        );

        graph_window.on(
            'show',
            function () {

                // create a network
                var container = document.getElementById('graph-innerCt');
                var data = {
                    nodes: dataset.data.nodes,
                    edges: dataset.data.edges
                };
                var options = {};
                network_graph = new vis.Network(container, data, options);

            }
        );


        graph_window.show();

    },

    displayOverviewGraph: function (data) {
        try {
            if (Ext.isObject(vis)) {
                this.drawGraph(data);
            }
        } catch (err) {
            //console.log( "Caught ERROR: " + err );
            Ext.Loader.loadScript(
                {
                    url: "resources/vis.min.js",
                    onLoad: function () {
                        PolicyWeb.getApplication().getController('Service').drawGraph(data);
                    },
                    onError: function () {
                        alert("Unable to load external graphical library 'vis.min.js'!");
                    }
                }
            );
        }
    },

    displayOverviewList: function (data) {
        var grid;
        if (Ext.isObject(overview_window)) {
            overview_window.close();
        }
        grid = Ext.create(
            'PolicyWeb.view.panel.grid.ConnectionOverview'
        );
        overview_window = Ext.create(
            'Ext.window.Window',
            {
                title: 'Überblick über Verbindungen',
                height: 400,
                width: 600,
                layout: 'fit',
                items: [grid]
            }
        );
        console.dir(data);
        overview_window.on(
            'show',
            function () {
                var store, rec;
                store = grid.getStore();
                store.loadRawData(data.records);
            }
        );
        overview_window.show();
    },

    onShowAllServices: function (win) {
        var srv_store = this.getServiceStore();
        var grid = win.down('grid');
        var extra_params = srv_store.getProxy().extraParams;
        var cb_params = this.getCheckboxParams();
        var params = Ext.merge(cb_params, extra_params);
        params.relation = this.getCurrentRelation();
        params = Ext.merge(
            params,
            this.getSearchParams()
        );
        grid.getStore().load({ params: params });
    },

    getCurrentRelation: function () {
        var b = this.getCurrentlyPressedServiceButton();
        return b ? b.relation : undefined;
    },

    getCurrentlyPressedServiceButton: function () {
        var sg = this.getServicesGrid();
        var tb = sg.getDockedItems('toolbar[dock="top"]');
        var b = tb[0].query('button[pressed=true]');
        return b[0];
    },

    onButtonClick: function (button, event, eOpts) {
        var relation = button.relation;
        var store = this.getServiceStore();
        var proxy = store.getProxy();
        var sb = this.getSearchServiceButton();
        sb.toggle(false);

        // Enable toggling of IPs and object names.
        this.enableAndDisableCheckboxes(
            {
                'display_property': 1
            },
            {
                'filter_rules': 1
            }
        );

        // Don't reload store if button clicked on is the one
        // that was already selected.
        if (!button.pressed && relation &&
            relation === proxy.extraParams.relation) {
            button.toggle(true);
            return;
        }

        // Pressing "Eigene/Genutzte Dienste" should clear
        // search form. Otherwise when changing owner, a search
        // with leftover params will be performed, although
        // own or used services should be displayed.
        if (Ext.isObject(search_window)) {
            this.getSearchFormPanel().getForm().reset();
        }

        proxy.extraParams.relation = relation;
        store.load();
    },

    onNavButtonClick: function (button, event, eOpts) {
        var card = this.getSearchCardPanel();
        var index = button.ownerCt.items.indexOf(button);
        card.layout.setActiveItem(index);
    },

    removeNonActiveParams: function (params) {
        /*
         * Remove textfield params of non-active tabpanel
         * from search parameters.
         */
        var tab_panel = this.getSearchTabPanel();
        var active_tab = tab_panel.getActiveTab();
        var index = tab_panel.items.indexOf(active_tab);
        if (index === 0) {
            params.search_string = '';
        }
        else {
            params.search_ip1 = '';
            params.search_ip2 = '';
            params.search_proto = '';
        }
        return params;
    },

    onStartSearchButtonClick: function (button, event, eOpts) {
        var form = this.getSearchFormPanel().getForm();
        var sb = this.getSearchServiceButton();
        this.enableCheckboxes({ 'filter_rules': 1 });
        if (form.isValid()) {
            button.search_params = form.getValues();
            var store = this.getServiceStore();
            var relation = button.relation;
            var keep_front = false;
            var params = this.removeNonActiveParams(
                button.search_params);

            if (params) {
                keep_front = params.keep_front;
            }
            if (search_window && !keep_front) {
                search_window.hide();
            }

            // Highlight "Suche"-button
            var b = this.getCurrentlyPressedServiceButton();
            if (b && b !== sb) {
                b.toggle(false);
            }
            sb.toggle(true);

            params.relation = '';
            store.on(
                'load',
                function (mystore, records) {
                    if (records.length === 0) {
                        var m = 'Ihre Suche ergab keine Treffer!';
                        Ext.MessageBox.alert('Keine Treffer für Ihre Suche!', m);
                    }
                },
                this,  // scope (defaults to the object which fired the event)
                { single: true }   // deactivate after being run once
            );
            store.load(
                {
                    params: params
                }
            );
        } else {
            var m = 'Bitte Eingaben in rot markierten ' +
                'Feldern korrigieren.';
            Ext.MessageBox.alert('Fehlerhafte Eingabe!', m);
        }
    },

    onServiceDetailsButtonClick: function (button, event, eOpts) {
        var card = this.getDetailsAndUserView();
        var itemId = button.serviceCardItemId;
        var target = itemId ? card.getComponent(itemId) : null;
        if (!target) {
            return;
        }
        var showUsers = itemId === 'service-users-card';

        // Only enable filter checkbox if we are in search mode
        // (relation is undefined).
        var filter = this.getCurrentRelation() === undefined ? 1 : 0;

        if (showUsers) {
            this.enableAndDisableCheckboxes(
                {
                    'filter_rules': filter
                },
                {
                    'display_property': 1
                }
            );
            // A failed or discarded request is retried when the user opens
            // the tab. An already loaded/current request is reused.
            this.loadSelectedServiceUsers();
        }
        else {
            this.enableCheckboxes(
                {
                    'display_property': 1,
                    'filter_rules': filter
                }
            );
        }
        if (card.layout.activeItem !== target) {
            card.layout.setActiveItem(target);
        }
        if (!button.pressed) {
            button.toggle(true);
        }
    },

    enableAndDisableCheckboxes: function (to_enable, to_disable) {
        var card = this.getDetailsAndUserView();
        var usersCard = card.getComponent('service-users-card');
        if (card.layout.activeItem === usersCard) {
            this.disableAllCheckboxes();
        }
        else {
            if (typeof to_enable !== 'undefined') {
                this.enableCheckboxes(to_enable);
            }
            if (typeof to_disable !== 'undefined') {
                this.disableCheckboxes(to_disable);
            }
        }
    },

    enableCheckboxes: function (cb_hash) {
        var view = this.getServiceView();
        var checkboxes = view.query('checkbox');
        Ext.each(
            checkboxes,
            function (cb) {
                if (cb_hash[cb.name] === 1) {
                    cb.enable();
                }
            }
        );
    },

    disableCheckboxes: function (cb_hash) {
        var view = this.getServiceView();
        var checkboxes = view.query('checkbox');
        Ext.each(
            checkboxes,
            function (cb) {
                if (cb_hash[cb.name] === 1) {
                    cb.disable();
                }
            }
        );
    },

    disableAllCheckboxes: function () {
        this.disableCheckboxes(
            {
                'filter_rules': 1,
                'display_property': 1
            }
        );
    },

    onUserDetailsSelected: function (rowmodel, user_item) {
        var owner = '';
        var email_panel = this.getUserDetailEmails();
        if (user_item) {
            owner = user_item.get('owner');
        }
        // Email-Panel gets cleared on empty owner.
        email_panel.show(owner);
    },

    onSearchWindowSpecialKey: function (field, e) {
        // Handle ENTER key press in search textfield.
        if (e.getKey() == e.ENTER) {
            var sb = this.getStartSearchButton();
            sb.fireEvent('click', sb);
        }
    },

    onSpecialKey: function (field, e) {
        // Handle ENTER key press in search textfield.
        var form_panel = field.up('form');
        var button = form_panel.down('button');
        if (e.getKey() == e.ENTER) {
            button.fireEvent('click', button);
        }
    },

    onSearchWindowTabchange: function (tab_panel, new_card, old_card) {
        var tf = new_card.query('textfield:first');
        tf[0].focus(true, 20);
    },

    getCheckboxParams: function (checkbox, newVal) {
        var params = {};
        var view = this.getServiceView();
        var checkboxes = view.query('checkbox');

        Ext.each(
            checkboxes,
            function (cb) {
                var name = cb.getName();
                var value;
                if (!checkbox) {
                    value = cb.getValue();
                }
                else {
                    if (name === checkbox.getName()) {
                        value = newVal;
                    }
                    else {
                        value = cb.getValue();
                    }
                }
                params[name] = cb_params_key2val[name][value];
            }
        );
        return params;
    },

    onCheckboxChange: function (checkbox, newVal, oldVal, eOpts) {
        var params;
        var relation = this.getCurrentRelation();
        var srv_store = this.getServiceStore();
        if (srv_store.getTotalCount() > 0) {
            params = this.getCheckboxParams(checkbox, newVal);
            if (typeof relation === 'undefined' && params.filter_rules === 1) {
                params = Ext.merge(
                    params,
                    this.getSearchParams()
                );
            }
            var rules = this.getRulesStore();
            var fields = rules.model.getFields();
            var sourceField;
            var destinationField;
            Ext.Array.each(fields, function (field) {
                if (field.name === 'src') { sourceField = field; }
                if (field.name === 'dst') { destinationField = field; }
            });
            if (params.display_property === "name" && newVal === true) {
                sourceField.sortType = "asUCText";
                destinationField.sortType = "asUCText";
            }
            else {
                sourceField.sortType = "asIP";
                destinationField.sortType = "asIP";
            }
            rules.model.setFields(fields);
            rules.load({ params: params });
            this.loadSelectedServiceUsers(
                this.getSelectedServiceName(), params, true);
        }
        if (Ext.isObject(print_window)) {
            this.onShowAllServices(print_window);
        }
    },

    displaySearchWindow: function () {
        if (!search_window) {
            search_window = Ext.create(
                'PolicyWeb.view.window.Search'
            );
            search_window.on('show', function () {
                search_window.center();
                var t = search_window.query(
                    'form > tabpanel fieldset > textfield'
                );
                t[0].focus(true, 20);
            }
            );
        }
        search_window.show();
    },

    //
    // Helper functions for convenience and code reuse.
    //
    getSelectedService: function () {
        var service;
        var service_grid = this.getServicesGrid();
        var sel_model = service_grid.getSelectionModel();
        var selected = sel_model.getSelection();
        if (selected) {
            service = selected[0];
        }
        return service;
    },

    getSelectedServiceData: function () {
        var data;
        var service = this.getSelectedService();
        if (service) {
            data = service.data;
        }
        return data || undefined;
    },

    getSelectedServiceName: function () {
        var service_name;
        var data = this.getSelectedServiceData();
        if (data) {
            service_name = data.name;
        }
        return service_name || undefined;
    }
}
);
