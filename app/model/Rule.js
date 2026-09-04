/*
(C) 2023 by Daniel Brunkhorst <daniel.brunkhorst@posteo.de>
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

// render_rule_side is defined in common.js, since it is used in
// AllServices.js, too (follow DRY principle).
Ext.define(
    'PolicyWeb.model.Rule',
    {
        extend: 'PolicyWeb.model.Netspoc',
        fields: [
            { name: 'has_user', mapping: 'has_user' },
            { name: 'action', mapping: 'action' },
            { name: 'policy_name', mapping: 'policy_name' },
            { name: 'stable_rule_id', mapping: 'stable_rule_id' },
            { name: 'current', mapping: 'current' },
            { name: 'service_name', mapping: 'service' },
            { name: 'active_owner', mapping: 'active_owner' },
            {
                name: 'base_version', mapping: function (node) {
                    return node.base_version || node.policy_version || '';
                }
            },
            {
                name: 'source_refs', mapping: function (node) {
                    return node.source_refs || node.src_refs || node.raw_src || [];
                }
            },
            {
                name: 'destination_refs', mapping: function (node) {
                    return node.destination_refs || node.dst_refs || node.raw_dst || [];
                }
            },
            {
                name: 'protocol_refs', mapping: function (node) {
                    return node.protocol_refs || node.prt_refs || node.raw_prt ||
                        node.prt || [];
                }
            },
            {
                name: 'src',
                sortType: "asIP",
                mapping: function (node) {
                    return render_rule_side(node, 'src');
                }
            },
            {
                name: 'dst',
                sortType: "asIP",
                mapping: function (node) {
                    return render_rule_side(node, 'dst');
                }
            },
            {
                name: 'prt', mapping: function (node) {
                    return node.prt.join('<br>');
                }
            }
        ]
    }
);

