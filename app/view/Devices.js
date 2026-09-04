Ext.define('PolicyWeb.view.Devices', {
    extend: 'Ext.Component',
    alias: 'widget.devicesview',
    autoEl: {
        tag: 'iframe',
        src: 'about:blank',
        title: 'Geräte und Routing',
        cls: 'pw-devices-frame',
        style: 'width:100%;height:100%;border:0'
    },

    loadDevices: function () {
        var frame = this.getEl() && this.getEl().dom;
        if (!frame || this.devicesLoaded) {
            return;
        }
        this.devicesLoaded = true;
        frame.src = 'devices.html?embedded=1&_=' + new Date().getTime();
    },

    reloadDevices: function () {
        this.devicesLoaded = false;
        this.loadDevices();
    }
});
