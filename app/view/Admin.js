Ext.define('PolicyWeb.view.Admin', {
    extend: 'Ext.Component',
    alias: 'widget.adminview',
    autoEl: {
        tag: 'iframe',
        src: 'about:blank',
        title: 'Policy Administration',
        style: 'width:100%;height:100%;border:0;background:#f4f7fa'
    },

    loadAdmin: function () {
        var frame = this.getEl() && this.getEl().dom;
        if (!frame || this.adminLoaded) {
            return;
        }
        this.adminLoaded = true;
        // A cache buster also prevents a stale admin document from surviving
        // a container update in the long-lived main application.
        frame.src = 'admin.html?embedded=1&_=' + new Date().getTime();
    },

    reloadAdmin: function () {
        this.adminLoaded = false;
        this.loadAdmin();
    }
});
