Ext.define('PolicyWeb.view.Requests', {
    extend: 'Ext.Component',
    alias: 'widget.requestsview',
    autoEl: {
        tag: 'iframe',
        src: 'about:blank',
        title: 'Antragswesen',
        cls: 'pw-requests-frame',
        style: 'width:100%;height:100%;border:0'
    },

    loadRequests: function () {
        var frame = this.getEl() && this.getEl().dom;
        if (!frame || this.requestsLoaded) {
            return;
        }
        this.requestsLoaded = true;
        frame.src = 'requests.html?embedded=1&_=' + new Date().getTime();
    },

    reloadRequests: function () {
        this.requestsLoaded = false;
        this.loadRequests();
    }
});
