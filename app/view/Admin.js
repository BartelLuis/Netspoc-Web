Ext.define('PolicyWeb.view.Admin', {
    extend: 'Ext.Component',
    alias: 'widget.adminview',
    autoEl: {
        tag: 'iframe',
        src: 'admin.html?embedded=1',
        title: 'Policy Administration',
        style: 'width:100%;height:100%;border:0;background:#f4f7fa'
    }
});
