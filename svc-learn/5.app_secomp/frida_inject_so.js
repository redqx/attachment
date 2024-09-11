// 192.168.0.105:65000

// frida inject so
function hook_dlopen(){
    const android_dlopen_ext = Module.findExportByName(null, "android_dlopen_ext");
    Interceptor.attach(android_dlopen_ext, {
        onEnter: function(args) {
            this.path = args[0].readCString();
            console.log(this.path)
        },onLeave(ret){
            if (this.path && (this.path).indexOf("libsvctest2.so") >= 0) {
                inject();
            }
        }
    });
}

function inject(){
    const dlopen = new NativeFunction(Module.findExportByName(null, 'dlopen'), 'pointer', ['pointer', 'int']);
    const soPath = Memory.allocUtf8String("/data/local/tmp/libtracer.so");
    var ret = dlopen(soPath, 2);
    console.log("dlopen ret: ", ret);
    const start_trace = new NativeFunction(Module.findExportByName("libtracer.so", "_Z11start_tracev"), 'void', []);
    start_trace();

}

setImmediate(hook_dlopen)