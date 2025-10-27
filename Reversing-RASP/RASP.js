var LibName = "librarynamehere";

var FileLoaded = 0
var do_dlopen = null;
var call_ctor = null;
var hooked = false;

Process.findModuleByName('linker64')
    .enumerateSymbols()
    .forEach(function (sym) {
        if (sym.name.indexOf('do_dlopen') >= 0) {
            do_dlopen = sym.address;
        } else if (sym.name.indexOf('call_constructor') >= 0) {
            call_ctor = sym.address;
        }
    })

Interceptor.attach(do_dlopen, function () {
    var Library = this.context.x0.readCString();
    if (Library && Library.indexOf(LibName) >= 0) {
        Interceptor.attach(call_ctor, function () {
            var Mod = Process.findModuleByName(LibName);
            /*
                PROT_NONE = 0, 
                PROT_READ = 1 (r--), 
                PROT_WRITE = 2 (-w-), 
                PROT_EXEC = 4 (--x),
                PROT_READ  | PROT_WRITE = 3 (rw-), 
                PROT_READ  | PROT_EXEC = 5 (r-x), 
                PROT_WRITE | PROT_EXEC = 6 (-wx)
                PROT_READ  | PROT_WRITE | PROT_EXEC = 7 (rwx)
            */
            if (!hooked) {
                var mprotectoffset = Mod.base.add(0x00001fc0);
                Interceptor.attach(mprotectoffset, function (args) {
                    console.log(this.context.x0,this.context.x1,this.context.x2)
                    if(this.context.x2 == 0x5){
                        var address = this.context.x0;
                        var size = this.context.x1.toInt32();
                        //Dump(address,size)
                        Interceptor.attach(address.add(0x5ae64),{
                            onLeave : function(retval){
                                console.warn(retval.toInt32())
                                retval.replace(0)
                            }
                        })
                        Interceptor.attach(address.add(0x00061094),{
                            onLeave : function(retval){
                                console.warn(retval.toInt32())
                                retval.replace(0)
                            }
                        })
                        Interceptor.attach(address.add(0x0005b7d8),{
                            onLeave : function(retval){
                                console.warn(retval.toInt32())
                                retval.replace(0)
                            }
                        })
                        Interceptor.attach(address.add(0x0003f978), function(args) {
                            console.warn(this.context.x0.readCString())
                            var str = this.context.x0.readCString();
                            if(str.includes("frida")){
                                console.warn(this.context.x0.readCString())
                                this.context.x0.writeUtf8String("lol")
                            }
                        })
                    }
                })
                hooked = true;
            }
        })

    }
})




function Dump(address, size) {
    let file_path = "/data/data/com.r2con.demo/" + RandString() + ".so";
    let file_handle = new File(file_path, "wb");
    let buffer = address.readByteArray(size);
    file_handle.write(buffer);
    file_handle.flush();
    file_handle.close();
    console.log("Dump :",file_path);
}

function RandString() {
    const characters = "abcdefghijklmnopqrstuvwxyz";
    let result = "";
    for (let i = 0; i < 5; i++) {
        result += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    return result;
}
