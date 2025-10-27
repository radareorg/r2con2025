function hookNative() {
    const moduleHandle = Process.findModuleByName('libpairipcore.so');

    
    const jniOnLoad = moduleHandle.findExportByName("JNI_OnLoad");
    if (!jniOnLoad) {
        console.log("[-] JNI_OnLoad not found!");
        return;
    }

    console.log("[+] JNI_OnLoad founded:", jniOnLoad);

    var hook3 = Interceptor.attach(jniOnLoad, {
        onEnter: function(args) {
            console.log("[+] JNI_OnLoad called");
            console.log("JavaVM pointer:", args[0]);
            console.log("reserved:", args[1]);
            
            console.log("Backtrace:\n" + Thread.backtrace(this.context, Backtracer.ACCURATE)
                .map(DebugSymbol.fromAddress).join("\n"));

            startStalker(this.threadId, Process.getModuleByName('libpairipcore.so'));
        },
        onLeave: function(retval) {
            console.log("[+] JNI_OnLoad return value:", retval);
            stopStalker(this.threadId);
            hook3.detach();
        }
    });


    if (!moduleHandle) {
        console.log("[-] libpairipcore.so not found!");
        return;
    }

    const registerNativesOffset = moduleHandle.base.add(0x7618c);
    Interceptor.attach(registerNativesOffset, {
        onEnter: function(args) {
            console.log("[+] RegisterNatives called");
            console.log("    JNIEnv*:", this.context.x0);
            console.log("    jclass:", this.context.x1);
            console.log("    JNINativeMethod*:", this.context.x2);
            console.log("    nMethods:", this.context.x3);

            const nMethods = this.context.x3.toInt32();
            const methods = this.context.x2;
            
            for(let i = 0; i < nMethods; i++) {
                const methodInfo = methods.add(i * Process.pointerSize * 3);
                const name = methodInfo.readPointer().readCString();
                const sig = methodInfo.add(Process.pointerSize).readPointer().readCString();
                const fnPtr = methodInfo.add(Process.pointerSize * 2).readPointer();
                const ghidraOffset = ptr(fnPtr).sub(moduleHandle.base).add(0x00100000);

                console.log(`    Method[${i}]:`);
                console.log(`        name: ${name}`);
                console.log(`        signature: ${sig}`);
                console.log(`        fnPtr: ${fnPtr}`);
                console.log(`        ghidraOffset: ${ghidraOffset}`);
                console.log(`        Ghidra offset: 0x${ghidraOffset.toString(16)}`);
                if (name === "executeVM") {
                    console.log("\n[!] executeVM found, dumping entire library...");
                    dumpLibrary(moduleHandle);
                }
            }
        },
        onLeave: function(retval) {
            console.log("[+] RegisterNatives finished, return value is:", retval);
        }
    });
}

function dumpLibrary(moduleHandle) {
    try {
        console.log("[*] Dumping " + moduleHandle.name);
        console.log("[+] Base: " + moduleHandle.base);
        console.log("[+] Size: 0x" + moduleHandle.size.toString(16) + " (" + moduleHandle.size + " bytes)");
        
        console.log("[*] Reading memory...");
        
        // Sayfa sayfa oku ve birleştir
        var pageSize = 4096;
        var totalSize = moduleHandle.size;
        var allData = [];
        
        for (var offset = 0; offset < totalSize; offset += pageSize) {
            var chunkSize = pageSize;
            if (offset + pageSize > totalSize) {
                chunkSize = totalSize - offset;
            }
            
            try {
                var chunk = moduleHandle.base.add(offset).readByteArray(chunkSize);
                var arr = new Uint8Array(chunk);
                for (var i = 0; i < arr.length; i++) {
                    allData.push(arr[i]);
                }
            } catch (e) {
                console.log("[-] Failed at offset 0x" + offset.toString(16) + ", filling with zeros");
                for (var i = 0; i < chunkSize; i++) {
                    allData.push(0);
                }
            }
            
            if (offset % (pageSize * 100) == 0) {
                console.log("[*] Progress: " + offset + " / " + totalSize);
            }
        }
        
        console.log("[+] Read complete, sending " + allData.length + " bytes...");
        
        // Python'a gönder
        send({
            type: 'dump',
            name: moduleHandle.name,
            base: moduleHandle.base.toString(),
            size: allData.length
        }, allData);
        
        console.log("[+] Dump sent successfully!");
        console.log("[!] Save it with the Python receiver script");
        console.log("\n[!] Freezing process...");
        
        var usleep = new NativeFunction(Module.findExportByName(null, "usleep"), 'int', ['uint']);
        while(true) { 
            usleep(1000000);
        }
    } catch (e) {
        console.log("[-] Dump error: " + e);
        console.log("[-] Stack: " + e.stack);
    }
}

function startStalker(threadId, targetModule){
    Stalker.follow(threadId, {
        transform: function(iterator){
            var instruction;
            while((instruction = iterator.next()) != null){
                if(instruction.address <= targetModule.base.add(targetModule.size) && 
                   instruction.address >= targetModule.base){
                    var offset = instruction.address.sub(targetModule.base);
                    console.log(`[+] ${offset}: ${instruction.toString()}`);
                    
                    if (instruction.mnemonic.startsWith('bl') || instruction.mnemonic.startsWith('b.')) {
                        iterator.putCallout(function(context) {
                            console.log(`    x8=${context.x8.toString(16)}`);
                            console.log(`    x0=${context.x0.toString(16)}`);

                            var moduleDetails = Process.findModuleByAddress(context.x8);
                            if (moduleDetails) {
                                console.log(`    Module: ${moduleDetails.name}`);
                                console.log(`    Base: ${moduleDetails.base}`);
                                console.log(`    Offset in module: 0x${context.x8.sub(moduleDetails.base).toString(16)}`);

                                var symbol = DebugSymbol.fromAddress(context.x8);
                                if (symbol && symbol.name && symbol.name.indexOf("0x") == -1) {
                                    console.log(`    Symbol: ${symbol.name}`);
                                }
                            }
                        });
                    }
                }
                iterator.keep();
            }
        }
    });
}

function stopStalker(threadId){
    Stalker.unfollow(threadId);
    Stalker.flush();
}

var libnative_loaded = 0;
var do_dlopen = null;
var call_ctor = null;

Process.findModuleByName('linker64').enumerateSymbols().forEach(function (sym) {
    if (sym.name.indexOf('do_dlopen') >= 0) {
        do_dlopen = sym.address;
    } else if (sym.name.indexOf('call_constructor') >= 0) {
        call_ctor = sym.address;
    }
});

Interceptor.attach(do_dlopen, function () {
    var libraryPath = this.context.x0.readCString();
    if (libraryPath.indexOf('libpairipcore.so') > -1) {
        console.log(`libpairipcore.so loaded.`);
        
        Interceptor.attach(call_ctor, function () {
            if (libnative_loaded == 0) {
                var native_mod = Process.findModuleByName('libpairipcore.so');
                console.warn(`[+] libpairipcore.so loaded @${native_mod.base}`);
                hookNative();
            }
            libnative_loaded = 1;
        });
    }
});
