    const lmdb = require('lmdb-store');

const fs = require('fs-extra')
const os = require('os');     
const {sep} = require('path'); 
    // or
    // import { open } from 'lmdb-store';

    async function lmdb1(){

        let myStore = lmdb.open('/home/shivam/.keri/db', {
            // any options go where, write-map mode is faster:
            useWritemap: true,
            encoding : 'binary',
        });
        
        let a = '1'
        let b = Buffer.from(JSON.stringify({"name":"Shivam"}))
        let data = await myStore.put(a,b)
        let dataReturn  = await myStore.get(a)
        console.log("dataReturn-------------->",dataReturn)
        console.log('-------------------->',data)


    }


    async function pathTest() {
        const tmpDir = os.tmpdir();
console.log("temp directory is ---------------------->",tmpDir,sep)
        fs.mkdtemp(`${tmpDir}${sep}`, (err, directory) => {
            if(directory)
            console.log("Directory is -------------->",directory);
            if (err) throw err;
        
            
            // Will print something similar to `/tmp/abc123`.
            // A new temporary directory is created within
            // the /tmp directory.
          });
    }

    lmdb1()