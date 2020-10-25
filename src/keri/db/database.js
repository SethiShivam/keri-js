// "use strict";

const fs = require('fs-extra')
const os = require('os');
const path = require('path');
// const lmdb = require('lmdb-store');
const lmdb = require('node-lmdb');


var Set = require("collections/set");
const { pad } = require('./util')
const util= require('util');
const encoder = new util.TextEncoder('utf-8');
let MaxHexDigits = 6
let MaxForks = parseInt('f'.repeat(MaxHexDigits), 16)  // # 16777215
class Databaser {

    // const MAX_DB_COUNT = 16;
    // const DATABASE_DIR_PATH = "/var/keri/db"
    // const ALT_DATABASE_DIR_PATH = path.join("~", '.keri/db')
    // const DB_KEY_EVENT_LOG_NAME = Buffer.from('kel', 'binary')

    /**
     * @description  Setup main database directory at .dirpath.
                    Create main database environment at .env using .dirpath.
     * @param {*} headDirPath headDirPath is str head of the pathname of directory for main database
                If not provided use default headDirpath
     * @param {*} name  name is str pathname differentiator for directory for main database
                When system employs more than one keri databse name allows
                differentiating each instance by name
     * @param {*} temp   temp is boolean If True then use temporary head pathname  instead of
                headDirPath if any or default headDirPath
     */
    constructor(headDirPath = null, name = 'main', temp = false) {

        let HeadDirPath = "/var"
        let TailDirPath = "keri/db"
        let AltHeadDirPath = path.join("~", '.keri/db')
        let AltTailDirPath = ".keri/db"
        // let ALT_DATABASE_DIR_PATH = 
        let MaxNamedDBs = 16


        if (temp) {

            const tmpDir = '/home/shivam/Desktop/shivam/test_lmdb'
            //os.tmpdir();
            const suffix = `/keri_lmdb_test`
            HeadDirPath = fs.mkdtempSync(`${tmpDir}${suffix}`)
            console.log("Db path is ----------->", name)
            this.path = path.join(HeadDirPath, name)
            console.log("Db path is ----------->", this.path)
            fs.mkdirSync(this.path,0o777)
        }
        if (!headDirPath)
            headDirPath = HeadDirPath + '/' + TailDirPath
        let baseDirPath = path.resolve(resolveHome(headDirPath))
        if (!fs.pathExistsSync(baseDirPath)) {
            try {
                fs.mkdirsSync(baseDirPath, 0o777)
            } catch (e) {
                baseDirPath = AltHeadDirPath
                baseDirPath = path.resolve(resolveHome(baseDirPath))
                if (!fs.pathExistsSync(baseDirPath)) {
                    fs.mkdirsSync(baseDirPath, 0o777)
                }
            }
        } else {
            if (fs.accessSync(baseDirPath, fs.constants.F_OK | fs.constants.W_OK | fs.constants.R_OK)) {
                baseDirPath = AltHeadDirPath
                baseDirPath = path.resolve(resolveHome(baseDirPath))
                if (!fs.pathExistsSync(baseDirPath)) { fs.mkdirsSync(baseDirPath, 0o777) }
            }
        }
        // set global db directory path
        //   this.env = new lmdb.Env();
     let   env = new lmdb.Env();
        env.open({ path: baseDirPath, mapSize: 2 * 1024 * 1024 * 1024, maxDbs: MaxNamedDBs })

        // this.names = name
            
        //    var stat = dbi.stat(txn);
        //    console.log("stat ------------------->",stat)
        this.path = baseDirPath
        this.env = env 

        // this.headDirPath = headDirPath
        // this.name = name
        // this.temp = temp
        // // file = _os.path.join(dir, prefix + name + suffix)
        // if (this.temp) {
        //     const tmpDir = os.tmpdir();
        //     const suffix = `/keri_lmdb_test`
        //     HeadDirPath = fs.mkdtempSync(`${tmpDir}${suffix}`)
        //     this.path = path.join(HeadDirPath, this.name)
        //     console.log("Db path is ----------->",this.path)
        //     fs.mkdirSync(this.path)

        // }else {
        //     if(!this.headDirPath) {

        //         this.headDirPath = HeadDirPath
        //         this.path = path.join(this.headDirPath,TailDirPath,this.name)


        //             console.log("this.path ------------>",this.path)
        //             if(!fs.pathExistsSync(this.path)){
        //                 try{
        //                     fs.mkdirSync(this.path,{ recursive: true })
        //                 }catch(error){
        //                     this.path = path.join(process.env.HOME,this.headDirPath,TailDirPath,this.name)
        //                 }

        //             }else 
        //             console.log('Directory already exist')
        //     }


        // }

    }

    clearDirPath() {
        console.log("this.env ===========>", this.path)
        if (this.env) {
            try {
                console.log("Inside try")
                this.env.close()
            } catch (err) {
                console.log("Inside error")
            }
            if (fs.pathExistsSync(this.path)) {
                fs.removeSync(this.path, { recursive: true });
                console.log("path Successfully removed ")
            }


        }

    }



    /**
     * @description         Write serialized bytes val to location key in db .Does not overwrite.
            Returns True If val successfully written Else False
            Returns False if val at key already exitss
     * @param {*} db db is opened named sub db with dupsort=False
     * @param {*} key key is bytes of key within sub db's keyspace
     * @param {*} value val is bytes of value to be written
     */
    putVal(db, key, value) {
try{
   
    let dbi = this.env.openDbi({
        name: db,
        create: true ,// will create if database did not exist,
        dupSort: true,
    }) 
        // key = encoder.encode(key)
      let txn = this.env.beginTxn();

        if (txn.getBinary(dbi, key) == null) {
            console.log("Inside if Confition")
            txn.putBinary(dbi, key, value, { keyIsBuffer: true });
            console.log("value successfully added")
           txn.commit();
           dbi.close();
            
            return true
        } else {
            console.log("value already exist")
            return false
        }
    
    }catch(error){
            console.log("ERROR==========>")
            return false
        }
        // finally{
        //     dbi.close();
        // }
    }


    /**
     * @description  Write serialized bytes val to location key in db
            Overwrites existing val if any
            Returns True If val successfully written Else False
     * @param {} dbi db is opened named sub db with dupsort=False
     * @param {*} key key is bytes of key within sub db's keyspace
     * @param {*} value val is bytes of value to be written
     */
    setVal(db, key, value) {
        try {

            let dbi = this.env.openDbi({
                name: db,
                create: true // will create if database did not exist
            })
            key = encoder.encode(key)
             let txn = this.env.beginTxn();
            this.txn.putBinary(dbi, key, value, { keyIsBuffer: true });
             txn.commit();


             dbi.close();
            return true
        } catch (error) {
            console.log("SETVAL ERROR : \n",error )
            return false
        }
        
        // finally{
        //     dbi.close();
        // }
    }
    updateVal(db, key, value) {

        try {

            let dbi = this.env.openDbi({
                name: db,
                create: true // will create if database did not exist
            })
           
           
            key = encoder.encode(key)
         let txn = this.env.beginTxn();
            txn.putBinary(dbi, key, value, { keyIsBuffer: true });
            txn.commit();
            return true
        } catch (error) {
            console.log("ERROR :\n",error)
            return false
        }

    }

    getVal(db, key) {

        let dbi = this.env.openDbi({
            name: db,
            dupSort: true,
            create : true
        })
        try {
            key = encoder.encode(key)
             let txn = this.env.beginTxn({ readOnly: true });

            var data = txn.getBinary(dbi, key);
            console.log("Data is --------------->",data.toString())
            txn.commit()
            return data.toString()
        } catch (error) {
            console.log("getVal ERROR :\n",error)
            return false
        }finally{
            dbi.close();
        }
    }

    delVal(db, key) {

        let dbi = this.env.openDbi({
            name: db,
     // will create if database did not exist
        })
        try {
            let txn = this.env.beginTxn();

            txn.del(dbi, key);
            txn.commit()
            return true

        } catch (error) {
console.log("ERROR :\n")
            return false
        }finally {
            dbi.close();
        }



    }


    /**
     * @description Write each entry from list of bytes vals to key in db.Adds to existing values at key if any
     */
    putVals(db, key, vals) {
        try {

            let dbi = this.env.openDbi({
                name: db,
                create: true, // will create if database did not exist
                dupSort: true,
            })
            // key = encoder.encode(key)
             let txn = this.env.beginTxn();


            for (let i = 0; i < vals.length  ; i++) {
                        console.log("Inside loop",vals[i])
                txn.putBinary(dbi, key,vals[i],{ keyIsBuffer: true })

             
            }
            console.log("values successfully added")
                txn.commit()
                // dbi.close()
            return true
        } catch (error) {
            console.log("Catch error ",error)
            return false
        }


    }



    /**
     * @description   Return array of values at key in db .Returns empty array if no entry at key

        Duplicates are retrieved in lexocographic order not insertion order.
     * @param {*} db db is opened named sub db with dupsort=True
     * @param {*} key key is bytes of key within sub db's keyspace
     */
    getVals(db, key) {
      
        try {           
              let  dbi = this.env.openDbi({
                    name: db,
                    dupSort: true,
    
                })

                let txn = this.env.beginTxn();
           
          let  cursor = new lmdb.Cursor(txn, dbi,{ keyIsBuffer: true });
            let vals = []
       
            // if (cursor.goToRange(key) === key) {
            //     console.log("key found")
            //     do {
            //         cursor.getCurrentNumber(function (key, data) {
            //             // do something with data
            //             vals.push(data)
            //         });
            //     } while (cursor.goToNextDup());
            // }
            console.log("cursor.goToRange(key) ==================>",'\n',cursor.goToRange(key))
    
                console.log("Inside If condition")
                if(cursor.goToRange(key)){
                for (var found = (cursor.goToRange(key) === key); found !== null; found = cursor.goToNextDup()) {
                    cursor.getCurrentBinary(function(key,value){
                        console.log("value is ------->",value.toString())
                        vals.push(value)
                    })} 
                   
                }
          console.log("value ===========>",vals.toString())
                txn.commit()
        //   dbi.close()
            return vals
        } catch (error) {
            console.log("Error is ---------------_>",error)
 
            return false
        }
    }

    // getVals(db, key) {
    //     try {

    //         let dbi = this.env.openDbi({
    //             name: db,
    //             create: true, // will create if database did not exist
    //             dupSort: true,
    //             keyIsBuffer: true
    //         })

    //         let txn = this.env.beginTxn();
    //         let cursor = new lmdb.Cursor(txn, dbi);
    //         let vals = []
    //         console.log("cursor.goToKey(key) =================>",   cursor.goToDup(key))
    //         if (cursor.goToRange(key) === key) {
    //             console.log("key found")
    //             do {
    //                 cursor.getCurrentNumber(function (key, data) {
    //                     // do something with data
    //                     vals.push(data)
    //                 });
    //             } while (cursor.goToNextDup());
    //         }
    //         console.log("vals --------------__>", vals)
    //         return vals
    //     } catch (error) {
    //         console.log("Error is ---------------_>",error)
    //         return false
    //     }
    // }


    /**
     * @description Return iterator of all dup values at key in db
            Raises StopIteration error when done or if empty
            Duplicates are retrieved in lexocographic order not insertion order.
     * @param {*} db    db is opened named sub db with dupsort=True
     * @param {*} key   key is bytes of key within sub db's keyspace
     */

    * getValsIter(db, key) {

        try {

            let dbi = this.env.openDbi({
                name: db,
                create: true, // will create if database did not exist
                dupSort: true
            })
            let response = null
            let txn = this.env.beginTxn();
            let cursor = new lmdb.Cursor(txn, dbi);
            let vals = []
            if (cursor.goToRange(key) === key) {


                // for (val in cursor.goToNextDup() )
                // yield val
                do {
                    cursor.getCurrentNumber(function (key, data) {
                        response = data
                    });
                    yield responses
                } while (cursor.goToNextDup());
            }

            txn.commit()
        } catch (error) {
            return false
        }


    }



    /**
     * @description Return count of dup values at key in db, or zero otherwise

     * @param {*} db db is opened named sub db with dupsort=True
     * @param {*} key key is bytes of key within sub db's keyspace
     */

    cntVals(db, key) {
        let txn = this.env.beginTxn();
        console.log("COUNTER IS ==========>")
        let count = 0
        try {

            let dbi = this.env.openDbi({
                name: db,
                // create: true,
                dupSort: true
            })
            let   cursor = new lmdb.Cursor(txn, dbi,{ keyIsBuffer: true });
            if(cursor.goToRange(key)){
                for (var found = (cursor.goToRange(key) === key); found !== null; found = cursor.goToNextDup()) {
                    cursor.getCurrentBinary((key,value)=>{
    
                        count = count +1 
                    })} 
                }
                console.log("COUNTER IS ==========>",count)
            txn.commit()
            return count
        } catch (error) {
            console.log("ERROR :",error)
            return false
        }

    }




    /**
     * @description Deletes all values at key in db.
            Returns True If key exists in db Else False
     * @param {*} db 
     * @param {*} key 
     */

    delVals(db, key) {
       
        try {
           

            let dbi = this.env.openDbi({
                name: db,
                dupSort: true
            })
            let txn = this.env.beginTxn();
           
            console.log("DELVAL------------------")
            txn.del(dbi, key);
         
            txn.commit()
            return true
        } catch (error) {
            console.log('DELVAL ERROR: ',error)
            return false
        }

    }


    /**
     * @description       Add val bytes as dup to key in db
            Adds to existing values at key if any
            Returns True if written else False if dup val already exists
    
            Duplicates are inserted in lexocographic order not insertion order.
            Lmdb does not insert a duplicate unless it is a unique value for that
            key.
    
            Does inclusion test to dectect of duplicate already exists
            Uses a python set for the duplicate inclusion test. Set inclusion scales
            with O(1) whereas list inclusion scales with O(n).
    
    
    
     */

    addVal(db, key, val) {


        let dups = this.getVals(db, key)

                let dbi = this.env.openDbi({
                    name: db,
                     create: true, // will create if database did not exist
                    dupSort: true
                })
        try {
            let txn = this.env.beginTxn();
           if (!dups.includes(val)) {
                console.log("VALUE INSIDE DUPE DOSTnt exist =========>")
               
                txn.putBinary(dbi, key, Buffer.from(val, 'binary'),{overwrite:false,keyIsBuffer: true})     
            }
            txn.commit()
            return true
        } catch (error) {
            console.log("ERROR =================> :",error)
            return false
        }
    }


    /**
     * @description Return list of values associated with a key in db (in insertion order)
     * returns empty  if there is no key . Duplicates are retrieved in insertion order.
     * lmdb is lexocographic an insertion ordering value is prepended to
           all values that makes lexocographic order that same as insertion order
            Duplicates are ordered as a pair of key plus value so prepending prefix
           to each value changes duplicate ordering. Prefix is 7 characters long.
           With 6 character hex string followed by '.' for a max
           of 2**24 = 16,777,216 duplicates,
     * 
     */





    getIOValues(db, key) {

        try {

            let dbi = this.env.openDbi({
                name: db,
                create: true, // will create if database did not exist
                dupSort: true
            })

            let txn = this.env.beginTxn();
            let cursor = new lmdb.Cursor(txn, dbi,{ keyIsBuffer: true });
            let vals = []

                   if(cursor.goToRange(key)){
                    for (var found = (cursor.goToRange(key) === key); found !== null; found = cursor.goToNextDup()) {
                        cursor.getCurrentBinary(function(key, data) {
                         data =  data.slice(7,data.length)
                            console.log("value is ------->",key,data.toString())
                            vals.push(data)
                        }) }
                   }
                    

                txn.commit()
            console.log("vals --------------__>", vals)
            return vals
        } catch (error) {
            console.log("getIOValues ERROR :",error)
            return false
        }

    }






    /**
     * @description Add val bytes as dup in insertion order to key in db
            Adds to existing values at key if any
            Returns True if written else False if val is already a dup
    
            Duplicates preserve insertion order.
     * @param {*} db        db is opened named sub db with dupsort=False
     * @param {*} key       key is bytes of key within sub db's keyspace
     * @param {*} val       val is bytes of value to be written
     */
    addIOVal(db, key, vals) {

        let dups = this.getIOValues(db, key) //
        console.log("values are  ------------------->",dups)
        //dups.add()
    
        try {

            let dbi = this.env.openDbi({
                name: db,
                // create: true, // will create if database did not exist
                dupSort: true
            })
            
            let txn = this.env.beginTxn();
            let cursor = new lmdb.Cursor(txn, dbi,{ keyIsBuffer: true });
            let count = 0
            let result = false
            let   val = null
            let count_pad = 0
            if(cursor.goToRange(key)){
                
             for (var found = cursor.goToFirst(); found !== null; found = cursor.goToNext()) {
                    count = count + 1
}
               }
               console.log("vals ------------>",vals)
                for(let i = 0 ; i < vals.length ; i++){
                        console.log("vals[i] ===========>",vals[i])
                    if (!dups.includes(vals[i])) {
                        if (count > MaxForks) { `Too many recovery forks at key = ${key}` }

                        console.log("inside for loop")
                        count_pad = pad(count,6)
                        count_pad =   count_pad + '.'
                        console.log("val-------->",vals[i])
                        console.log("Buffer.from(count, 'binary') --------------->",Buffer.from(count_pad, 'binary'),vals[i])
                        val = Buffer.concat([Buffer.from(count_pad, 'binary') , vals[i]])
                       console.log("val ===============>",val.toString())
                        result = true
                        txn.putBinary(dbi,key, val,{ keyIsBuffer: true })

                        count += 1
                        console.log("count is -------------->",count)
                    }

                }
                   
            txn.commit()
            return true
        } catch (error) {
            console.log("PUTIOVAL ERROR:",error)
            return false
        }



    }








    /**
     * * @description Write each entry from list of bytes vals to key in db in insertion order
            Adds to existing values at key if any
            Returns True If at least one of vals is added as dup, False otherwise
    
            Duplicates preserve insertion order.
            Because lmdb is lexocographic an insertion ordering value is prepended to
            all values that makes lexocographic order that same as insertion order
            Duplicates are ordered as a pair of key plus value so prepending prefix
            to each value changes duplicate ordering. Prefix is 7 characters long.
            With 6 character hex string followed by '.' for a max
            of 2**24 = 16,777,216 duplicates. With prepended ordinal must explicity
            check for duplicate values before insertion. Uses a python set for the
            duplicate inclusion test. Set inclusion scales with O(1) whereas list
            inclusion scales with O(n).
     * @param {*} db   db is opened named sub db with dupsort=False
     * @param {*} key key is bytes of key within sub db's keyspace
     * @param {*} val val is bytes of value to be written
     */
    putIOVals(db, key, vals) {
        let dups = new Set(this.getIOValues(db, key))   //
        console.log("dups ------------------->",dups)
        //dups.add()
    
        try {

            let dbi = this.env.openDbi({
                name: db,
                // create: true, // will create if database did not exist
                dupSort: true
            })
            
            let txn = this.env.beginTxn();
            let cursor = new lmdb.Cursor(txn, dbi,{ keyIsBuffer: true });
            let count = 0
            let result = false
            let   val = null
            let count_pad = 0
            if(cursor.goToRange(key)){
                
             for (var found = cursor.goToFirst(); found !== null; found = cursor.goToNext()) {
                    count = count + 1
}
               }
               console.log("vals ------------>",vals)
                for(let i = 0 ; i < vals.length ; i++){
                        console.log("vals[i] ===========>",vals[i])
                    if (!dups.has(vals[i])) {
                        if (count > MaxForks) { `Too many recovery forks at key = ${key}` }

                        console.log("inside for loop")
                        count_pad = pad(count,6)
                        count_pad =   count_pad + '.'
                        console.log("val-------->",vals[i])
                        console.log("Buffer.from(count, 'binary') --------------->",Buffer.from(count_pad, 'binary'),vals[i])
                        val = Buffer.concat([Buffer.from(count_pad, 'binary') , vals[i]])
                       console.log("val ===============>",val.toString())
                        result = true
                        txn.putBinary(dbi,key, val,{ keyIsBuffer: true })

                        count += 1
                        console.log("count is -------------->",count)
                    }

                }
                   
            txn.commit()
            return true
        } catch (error) {
            console.log("PUTIOVAL ERROR:",error)
            return false
        }



    }








    /**
     * @description Return last added dup value at key in db in insertion order
            Returns None no entry at key
    
            Duplicates are retrieved in insertion order.
            Because lmdb is lexocographic an insertion ordering value is prepended to
            all values that makes lexocographic order that same as insertion order
            Duplicates are ordered as a pair of key plus value so prepending prefix
            to each value changes duplicate ordering. Prefix is 7 characters long.
            With 6 character hex string followed by '.' for a max
            of 2**24 = 16,777,216 duplicates,
     * @param {*} db db is opened named sub db with dupsort=True
     * @param {*} key key is bytes of key within sub db's keyspace
     */
    getIOValsLast(db, key) {

        let dbi = this.env.openDbi({
            name: db,
            // create: true, // will create if database did not exist
            dupSort: true
        })
        try {
            let txn = this.env.beginTxn();
            let cursor = new lmdb.Cursor(txn, dbi,{ keyIsBuffer: true });
            let vals = null
            
            if(cursor.goToRange(key)){
                
               
                cursor.goToLastDup()
                cursor.getCurrentBinary(function(key, data) {
                            // do something with data
                            console.log("value is ------->",key,data.toString())
                           vals = data.slice(7,data.length)
                        })
                // for (var found = (cursor.goToRange(key) === key); found !== null; found = cursor.goToNextDup()) {
                //     cursor.getCurrentBinary(function(key, data) {
                //         // do something with data
                //         console.log("value is ------->",key,value.toString())
                //         vals.push(value)
                //     }) }
               }
                

            txn.commit()
            return vals
        }

        catch (error) {
            console.log("getIOValsLast ERROR :",getIOValsLast)
            return false
        }

    }


    /**
     * @description Return count of dup values at key in db, or zero otherwise
     * @param {*} db db is opened named sub db with dupsort=True
     * @param {*} key key is bytes of key within sub db's keyspace
     */
    cntIoVals(db, key) {
        try {

            let dbi = this.env.openDbi({
                name: db,
                create: true, // will create if database did not exist
                dupSort: true
            })

            let txn = this.env.beginTxn();
            let cursor = new lmdb.Cursor(txn, dbi,{ keyIsBuffer: true });
            let count = 0


            if(cursor.goToRange(key)){
                for (var found = (cursor.goToRange(key) === key); found !== null; found = cursor.goToNextDup()) {
                    cursor.getCurrentBinary(function(key, data) {
                        count = count + 1
                    }) }
               }
               else {
                   return count
               }
               console.log("counter ======>",count)
               txn.commit()
            return count
        } catch (error) {
            console.log("ERROR :",error)
            return false
        }
    }


    delIoVals(db, key) {
//cursor.del();
        try {

            let dbi = this.env.openDbi({
                name: db,
            })

            let txn = this.env.beginTxn();
            let cursor = new lmdb.Cursor(txn, dbi,{ keyIsBuffer: true });

            txn.del(dbi,key)
            console.log("deleted Successfully")
            txn.commit()
            return true
        } catch (error) {
            return false
        }
    }



    /**
     * @description  Returns iterator of all dup vals in insertion order for all entries
            with same prefix across all sequence numbers in order without gaps
            starting with zero. Stops if gap or different pre.
            Assumes that key is combination of prefix and sequence number given
            by .snKey().
    
            Raises StopIteration Error when empty.
    
            Duplicates are retrieved in insertion order.
            Because lmdb is lexocographic an insertion ordering value is prepended to
            all values that makes lexocographic order that same as insertion order
            Duplicates are ordered as a pair of key plus value so prepending prefix
            to each value changes duplicate ordering. Prefix is 7 characters long.
            With 6 character hex string followed by '.' for a max
            of 2**24 = 16,777,216 duplicates,
    
     * @param {*} db     db is opened named sub db with dupsort=True
     * @param {*} pre   pre is bytes of itdentifier prefix prepended to sn in key
                    within sub db's keyspace
     */
    *getIoValsAllPreIter(db, pre) {


        try {

            let key = snkey(pre, 0)
            let txn = this.env.beginTxn();
            let cursor = new lmdb.Cursor(txn, dbi,{ keyIsBuffer: true });
            let count = 0
            let result = false


            
            if (cursor.goToRange(key) === key) {
                do {
                    cursor.getCurrentNumber(function (key, data) {
                        result = data.slice(7, data.length)

                    });

                    yield result
                    key = snkey(pre, cnt + 1)
                } while (cursor.goToNextDup());
            }


        }

        // if (cursor.goToRange(key) === key) {


        //     // for (val in cursor.goToNextDup() )
        //     // yield val
        //     do {
        //         cursor.getCurrentNumber(function(key, data) {
        //           response = data
        //         });
        //         yield responses
        //     } while (cursor.goToNextDup());
        // }
        catch (error) {
            return false
        }


    }



    /**
     * @description  Returns iterator of last only dup vals in insertion order for all entries
            with same prefix across all sequence numbers in order without gaps
            starting with zero. Stops if gap or different pre.
            Assumes that key is combination of prefix and sequence number given
            by .snKey().
    
            Raises StopIteration Error when empty.
    
            Duplicates are retrieved in insertion order.
            Because lmdb is lexocographic an insertion ordering value is prepended to
            all values that makes lexocographic order that same as insertion order
            Duplicates are ordered as a pair of key plus value so prepending prefix
            to each value changes duplicate ordering. Prefix is 7 characters long.
            With 6 character hex string followed by '.' for a max
            of 2**24 = 16,777,216 duplicates,
     * @param {*} db  db is opened named sub db with dupsort=True
     * @param {*} pre   pre is bytes of itdentifier prefix prepended to sn in key
                    within sub db's keyspace
     */

    *getIoValsLastAllPreIter(dbi, pre) {


        try {

            let key = snkey(pre, 0)
            let txn = this.env.beginTxn();
            let cursor = new lmdb.Cursor(txn, dbi);
            let result = false

            if (cursor.goToRange(key) === key) {
                do {

                    cursor.goToLast();
                    cursor.getCurrentString(function (key, data) {
                        result = data.slice(7, data.length)
                    });
                    // cursor.getCurrentNumber(function(key, data) {
                    //     result =  data.slice(7,data.length)
                    // });
                    yield result
                    key = snKey(pre, cnt + 1)
                } while (cursor.goToNextDup());
            }

            // do {
            //     cursor.goToLastDup(function(key, data) {
            //         yield data.slice(7,data.length)


            //     });
            //     key = snKey(pre,cnt + 1)
            // } while (cursor.goToRange(key) === key);

        }

        catch (error) {
            return false
        }

    }
}







function resolveHome(filepath) {
    if (filepath[0] === '~') {
        return path.join(process.env.HOME, filepath.slice(1));
    }
    return filepath;
}

function dgkey(pre, dig) {

    if (pre)
        pre = Buffer.from(pre,'binary')
    if (dig)
        dig =   Buffer.from(dig,'binary')

let dot_buf =  Buffer.from('.','binary')
    return Buffer.concat([pre,dot_buf,dig])
}



/**
 * @description  Returns bytes db key  from concatenation of qualified Base64 prefix
    bytes pre and int sn (sequence number) of event
 * @param {*} pre 
 * @param {*} sn 
 */
function snkey(pre, sn) {

    if (pre)
        pre = encodeURIComponent(pre)
    pre = Buffer.from(pre, 'binary')
    sn = pad(sn, 32)
    sn = '.' + sn
    sn = Buffer.from(sn, 'binary')
    let arr = [pre, sn]
    return Buffer.concat(arr)
}


/**
 * @description  Wrapper to enable temporary (test) Databaser instances
    When used in with statement calls .clearDirPath() on exit of with block
 * @param {} name name is str name of temporary Databaser dirPath  extended name so
                 can have multiple temporary databasers is use differen name
 * @param {*} cls cls is Class instance of subclass instance
 */
function* openDatabaser(name = "test", cls = null) {
    let databaser = null
    if (!cls) {
        cls = new Databaser(null, name, true)
    }

    try {
        // databaser = cls
        console.log("Inside try =================>", cls)
        yield cls
    } catch (error) {
        throw error
    }
    // finally {
    //     console.log("databaser ============>", databaser)
    //     databaser.clearDirPath()
    // }

}


function openLogger(name = "test") {
    return openDatabaser(name, new Logger)

}


/**
 * @description  Logger sets up named sub databases with Keri Event Logs within main database
 * 
 *  Attributes:
        see superclass Databaser for inherited attributes

        .evts is named sub DB whose values are serialized events
            dgKey
            DB is keyed by identifer prefix plus digest of serialized event
            Only one value per DB key is allowed

        .dtss is named sub DB of datetime stamp strings in ISO 8601 format of
            dgKey
            the datetime when the event was first seen by log.
            Used for escrows timeouts and extended validation.
            DB is keyed by identifer prefix plus digest of serialized event

        .sigs is named sub DB of fully qualified event signatures
            dgKey
            DB is keyed by identifer prefix plus digest of serialized event
            More than one value per DB key is allowed

        .rcts is named sub DB of event receipt couplets from nontransferable
            signers. Each couplet is concatenation of fully qualified
            non-transferale prefix plus fully qualified event signature
            by witness, watcher, or validator.
            dgKey
            SB is keyed by identifer prefix plus digest of serialized event
            More than one value per DB key is allowed

        .ures is named sub DB of unverified event receipt escrowed couplets from
            non-transferable signers. Each couplet is concatenation of fully
            qualified non-transferable identfier prefix plus fully qualified
            event signature by witness, watcher, or validator
            dgKey
            SB is keyed by controller prefix plus digest
            of serialized event
            More than one value per DB key is allowed

        .vrcs is named sub DB of event validator receipt triplets from transferable
            signers. Each triplet is concatenation of  three fully qualified items
            of validator. These are transferable prefix, plus latest establishment
            event digest, plus event signature.
            When latest establishment event is multisig then there will
            be multiple triplets one per signing key, each a dup at same db key.
            dgKey
            SB is keyed by identifer prefix plus digest of serialized event
            More than one value per DB key is allowed

        .vres is named sub DB of unverified event validator receipt escrowed
            triplets from transferable signers. Each triplet is concatenation of
            three fully qualified items of validator. These are transferable
            prefix, plus latest establishment event digest, plus event signature.
            When latest establishment event is multisig then there will
            be multiple triplets one per signing key, each a dup at same db key.
            dgKey
            SB is keyed by identifer prefix plus digest of serialized event
            More than one value per DB key is allowed

        .kels is named sub DB of key event log tables that map sequence numbers
            to serialized event digests.
            snKey
            Values are digests used to lookup event in .evts sub DB
            DB is keyed by identifer prefix plus sequence number of key event
            More than one value per DB key is allowed

        .pses is named sub DB of partially signed escrowed event tables
            that map sequence numbers to serialized event digests.
            snKey
            Values are digests used to lookup event in .evts sub DB
            DB is keyed by identifer prefix plus sequence number of key event
            More than one value per DB key is allowed

        .ooes is named sub DB of out of order escrowed event tables
            that map sequence numbers to serialized event digests.
            snKey
            Values are digests used to lookup event in .evts sub DB
            DB is keyed by identifer prefix plus sequence number of key event
            More than one value per DB key is allowed

        .dels is named sub DB of deplicitous event log tables that map sequence numbers
            to serialized event digests.
            snKey
            Values are digests used to lookup event in .evts sub DB
            DB is keyed by identifer prefix plus sequence number of key event
            More than one value per DB key is allowed

        .ldes is named sub DB of likely deplicitous escrowed event tables
            that map sequence numbers to serialized event digests.
            snKey
            Values are digests used to lookup event in .evts sub DB
            DB is keyed by identifer prefix plus sequence number of key event
            More than one value per DB key is allowed
 */

class Logger extends Databaser {


    constructor() {

        super(null, 'main',false)
        // this.evts = this.env.openDbi({ name: Buffer.from('evts.', 'binary'), create: true })
        // this.dtss = this.env.openDbi({ name: Buffer.from('dtss.', 'binary'), create: true, dupSort: true })
        // this.sigs = this.env.openDbi({ name: Buffer.from('sigs.', 'binary'), create: true, dupSort: true })
        // this.rcts = this.env.openDbi({ name: Buffer.from('rcts.', 'binary'), create: true, dupSort: true })
        // this.ures = this.env.openDbi({ name: Buffer.from('ures.', 'binary'), create: true, dupSort: true })
        // this.vrcs = this.env.openDbi({ name: Buffer.from('vrcs.', 'binary'), create: true, dupSort: true })
        // this.vres = this.env.openDbi({ name: Buffer.from('vres.', 'binary'), create: true, dupSort: true })
        // this.kels = this.env.openDbi({ name: Buffer.from('kels.', 'binary'), create: true, dupSort: true })
        // this.pses = this.env.openDbi({ name: Buffer.from('pses.', 'binary'), create: true, dupSort: true })
        // this.ooes = this.env.openDbi({ name: Buffer.from('ooes.', 'binary'), create: true, dupSort: true })
        // this.dels = this.env.openDbi({ name: Buffer.from('dels.', 'binary'), create: true, dupSort: true })
        // this.ldes = this.env.openDbi({ name: Buffer.from('ldes.', 'binary'), create: true, dupSort: true })
    }


    /**
     * @description  Use dgKey()
            Write serialized event bytes val to key
            Does not overwrite existing val if any
            Returns True If val successfully written Else False
            Return False if key already exists
     * @param {*} key 
     * @param {*} val 
     */
    putEvt(key, val) {
        return this.putVal(Buffer.from('evts.', 'binary'), key, val)
    }


    /**
     * @description  Use dgKey()
            Write serialized event bytes val to key
            Overwrites existing val if any
            Returns True If val successfully written Else False
     * @param {} key 
     * @param {*} val 
     */
    setEvt(key, val) {
        return this.setVal(Buffer.from('evts.', 'binary'), key, val)
    }



    /**
     * @description  Use dgKey()
            Write serialized event bytes val to key
            Overwrites existing val if any
            Returns True If val successfully written Else False
     * @param {} key 
     * @param {*} val 
     */
    getEvt(key, val) {
        return Buffer.from(this.getVal(Buffer.from('evts.', 'binary'), key, val),'binary')
    }


        /**
     * @description  Use dgKey()
            Deletes value at key.
            Returns True If key exists in database Else False
     * @param {*} key 
     */
    delEvt(key) {
        return this.delVal(Buffer.from('evts.', 'binary'), key)
    }



    /**
     *    Use dgKey()
            Write serialized event datetime stamp val to key
            Does not overwrite existing val if any
            Returns True If val successfully written Else False
            Returns False if key already exists
     * @param {*} key 
     * @param {*} val 
     */

    putDts(key, val) {

        return this.putVal(Buffer.from('dtss.', 'binary'), key, val)
    }



    /**
     * @description   Use dgKey()
            Write serialized event datetime stamp val to key
            Overwrites existing val if any
            Returns True If val successfully written Else False
     * @param {*} key 
     * @param {*} val 
     */
    setDts(key, val) {

        return this.setVal(Buffer.from('dtss.', 'binary'), key, val)
    }


    /**
     * @description  Use dgKey()
            Return datetime stamp at key
            Returns None if no entry at key
     * @param {*} key 
     */
    getDts(key) {
        return Buffer.from(this.getVal(Buffer.from('dtss.', 'binary'), key),'binary')
    }


    /**
     * @description  Use dgKey()
            Deletes value at key.
            Returns True If key exists in database Else False
     * @param {*} key 
     */
    delDts(key) {
        return this.delVal(Buffer.from('dtss.', 'binary'), key)
    }



    /**
     * @description   Use dgKey()
            Return list of signatures at key
            Returns empty list if no entry at key
            Duplicates are retrieved in lexocographic order not insertion order.
     * @param {*} key 
     */
    getSigs(key) {

        return this.getVals(Buffer.from('sigs.', 'binary'), key)

    }

    /**
     * @description Use dgKey()
            Return iterator of signatures at key
            Raises StopIteration Error when empty
            Duplicates are retrieved in lexocographic order not insertion order.
     * @param {*} key 
     */

    getSigsIter(key) {
        return this.getValsIter(Buffer.from('sigs.', 'binary'), key)
    }



    /**
     * @description Use dgKey()
            Write each entry from list of bytes signatures vals to key
            Adds to existing signatures at key if any
            Returns True If no error
            Apparently always returns True (is this how .put works with dupsort=True)
            Duplicates are inserted in lexocographic order not insertion order.
     * @param {*} key 
     * @param {*} vals 
     */

    putSigs(key, vals) {

        return this.putVals(Buffer.from('sigs.', 'binary'), key, vals)
    }

    /**
     * @description  Use dgKey()
            Return list of signatures at key
            Returns empty list if no entry at key
            Duplicates are retrieved in lexocographic order not insertion order.
     * @param {*} key 
     * @param {*} val 
     */
    addSig(key, val) {
        return this.addVal(Buffer.from('sigs.', 'binary'), key, val)

    }


    /**
     * @description   Use dgKey()
            Return list of signatures at key
            Returns empty list if no entry at key
            Duplicates are retrieved in lexocographic order not insertion order.
     * @param {*} key 
     */
    getSigs(key) {

        return this.getVals(Buffer.from('sigs.', 'binary'), key)
    }



    /**
     * @description   Use dgKey()
            Return count of signatures at key
            Returns zero if no entry at key
     * @param {*} key 
     */
    cntSigs(key) {
        return this.cntVals(Buffer.from('sigs.', 'binary'), key)
    }

    /**
     * @description  Use dgKey()
            Deletes all values at key.
            Returns True If key exists in database Else False
     * @param {*} key 
     */
    delSigs(key) {


        return this.delVals(Buffer.from('sigs.', 'binary'), key)
    }







    /**
     * @description  Use dgKey()
            Write each entry from list of bytes receipt couplets vals to key
            Adds to existing receipts at key if any
            Returns True If no error
            Apparently always returns True (is this how .put works with dupsort=True)
            Duplicates are inserted in lexocographic order not insertion order.
     * @param {*} key 
     * @param {*} vals 
     */

    putRcts(key, vals) {

        return this.putVals(Buffer.from('rcts.', 'binary'), key, vals)
    }

    /**
     * @description   Use dgKey()
            Add receipt couplet val bytes as dup to key in db
            Adds to existing values at key if any
            Returns True if written else False if dup val already exists
            Duplicates are inserted in lexocographic order not insertion order.
     * @param {*} key 
     * @param {*} val 
     */
    addRct(key, val) {
        return this.addVal(Buffer.from('rcts.', 'binary'), key, val)

    }


    /**
     * @description      Use dgKey()
            Return list of receipt couplets at key
            Returns empty list if no entry at key
            Duplicates are retrieved in lexocographic order not insertion order.
     * @param {*} key 
     */
    getRcts(key) {

        return this.getVals(Buffer.from('rcts.', 'binary'), key)
    }



    /**
     * @description    Use dgKey()
            Return count of receipt couplets at key
            Returns zero if no entry at key
     * @param {*} key 
     */
    cntRcts(key) {
        return this.cntVals(Buffer.from('rcts.', 'binary'), key)
    }

    /**
     * @description  Use dgKey()
            Deletes all values at key.
            Returns True If key exists in database Else False
     * @param {*} key 
     */
    delRcts(key) {


        return this.delVals(Buffer.from('rcts.', 'binary'), key)
    }


    /**
     * @description Use dgKey()
            Return iterator of signatures at key
            Raises StopIteration Error when empty
            Duplicates are retrieved in lexocographic order not insertion order.
     * @param {*} key 
     */

    getRctsIter(key) {
        return this.getValsIter(Buffer.from('rcts.', 'binary'), key)
    }







    /**
     * @description  Use dgKey()
            Write each entry from list of bytes receipt couplets vals to key
            Adds to existing receipts at key if any
            Returns True If no error
            Apparently always returns True (is this how .put works with dupsort=True)
            Duplicates are inserted in lexocographic order not insertion order.
     * @param {*} key 
     * @param {*} vals 
     */

    putUres(key, vals) {

        return this.putVals(Buffer.from('ures.', 'binary'), key, vals)
    }

    /**
     * @description   Use dgKey()
            Add receipt couplet val bytes as dup to key in db
            Adds to existing values at key if any
            Returns True if written else False if dup val already exists
            Duplicates are inserted in lexocographic order not insertion order.
     * @param {*} key 
     * @param {*} val 
     */
    addUre(key, val) {
        return this.addVal(Buffer.from('ures.', 'binary'), key, val)

    }


    /**
     * @description      Use dgKey()
            Return list of receipt couplets at key
            Returns empty list if no entry at key
            Duplicates are retrieved in lexocographic order not insertion order.
     * @param {*} key 
     */
    getUres(key) {

        return this.getVals(Buffer.from('ures.', 'binary'), key)
    }



    /**
     * @description    Use dgKey()
            Return count of receipt couplets at key
            Returns zero if no entry at key
     * @param {*} key 
     */
    cntUres(key) {
        return this.cntVals(Buffer.from('ures.', 'binary'), key)
    }

    /**
     * @description  Use dgKey()
            Deletes all values at key.
            Returns True If key exists in database Else False
     * @param {*} key 
     */
    delUres(key) {


        return this.delVals(Buffer.from('ures.', 'binary'), key)
    }


    /**
     * @description Use dgKey()
            Return iterator of signatures at key
            Raises StopIteration Error when empty
            Duplicates are retrieved in lexocographic order not insertion order.
     * @param {*} key 
     */

    getUresIter(key) {
        return this.getValsIter(Buffer.from('ures.', 'binary'), key)
    }
















    /**
     * @description  Use dgKey()
            Write each entry from list of bytes receipt couplets vals to key
            Adds to existing receipts at key if any
            Returns True If no error
            Apparently always returns True (is this how .put works with dupsort=True)
            Duplicates are inserted in lexocographic order not insertion order.
     * @param {*} key 
     * @param {*} vals 
     */

    putVrcs(key, vals) {

        return this.putVals(Buffer.from('vrcs.', 'binary'), key, vals)
    }

    /**
     * @description   Use dgKey()
            Add receipt couplet val bytes as dup to key in db
            Adds to existing values at key if any
            Returns True if written else False if dup val already exists
            Duplicates are inserted in lexocographic order not insertion order.
     * @param {*} key 
     * @param {*} val 
     */
    addVrc(key, val) {
        return this.addVal(Buffer.from('vrcs.', 'binary'), key, val)

    }


    /**
     * @description      Use dgKey()
            Return list of receipt couplets at key
            Returns empty list if no entry at key
            Duplicates are retrieved in lexocographic order not insertion order.
     * @param {*} key 
     */
    getVrcs(key) {

        return this.getVals(Buffer.from('vrcs.', 'binary'), key)
    }



    /**
     * @description    Use dgKey()
            Return count of receipt couplets at key
            Returns zero if no entry at key
     * @param {*} key 
     */
    cntVrcs(key) {
        return this.cntVals(Buffer.from('vrcs.', 'binary'), key)
    }

    /**
     * @description  Use dgKey()
            Deletes all values at key.
            Returns True If key exists in database Else False
     * @param {*} key 
     */
    delVrcs(key) {


        return this.delVals(Buffer.from('vrcs.', 'binary'), key)
    }


    /**
     * @description Use dgKey()
            Return iterator of signatures at key
            Raises StopIteration Error when empty
            Duplicates are retrieved in lexocographic order not insertion order.
     * @param {*} key 
     */

    getVrcsIter(key) {
        return this.getValsIter(Buffer.from('vrcs.', 'binary'), key)
    }
















    /**
     * @description  Use dgKey()
            Write each entry from list of bytes receipt couplets vals to key
            Adds to existing receipts at key if any
            Returns True If no error
            Apparently always returns True (is this how .put works with dupsort=True)
            Duplicates are inserted in lexocographic order not insertion order.
     * @param {*} key 
     * @param {*} vals 
     */

    putVres(key, vals) {

        return this.putVals(Buffer.from('vres.', 'binary'), key, vals)
    }

    /**
     * @description   Use dgKey()
            Add receipt couplet val bytes as dup to key in db
            Adds to existing values at key if any
            Returns True if written else False if dup val already exists
            Duplicates are inserted in lexocographic order not insertion order.
     * @param {*} key 
     * @param {*} val 
     */
    addVre(key, val) {
        return this.addVal(Buffer.from('vres.', 'binary'), key, val)

    }


    /**
     * @description      Use dgKey()
            Return list of receipt couplets at key
            Returns empty list if no entry at key
            Duplicates are retrieved in lexocographic order not insertion order.
     * @param {*} key 
     */
    getVres(key) {

        return this.getVals(Buffer.from('vres.', 'binary'), key)
    }



    /**
     * @description    Use dgKey()
            Return count of receipt couplets at key
            Returns zero if no entry at key
     * @param {*} key 
     */
    cntVres(key) {
        return this.cntVals(Buffer.from('vres.', 'binary'), key)
    }

    /**
     * @description  Use dgKey()
            Deletes all values at key.
            Returns True If key exists in database Else False
     * @param {*} key 
     */
    delVres(key) {


        return this.delVals(Buffer.from('vres.', 'binary'), key)
    }


    /**
     * @description Use dgKey()
            Return iterator of signatures at key
            Raises StopIteration Error when empty
            Duplicates are retrieved in lexocographic order not insertion order.
     * @param {*} key 
     */

    getVresIter(key) {
        return this.getValsIter(Buffer.from('vres.', 'binary'), key)
    }










    /**
     * @description     Use snKey()
        Write each key event dig entry from list of bytes vals to key
        Adds to existing event indexes at key if any
        Returns True If at least one of vals is added as dup, False otherwise
        Duplicates are inserted in insertion order.
     * @param {*} key 
     * @param {*} vals 
     */

    putKes(key, vals) {
        return this.putIOVals(Buffer.from('kels.', 'binary'), key, vals)
    }


    /**
     * @description   Use snKey()
        Add key event val bytes as dup to key in db
        Adds to existing event indexes at key if any
        Returns True if written else False if dup val already exists
        Duplicates are inserted in insertion order.
     */
    addKe(key, val) {
        return this.addIOVal(Buffer.from('kels.', 'binary'), key, val)

    }


    /**
     * @description  Use snKey()
        Return list of key event dig vals at key
        Returns empty list if no entry at key
        Duplicates are retrieved in insertion order.
     * @param {*} key 
     */
    getKes(key) {
        return this.getIOValues(Buffer.from('kels.', 'binary'), key)

    }


    /**
     * @description  Use snKey()
       Return last inserted dup key event dig vals at key
       Returns None if no entry at key
       Duplicates are retrieved in insertion order.
     */
    getKeLast(key) {
        return this.getIOValsLast(Buffer.from('kels.', 'binary'), key)
    }



    /**
     * @description   Use snKey()
        Return count of dup key event dig val at key
        Returns zero if no entry at key
     * @param {*} key 
     */
    cntKes(key) { return this.cntIoVals(Buffer.from('kels.', 'binary'), key) }



    /**
     * @description  Use snKey()
       Deletes all values at key.
       Returns True If key exists in database Else False
     * @param {*} key 
     */
    delKes(key) { return this.delIoVals(Buffer.from('kels.', 'binary'), key) }



    /**
     * @description   Returns iterator of all dup vals in insertion order for all entries
        with same prefix across all sequence numbers without gaps. Stops if
        encounters gap.
        Assumes that key is combination of prefix and sequence number given
        by .snKey().
    
        Raises StopIteration Error when empty.
        Duplicates are retrieved in insertion order.
    
        Parameters:
            db is opened named sub db with dupsort=True
            pre is bytes of itdentifier prefix prepended to sn in key
                within sub db's keyspace
     * @param {*} pre 
     */

    getKelIter(pre) {
        if (pre) {
            pre = encodeURIComponent(pre)
        }
        return this.getIoValsAllPreIter(Buffer.from('kels.', 'binary'), pre)
    }


    /**
     * @description    Returns iterator of last dup vals in insertion order for all entries
        with same prefix across all sequence numbers without gaps. Stops if
        encounters gap.
        Assumes that key is combination of prefix and sequence number given
        by .snKey().
    
        Raises StopIteration Error when empty.
        Duplicates are retrieved in insertion order.
    
    
     * @param {*} pre is bytes of itdentifier prefix prepended to sn in key
                within sub db's keyspace
     */
    getKelEstIter(pre) {

        if (pre) {
            pre = encodeURIComponent(pre)
        }
        return this.getIoValsLastAllPreIter(Buffer.from('kels.', 'binary'), pre)
    }




















    /**
     * @description  Use snKey()
     Write each partial signed escrow event entry from list of bytes dig vals to key
     Adds to existing event indexes at key if any
     Returns True If at least one of vals is added as dup, False otherwise
     Duplicates are inserted in insertion order.
     * @param {*} key 
     * @param {*} vals 
     */

    putPses(key, vals) {
        return this.putIOVals(Buffer.from('pses.', 'binary'), key, vals)
    }




    /**
     * @description  Use snKey()
   Add Partial signed escrow val bytes as dup to key in db
   Adds to existing event indexes at key if any
   Returns True if written else False if dup val already exists
   Duplicates are inserted in insertion order.
     * @param {*} key 
     * @param {*} val 
     */
    addPse(key, val) {
        return this.addIOVal(Buffer.from('pses.', 'binary'), key, val)
    }



    /**
     * @description  Use snKey()
    Return list of partial signed escrowed event dig vals at key
    Returns empty list if no entry at key
    Duplicates are retrieved in insertion order.
     * @param {*} key 
     */
    getPses(key) {
        return this.getIOValues(Buffer.from('pses.', 'binary'), key)
    }



    /**
     * @description  Use snKey()
     Return last inserted dup partial signed escrowed event dig val at key
     Returns None if no entry at key
     Duplicates are retrieved in insertion order.
     */
    getPsesLast(key) {
        return this.getIOValsLast(Buffer.from('pses.', 'binary'), key)
    }


    /**
     * @description  Use snKey()
     Return count of dup event dig vals at key
     Returns zero if no entry at key
     * @param {*} key 
     */
    cntPses(key) {
        return this.cntIoVals(Buffer.from('pses.', 'binary'), key)
    }




    /**
     * @description  Use snKey()
     Deletes all values at key.
     Returns True If key exists in database Else False
     * @param {*} key 
     */
    delPses(key) {
        return this.delIoVals(Buffer.from('pses.', 'binary'), key)
    }


    /**
     * @description  Use snKey()
     Write each out of order escrow event dig entry from list of bytes vals to key
     Adds to existing event indexes at key if any
     Returns True If at least one of vals is added as dup, False otherwise
     Duplicates are inserted in insertion order.
     * @param {} key 
     * @param {*} vals 
     */
    putOoes(key, vals) { return this.putIOVals(Buffer.from('ooes.', 'binary'), key, vals) }


    /**
     * @description  Use snKey()
     Add out of order escrow val bytes as dup to key in db
     Adds to existing event indexes at key if any
     Returns True if written else False if dup val already exists
     Duplicates are inserted in insertion order.
     * @param {*} key 
     * @param {*} val 
     */
    addOoe(key, val) {
        return this.addIOVal(Buffer.from('ooes.', 'binary'), key, val)
    }



    /**
     * @description  Use snKey()
    Return list of out of order escrow event dig vals at key
    Returns empty list if no entry at key
    Duplicates are retrieved in insertion order.
     * @param {*} key 
     */
    getOoes(key) { return this.getIOValues(Buffer.from('ooes.', 'binary'), key) }




    /**
     * @description  Use snKey()
     Return last inserted dup out of order escrow event dig at key
     Returns None if no entry at key
     Duplicates are retrieved in insertion order.
     
     * @param {*} key 
     */
    getOoesLast(key) {

        return this.getIOValsLast(Buffer.from('ooes.', 'binary'), key)
    }


    /**
     * @description  Use snKey()
     Return count of dup event dig at key
     Returns zero if no entry at key
     * @param {*} key 
     */

    cntOoes(key) {
        return this.cntIoVals(Buffer.from('ooes.', 'binary'), key)
    }


    /**
     * @description  Use snKey()
     Deletes all values at key.
     Returns True If key exists in database Else False
     * @param {*} key 
     */
    delOoes(key) {

        return this.delIoVals(Buffer.from('ooes.', 'binary'), key)
    }



    /**
     * @description  Use snKey()
     Write each duplicitous event entry dig from list of bytes vals to key
     Adds to existing event indexes at key if any
     Returns True If at least one of vals is added as dup, False otherwise
     Duplicates are inserted in insertion order.
     * @param {*} key 
     * @param {*} vals 
     */
    putDes(key, vals) { return this.putIOVals(Buffer.from('dels.', 'binary'), key, vals) }



    /**
     * @description  Use snKey()
     Add duplicate event index val bytes as dup to key in db
     Adds to existing event indexes at key if any
     Returns True if written else False if dup val already exists
     Duplicates are inserted in insertion order.
     * @param {*} key 
     * @param {*} val 
     */
    addDe(key, val) {
        return this.addIOVal(Buffer.from('dels.', 'binary'), key, val)
    }


    /**
     * @description  """
    Use snKey()
    Return list of duplicitous event dig vals at key
    Returns empty list if no entry at key
    Duplicates are retrieved in insertion order.
    """
     * @param {*} self 
     * @param {*} key 
     */
    getDes(self, key) {
        return this.getIOValues(Buffer.from('dels.', 'binary'), key)
    }

    /**
     * @description  Use snKey()
     Return last inserted dup duplicitous event dig vals at key
     Returns None if no entry at key
    
     Duplicates are retrieved in insertion order.
     * @param {*} self 
     * @param {*} key 
     */
    getDesLast(key) {
        return this.getIOValsLast(Buffer.from('dels.', 'binary'), key)
    }


    /**
     * @description     Use snKey()
        Return count of dup event dig vals at key
        Returns zero if no entry at key
     * @param {*} key 
     */
    cntDes(key) {

        return this.cntIoVals(Buffer.from('dels.', 'binary'), key)
    }



    /**
     * @description  """
     Use snKey()
     Deletes all values at key.
     Returns True If key exists in database Else False
     """
     * @param {*} key 
     */
    delDes(key) { return this.delIoVals(Buffer.from('dels.', 'binary'), key) }


    /**
     * @description Returns iterator of all dup vals  in insertion order for any entries
     with same prefix across all sequence numbers including gaps.
     Assumes that key is combination of prefix and sequence number given
     by .snKey().
    
     Raises StopIteration Error when empty.
     Duplicates are retrieved in insertion order.
     * @param {*} pre      pre is bytes of itdentifier prefix prepended to sn in key
             within sub db's keyspace
     */
    getDelIter(pre) {
        if (pre)
            pre = encodeURIComponent(pre)
        return this.getIoValsAnyPreIter(Buffer.from('dels.', 'binary'), pre)
    }





    /**
     * @description  Use snKey()
     Write each likely duplicitous event entry dig from list of bytes vals to key
     Adds to existing event indexes at key if any
     Returns True If at least one of vals is added as dup, False otherwise
     Duplicates are inserted in insertion order.
     * @param {*} key 
     * @param {*} vals 
     */
    putLdes(key, vals) {
        return this.putIOVals(Buffer.from('ldes.', 'binary'), key, vals)
    }


    /**
     * @description  Use snKey()
     Add likely duplicitous escrow val bytes as dup to key in db
     Adds to existing event indexes at key if any
     Returns True if written else False if dup val already exists
     Duplicates are inserted in insertion order.
     * @param {*} key 
     * @param {*} val 
     */
    addLde(key, val) { return this.addIOVal(Buffer.from('ldes.', 'binary'), key, val) }






    /**
     * @description  Use snKey()
     Return list of likely duplicitous event dig vals at key
     Returns empty list if no entry at key
     Duplicates are retrieved in insertion order.
     * @param {*} key 
     */
    getLdes(key) { return this.getIOValues(Buffer.from('ldes.', 'binary'), key) }


    /**
     * @description  Use snKey()
    Return last inserted dup likely duplicitous event dig at key
    Returns None if no entry at key
    Duplicates are retrieved in insertion order.
     * @param {*} key 
     */
    getLdesLast(key) {
        return this.getIOValsLast(Buffer.from('ldes.', 'binary'), key)
    }



    /**
     * @description  Use snKey()
     Return count of dup event dig at key
     Returns zero if no entry at key
     * @param {*} self 
     * @param {*} key 
     */
    cntLdes(key) {

        return this.cntIoVals(Buffer.from('ldes.', 'binary'), key)
    }


    /**
     * @description  Use snKey()
    Deletes all values at key.
    Returns True If key exists in database Else False
     * @param {*} key 
     */
    delLdes(key) {

        return this.delIoVals(Buffer.from('ldes.', 'binary'), key)
    }



}
var Func = function(key, data) {
    console.log("---------->  key:", key);
    console.log("----------> data:", data);
}



module.exports = { snkey, dgkey, openDatabaser, openLogger, Logger, Databaser }



// vekh lena je thodi bhoti adjustment hoje, I will manage my schedule accordingly 