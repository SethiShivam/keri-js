
const fs = require('fs-extra')
const os = require('os');
const path = require('path');
const lmdb = require('lmdb-store');

class Database {

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
console.log("we are here ----------------->")
        let HeadDirPath = "/var"
        let TailDirPath = "keri/db"
        let AltHeadDirPath = path.join("~", '.keri/db')
        let AltTailDirPath = ".keri/db"
        // let ALT_DATABASE_DIR_PATH = 
        let MaxNamedDBs = 16


            if(temp){

            const tmpDir = os.tmpdir();
            const suffix = `/keri_lmdb_test`
            HeadDirPath = fs.mkdtempSync(`${tmpDir}${suffix}`)
            this.path = path.join(HeadDirPath, name)
            console.log("Db path is ----------->",this.path)
            fs.mkdirSync(this.path)
            }
        if (!headDirPath)
        headDirPath = HeadDirPath + '/' + TailDirPath
        console.log("we are here ---------->")
  let  baseDirPath = path.resolve(resolveHome(headDirPath))
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
  let  keriDbDirPath = baseDirPath  // set global db directory path
  console.log("baseDirPath=============>",baseDirPath)
   this.db =  lmdb.open(keriDbDirPath  ,MaxNamedDBs )


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

clearDirPath(){

    if(this.db){
        try{
                this.db.close()
        }catch(err){
                {}
        }
            if(fs.pathExistsSync(this.path))
            fs.rmdirSync(this.path)

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
putVal(db,key,value){

   let db_instance =  this.db.openDB(db)

   if(db_instance.get(key) === null){
    db_instance.putSync(key, Buffer.from(JSON.stringify(value)))
    this.db.close()
   }else {
    this.db.close()  
    return "key already exist"}
}

updateVal(db,key,value){

    let db_instance =  this.db.openDB(db)
     db_instance.putSync(key, Buffer.from(JSON.stringify(value)))
     this.db.close()  
 }

 getVal(db,key){

    let db_instance =  this.db.openDB(db)
        let data = db_instance.get(key)
        this.db.close()  
        return data
 }

 removeVal(db,key){
    let db_instance =  this.db.openDB(db)
    db_instance.removeSync(key)
    this.db.close()  
    return 'Success'
 }

 
}







function resolveHome(filepath) {
    if (filepath[0] === '~') {
        return path.join(process.env.HOME, filepath.slice(1));
    }
    return filepath;
}

function dgkey(pre,dig){

if(pre)
pre = encodeURIComponent(pre)
if(dig)
dig = encodeURIComponent(dig)
return Buffer.concat(Buffer.from(pre,'binary'),Buffer.from(dig,'binary'))
}1
let db = new Database()