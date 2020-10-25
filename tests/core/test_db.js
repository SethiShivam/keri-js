
const assert = require('assert').strict;
const { snkey, dgkey, openDatabaser, openLogger, Logger, Databaser } = require('../../src/keri/db/database')
const { versify, Serials } = require('../../src/keri/core/core')
const lmdb = require('node-lmdb');
const os = require('os');
const path = require('path');
const { serialize } = require('v8');
const util = require('util');
const encoder = new util.TextEncoder('utf-8');


function test_opendatabaser() {


   // var db  = new Databaser()

   //     assert.deepStrictEqual(db , new Databaser())
   //     assert.equal(db.name,'main')
   //     assert.deepStrictEqual(db.environment,new lmdb.Env())
   //     ///home/shivam/.keri/db
   let pre = Buffer.from('BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc', 'binary')
   let dig = Buffer.from('EGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4', 'binary')
   //    let  sn = 3

   //    assert.deepStrictEqual(snkey(pre,sn),Buffer.from('BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc.00000000000000000000000000000003'))
   //    assert.deepStrictEqual(dgkey(pre,dig),Buffer.from('BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc.EGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4'))
   //    db.clearDirPath()
   //    assert.deepStrictEqual(path.exists(db.path),'')

   var dber_gen = openDatabaser('test', null,)
   var dber_val = dber_gen.next().value
   let dbi = Buffer.from('Test1', 'binary')

   // console.log("dber --------------------->",dber_val.env)
   let key = Buffer.from("omega4", 'binary')
   let val = Buffer.from("Abcd", 'binary')

   let vals = [Buffer.from('z', 'binary'), Buffer.from('m', 'binary'), Buffer.from('x', 'binary'), Buffer.from('a', 'binary')]
   //


   // var dbi = dber_val.env.openDbi({
   //    name: "mydb1",
   //    create : true
   // });





   // assert.equal(dber_val.getVal(dbi, key), null)
   // assert.equal(dber_val.delVal(dbi, key), false)
   //  assert.deepStrictEqual(dber_val.putVal(dbi, key, val), true)
   // assert.equal(dber_val.putVal(dbi, key, val), false)
   // assert.deepStrictEqual(dber_val.setVal(dbi, key, val), true)
   // assert.equal(dber_val.getVal(dbi, key), val.toString())
   // assert.equal(dber_val.delVal(dbi, key), true)
   // assert.equal(dber_val.getVal(dbi, key), null)


   // assert.deepStrictEqual(dber_val.getVals(dbi, key) , []) 
   // assert.deepStrictEqual(dber_val.delVals(dbi, key) , false) 
   // assert.deepStrictEqual(dber_val.cntVals(dbi, key) , 0) 


   // console.log("dber_val.getVals(db, key) -====================>",dber_val.getVals(db, key))
   //  assert.deepStrictEqual(dber_val.putVals(dbi, key, vals) , true) //[Buffer.from('a','binary'),Buffer.from('m','binary'),Buffer.from('x','binary'),Buffer.from('z','binary')]
   //   assert.deepStrictEqual(dber_val.getVals(dbi, key) ,[Buffer.from('a','binary'),Buffer.from('m','binary'),Buffer.from('x','binary'),Buffer.from('z','binary') ])

   //    assert.deepStrictEqual(dber_val.cntVals(dbi, key) , 4) 
   //    assert.deepStrictEqual(dber_val.putVals(dbi, key, vals=[Buffer.from('a','binary')]) , true) 
   //    assert.deepStrictEqual(dber_val.addVal(dbi, key, vals=[Buffer.from('b','binary')]) , true) 
   // assert.deepStrictEqual(dber_val.getVals(dbi, key) ,[Buffer.from('a','binary'),Buffer.from('b','binary'),
   // Buffer.from('m','binary'),Buffer.from('x','binary'),Buffer.from('z','binary') ])

   // assert.deepStrictEqual(dber_val.delVals(dbi, key) , true) 
   // assert.deepStrictEqual(dber_val.getVals(dbi, key) , false) 
   // ============= PENDING =============
   // assert [val for val in dber.getValsIter(db, key)] == [b'a', b'b', b'm', b'x', b'z']
   // ================ PENDING

   //   #     # test IoVals insertion order dup methods.  dup vals are insertion order
   //     #     key = b'A'
   //     #     vals = [b"z", b"m", b"x", b"a"]
   //     #     db = dber.env.open_db(key=b'peep.', dupsort=True)


   dbi = Buffer.from('peep.', 'binary')

   // console.log("dber --------------------->",dber_val.env)
   key = Buffer.from("A", 'binary')
   val = Buffer.from("Abcd", 'binary')

   //    //  assert.deepStrictEqual(dber_val.getIOValues(dbi, key) , []) 
   //    //  assert.deepStrictEqual(dber_val.getIOValsLast(dbi, key) , null) 
   //    //  assert.deepStrictEqual(dber_val.cntIoVals(dbi, key) , 0) 
   //    //  assert.deepStrictEqual(dber_val.delIoVals(dbi, key) , false) 
   //     assert.deepStrictEqual(dber_val.putIOVals(dbi, key,vals) , true) 
   //     assert.deepStrictEqual(dber_val.getIOValues(dbi, key) , vals)  //# preserved insertion order
   //     assert.deepStrictEqual(dber_val.cntIoVals(dbi, key) , 4) 
   //     assert.deepStrictEqual(dber_val.getIOValsLast(dbi, key) , vals[vals.length-1]) 
   //   //  assert.deepStrictEqual(dber_val.putIOVals(dbi, key,[Buffer.from('a','binary')]) , false)  //# duplicate this will work in one shot testing
   //     assert.deepStrictEqual(dber_val.getIOValues(dbi, key) , vals)
   //     assert.deepStrictEqual(dber_val.addIOVal(dbi, key,[Buffer.from('a','binary')]) , true)
   //    //  assert.deepStrictEqual(dber_val.addIOVal(dbi, key,[Buffer.from('b','binary')]) , false) this will work in one shot testin
   //    // assert.deepStrictEqual(dber_val.getIOValues(dbi, key) , vals)
   //    assert.deepStrictEqual(dber_val.delIoVals(dbi, key) , true)

   //    //  #     assert dber.delIoVals(db, key) == True




   //  #     # Test getIoValsAllPreIter(self, db, pre)

   let vals0 = [Buffer.from('gamma', 'binary'), Buffer.from('beta', 'binary')]
   sn = 0
   key = snkey(pre, sn)
   // assert.deepStrictEqual(dber_val.addIOVal(dbi, key, [Buffer.from('gamma', 'binary')]), true)
   // assert.deepStrictEqual(dber_val.addIOVal(dbi, key, [Buffer.from('beta', 'binary')]), true)


   let vals1 = [Buffer.from('mary', 'binary'), Buffer.from('peter', 'binary'), Buffer.from('john', 'binary'), Buffer.from('paul', 'binary')]
   sn += 1
   key = snkey(pre, sn)
   // assert.deepStrictEqual(dber_val.putIOVals(dbi, key, vals1), true)

   let vals2 = [Buffer.from('dog', 'binary'), Buffer.from('cat', 'binary'), Buffer.from('bird  ', 'binary')]
   sn += 1
   key = snkey(pre, sn)
   // assert.deepStrictEqual(dber_val.putIOVals(dbi, key, vals1), true)


   // *********************** THIS IS PENDING ********************************************
   //  #     vals = [bytes(val) for val in dber.getIoValsAllPreIter(db, pre)]
   //  #     allvals = vals0 + vals1 + vals2
   //  #     assert vals == allvals
   // *********************** THIS IS PENDING ********************************************


   //  #     # Test getIoValsLastAllPreIter(self, db, pre)

   pre = Buffer.from('B4ejWzwQPYGGwTmuupUhPx5_yZ-Wk1xEHHzq7K0gzhcc', 'binary')
   vals0 = [Buffer.from('gamma', 'binary'), Buffer.from('beta', 'binary')]
   sn = 0
   key = snkey(pre, sn)
   assert.deepStrictEqual(dber_val.addIOVal(dbi, key, [Buffer.from('gamma', 'binary')]), true)


   //  #     vals2 = [b"dog", b"cat", b"bird"]
   //  #     sn += 1
   //  #     key = snKey(pre, sn)
   //  #     assert dber.putIoVals(db, key, vals2) == True

   //  #     vals = [bytes(val) for val in dber.getIoValsLastAllPreIter(db, pre)]
   //  #     lastvals = [vals0[-1], vals1[-1], vals2[-1]]
   //  #     assert vals == lastvals

   //  #     # Test getIoValsAnyPreIter(self, db, pre)
   //  #     pre = b'BQPYGGwTmuupUhPx5_yZ-Wk1x4ejWzwEHHzq7K0gzhcc'
   //  #     vals0 = [b"gamma", b"beta"]
   //  #     sn = 1  # not start at zero
   //  #     key = snKey(pre, sn)
   //  #     assert dber.addIoVal(db, key, vals0[0]) == True
   //  #     assert dber.addIoVal(db, key, vals0[1]) == True

   //  #     vals1 = [b"mary", b"peter", b"john", b"paul"]
   //  #     sn += 1
   //  #     key = snKey(pre, sn)
   //  #     assert dber.putIoVals(db, key, vals1) == True

   //  #     vals2 = [b"dog", b"cat", b"bird"]
   //  #     sn += 2  # gap
   //  #     key = snKey(pre, sn)
   //  #     assert dber.putIoVals(db, key, vals2) == True

   //  #     vals = [bytes(val) for val in dber.getIoValsAnyPreIter(db, pre)]
   //  #     allvals = vals0 + vals1 + vals2
   //  #     assert vals == allvals


   //  # assert not os.path.exists(dber.path)


}

function test_logger() {

   var logger = openDatabaser(null, new Logger())

   let preb = Buffer.from('DWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc', 'binary')
   let vals = [Buffer.from('z', 'binary'), Buffer.from('m', 'binary'), Buffer.from('x', 'binary'), Buffer.from('a', 'binary')]
   let vals1 = [Buffer.from('a', 'binary'), Buffer.from('m', 'binary'), Buffer.from('x', 'binary'), Buffer.from('z', 'binary')]
   let vals2 = [Buffer.from('a', 'binary'), Buffer.from('b', 'binary'), Buffer.from('m', 'binary'), Buffer.from('x', 'binary'), Buffer.from('z', 'binary')]
   let digb = Buffer.from('EGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4', 'binary')
   let dot = Buffer.from('.', 'binary')
   let preb_digb = [preb, dot, digb]
   let sn = 3
   let vs = versify(null, Serials.json, 20)
   assert.equal(vs, 'KERI10JSON000014_')


   let ked = {
      vs: vs, pre: preb.toString('utf-8'),
      sn: sn.toString(16),
      ilk: "rot",
      dig: digb.toString('utf-8')
   }

   let skedb = Buffer.from(JSON.stringify(ked), 'binary')

   let sig0b = Buffer.from('AAz1KAV2z5IRqcFe4gPs9l3wsFKi1NsSZvBe8yQJmiu5AzJ91Timrykocna6Z_pQBl2gt59I_F6BsSwFbIOG1TDQ', 'binary')
   let sig1b = Buffer.from('AB_pQBl2gt59I_F6BsSwFbIOG1TDQz1KAV2z5IRqcFe4gPs9l3wsFKi1NsSZvBe8yQJmiu5AzJ91Timrykocna6Z', 'binary')


   let wit0b = Buffer.from('BmuupUhPx5_yZ-Wk1x4ejhccWzwEHHzq7K0gzQPYGGwT', 'binary')
   let wit1b = Buffer.from('BjhccWzwEHHzq7K0gzmuupUhPx5_yZ-Wk1x4eQPYGGwT', 'binary')
   let wsig0b = Buffer.from('0B1Timrykocna6Z_pQBl2gt59I_F6BsSwFbIOG1TDQz1KAV2z5IRqcFe4gPs9l3wsFKi1NsSZvBe8yQJmiu5AzJ9', 'binary')
   let wsig1b = Buffer.from('0B5IRqcFe4gPs9l3wsFKi1NsSZvBe8yQJmiu5Az_pQBl2gt59I_F6BsSwFbIOG1TDQz1KAV2zJ91Timrykocna6Z', 'binary')

   let valb = Buffer.from('EHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhccWzwEH', 'binary')
   let vdigb = Buffer.from('EQiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4GAPkzNZMtX-', 'binary')
   let vsig0b = Buffer.from('AAKAV2z5IRqcFe4gPs9l3wsFKi1NsSZvBe81Timrykocna6Z_pQBl2gt59I_F6BsSwFbIOG1TDQz1yQJmiu5AzJ9', 'binary')
   let vsig1b = Buffer.from('AB1KAV2zJ91Timrykocna6Z5IRqcFe4gPs9l3wsFKi1NsSZvBe8yQJmiu5Az_pQBl2gt59I_F6BsSwFbIOG1TDQz', 'binary')

   let lgr = openLogger()

   let key = dgkey(preb, digb)
   // assert.deepEqual(key, Buffer.concat(preb_digb))

   let _lgr = lgr.next().value
   // #  test .evts sub db methods

   // assert.deepStrictEqual(_lgr.getEvt(key),false)
   // assert.deepStrictEqual(_lgr.delEvt(key),false)
   // assert.deepStrictEqual(_lgr.putEvt(key,skedb),true)
   // assert.deepStrictEqual(_lgr.getEvt(key),skedb)
   // assert.deepStrictEqual(_lgr.putEvt(key,skedb),false)
   // assert.deepStrictEqual(_lgr.setEvt(key,skedb),true)
   // assert.deepStrictEqual(_lgr.getEvt(key),skedb)
   // assert.deepStrictEqual(_lgr.delEvt(key),true)
   // assert.deepStrictEqual(_lgr.getEvt(key),false)



   // #     # test .dtss sub db methods
   let val1 = Buffer.from('2020-08-22T17:50:09.988921+00:00', 'binary')
   let val2 = Buffer.from('2020-08-22T17:50:09.988921+00:00', 'binary')


   // assert.deepStrictEqual(_lgr.getDts(key),false)
   // assert.deepStrictEqual(_lgr.delDts(key),false)
   // assert.deepStrictEqual(_lgr.putDts(key,val1),true)
   // assert.deepStrictEqual(_lgr.getDts(key),val1)
   // assert.deepStrictEqual(_lgr.putDts(key,val2),false)
   // assert.deepStrictEqual(_lgr.setDts(key,val2),true)
   // assert.deepStrictEqual(_lgr.delDts(key),true)
   // assert.deepStrictEqual(_lgr.getDts(key),false)


   //    # test .sigs sub db methods
   //  assert.deepStrictEqual(_lgr.getSigs(key),[])
   // assert.deepStrictEqual(_lgr.cntSigs(key),0)
   // assert.deepStrictEqual(_lgr.delDts(key),false)

   // #     # dup vals are lexocographic

   // assert.deepStrictEqual(_lgr.putSigs(key,vals),true)
   // assert.deepStrictEqual(_lgr.getSigs(key),vals1)
   // assert.deepStrictEqual(_lgr.cntSigs(key),4)
   // assert.deepStrictEqual(_lgr.putSigs(key,Buffer.from('a','binary')),true)   //# duplicate but True
   // assert.deepStrictEqual(_lgr.getSigs(key),vals1)
   // ===================+>
   // assert.deepStrictEqual(_lgr.addSig(key,Buffer.from('a','binary')),false) //duplicate
   // ===================>  This test is getting failed

   // assert.deepStrictEqual(_lgr.addSig(key,Buffer.from('b','binary')),true)
   // assert.deepStrictEqual(_lgr.getSigs(key),vals2)
   // assert.deepStrictEqual(_lgr.getSigs(key),vals2)
   // assert.deepStrictEqual(_lgr.delSigs(key),true)
   // #     assert lgr.getSigs(key) == [b'a', b'b', b'm', b'x', b'z']
   // #     assert [val for val in lgr.getSigsIter(key)] == [b'a', b'b', b'm', b'x', b'z']
   // #     assert lgr.delSigs(key) == True
   // #     assert lgr.getSigs(key) == []



   // assert.deepStrictEqual(_lgr.putSigs(key,[sig0b]),true) 
   // assert.deepStrictEqual(_lgr.getSigs(key),[sig0b])
   // assert.deepStrictEqual(_lgr.putSigs(key,[sig1b]),true)
   // assert.deepStrictEqual(_lgr.getSigs(key),[sig0b,sig1b])
   // assert.deepStrictEqual(_lgr.delSigs(key),true)
   //   ? assert.deepStrictEqual(_lgr.putSigs(key,[sig0b, sig1b]),true)
   // assert.deepStrictEqual(_lgr.getSigs(key),[sig0b,sig1b])
   // assert.deepStrictEqual(_lgr.delSigs(key),true)
   // assert.deepStrictEqual(_lgr.getSigs(key),[])



   // #     # test .rcts sub db methods dgkey
   // assert.deepStrictEqual(_lgr.getRcts(key),[])
   // assert.deepStrictEqual(_lgr.cntRcts(key),0)
   // assert.deepStrictEqual(_lgr.delRcts(key),false)


   // #     # dup vals are lexocographic
   // assert.deepStrictEqual(_lgr.putRcts(key,vals),true) 
   // assert.deepStrictEqual(_lgr.getRcts(key),[Buffer.from('a','binary'),Buffer.from('m','binary'),Buffer.from('x','binary'),Buffer.from('z','binary')]) 
   // assert.deepStrictEqual(_lgr.cntRcts(key),4)
   // assert.deepStrictEqual(_lgr.putRcts(key,[Buffer.from('a','binary')]),true) 
   // assert.deepStrictEqual(_lgr.getRcts(key),[Buffer.from('a','binary'),Buffer.from('m','binary'),Buffer.from('x','binary'),Buffer.from('z','binary')]) 
   // assert.deepStrictEqual(_lgr.addRct(key,[Buffer.from('a','binary')]),true) 
   // assert.deepStrictEqual(_lgr.addRct(key,[Buffer.from('b','binary')]),true) 
   // assert.deepStrictEqual(_lgr.getRcts(key),vals2) 


   // #     assert [val for val in lgr.getRctsIter(key)] == [b'a', b'b', b'm', b'x', b'z']
   // #     assert lgr.delRcts(key) == True
   // #     assert lgr.getRcts(key) == []
   // assert.deepStrictEqual(_lgr.putRcts(key,[Buffer.concat([wit0b , wsig0b, wit1b , wsig1b])]),true)
   // console.log("ACTUAL DATA+++++++++++++++>",Buffer.concat([wit1b,wsig1b, wit0b , wsig0b]).toString())
   // assert.deepStrictEqual(_lgr.getRcts(key),[Buffer.concat([wit1b,wsig1b, wit0b , wsig0b])]) 
   // assert.deepStrictEqual(_lgr.putRcts(key,[Buffer.concat([wit1b , wsig1b])]),true)
   // assert.deepStrictEqual(_lgr.getRcts(key),[Buffer.concat([wit1b,wsig1b, wit0b , wsig0b])]) 
   // assert.deepStrictEqual(_lgr.delRcts(key),true)
   // assert.deepStrictEqual(_lgr.putRcts(key,[Buffer.concat([wit0b , wsig0b, wit1b , wsig1b])]),true)

   // THIS IS NOT WORKING AS EXPECTED ================>
   // assert.deepStrictEqual(_lgr.getRcts(key),[Buffer.concat([wit1b,wsig1b, wit0b , wsig0b])]) 
   // THIS IS NOT WORKING AS EXPECTED ================>
   // assert.deepStrictEqual(_lgr.delRcts(key),true)
   // assert.deepStrictEqual(_lgr.getRcts(key),[]) 



   // #     # test .ures sub db methods dgKey
   // assert.deepStrictEqual(_lgr.getUres(key), [])
   // assert.deepStrictEqual(_lgr.cntUres(key), 0)
   // assert.deepStrictEqual(_lgr.delUres(key), false)


   // #     # dup vals are lexocographic

   //  assert.deepStrictEqual(_lgr.putUres(key,vals),true) 
   // assert.deepStrictEqual(_lgr.getUres(key),[Buffer.from('a','binary'),Buffer.from('m','binary'),Buffer.from('x','binary'),Buffer.from('z','binary')]) 
   // assert.deepStrictEqual(_lgr.cntUres(key),4)
   // assert.deepStrictEqual(_lgr.putUres(key,[Buffer.from('a','binary')]),true) 
   // assert.deepStrictEqual(_lgr.getUres(key),[Buffer.from('a','binary'),Buffer.from('m','binary'),Buffer.from('x','binary'),Buffer.from('z','binary')]) 
   // assert.deepStrictEqual(_lgr.addUre(key,[Buffer.from('a','binary')]),true) 
   // assert.deepStrictEqual(_lgr.addUre(key,[Buffer.from('b','binary')]),true) 
   // assert.deepStrictEqual(_lgr.getUres(key),vals2) 




   // #     assert [val for val in lgr.getUresIter(key)] == [b'a', b'b', b'm', b'x', b'z']
   // #     assert lgr.delUres(key) == True
   // #     assert lgr.getUres(key) == []


   // assert.deepStrictEqual(_lgr.putUres(key,[Buffer.concat([wit0b , wsig0b, wit1b , wsig1b])]),true)
   // assert.deepStrictEqual(_lgr.getUres(key),Buffer.concat([wit1b , wsig1b, wit0b , wsig0b]))

   // assert.deepStrictEqual(_lgr.putUres(key,[Buffer.concat([wit1b , wsig1b])]),true)
   // assert.deepStrictEqual(_lgr.getUres(key),[Buffer.concat([wit1b , wsig1b, wit0b , wsig0b])]) 
   // assert.deepStrictEqual(_lgr.delUres(key), true)
   // assert.deepStrictEqual(_lgr.putUres(key,[Buffer.concat([wit1b , wsig1b, wit0b , wsig0b])]),true)
   // assert.deepStrictEqual(_lgr.getUres(key),Buffer.concat([wit1b , wsig1b, wit0b , wsig0b]))
   // assert.deepStrictEqual(_lgr.delUres(key), true)
   // assert.deepStrictEqual(_lgr.getUres(key), [])


   // #     # test .vrcs sub db methods dgkey
   // assert.deepStrictEqual(_lgr.getVrcs(key), [])
   // assert.deepStrictEqual(_lgr.cntVrcs(key), 0)
   // assert.deepStrictEqual(_lgr.delVrcs(key), false)


   // #     # dup vals are lexocographic
   //  assert.deepStrictEqual(_lgr.putVrcs(key,vals),true) 
   // assert.deepStrictEqual(_lgr.getVrcs(key),[Buffer.from('a','binary'),Buffer.from('m','binary'),Buffer.from('x','binary'),Buffer.from('z','binary')]) 
   // assert.deepStrictEqual(_lgr.cntVrcs(key),4)
   // assert.deepStrictEqual(_lgr.putVrcs(key,[Buffer.from('a','binary')]),true) 
   // assert.deepStrictEqual(_lgr.getVrcs(key),[Buffer.from('a','binary'),Buffer.from('m','binary'),Buffer.from('x','binary'),Buffer.from('z','binary')]) 
   // assert.deepStrictEqual(_lgr.addVrc(key,[Buffer.from('a','binary')]),true) 
   // assert.deepStrictEqual(_lgr.addVrc(key,[Buffer.from('b','binary')]),true) 
   // assert.deepStrictEqual(_lgr.getVrcs(key),vals2) 

   // #     assert [val for val in lgr.getVrcsIter(key)] == [b'a', b'b', b'm', b'x', b'z']
   // #     assert lgr.delVrcs(key) == True
   // #     assert lgr.getVrcs(key) == []

   // assert.deepStrictEqual(_lgr.putVrcs(key,[Buffer.concat([wit0b , wsig0b, wit1b , wsig1b])]),true)
   // assert.deepStrictEqual(_lgr.getVrcs(key),Buffer.concat([wit1b , wsig1b, wit0b , wsig0b]))

   // assert.deepStrictEqual(_lgr.putVrcs(key,[Buffer.concat([wit1b , wsig1b])]),true)
   // assert.deepStrictEqual(_lgr.getVrcs(key),[Buffer.concat([wit1b , wsig1b, wit0b , wsig0b])]) 
   // assert.deepStrictEqual(_lgr.delVrcs(key), true)
   // assert.deepStrictEqual(_lgr.putVrcs(key,[Buffer.concat([wit1b , wsig1b, wit0b , wsig0b])]),true)
   // assert.deepStrictEqual(_lgr.getVrcs(key),Buffer.concat([wit1b , wsig1b, wit0b , wsig0b]))
   // assert.deepStrictEqual(_lgr.delVrcs(key), true)
   // assert.deepStrictEqual(_lgr.getVrcs(key), [])


   // #     # test .vres sub db methods dgKey
   //  assert.deepStrictEqual(_lgr.getVres(key), [])
   //    assert.deepStrictEqual(_lgr.cntVres(key), 0)
   //    assert.deepStrictEqual(_lgr.delVres(key), false)


   // #     # dup vals are lexocographic
   //  assert.deepStrictEqual(_lgr.putVres(key,vals),true) 
   // assert.deepStrictEqual(_lgr.getVres(key),[Buffer.from('a','binary'),Buffer.from('m','binary'),Buffer.from('x','binary'),Buffer.from('z','binary')]) 
   // assert.deepStrictEqual(_lgr.cntVres(key),4)
   // assert.deepStrictEqual(_lgr.putVres(key,[Buffer.from('a','binary')]),true) 
   // assert.deepStrictEqual(_lgr.getVres(key),[Buffer.from('a','binary'),Buffer.from('m','binary'),Buffer.from('x','binary'),Buffer.from('z','binary')]) 
   // assert.deepStrictEqual(_lgr.addVre(key,[Buffer.from('a','binary')]),true) 
   // assert.deepStrictEqual(_lgr.addVre(key,[Buffer.from('b','binary')]),true) 
   // assert.deepStrictEqual(_lgr.getVres(key),vals2) 

   // #     assert [val for val in lgr.getVrcsIter(key)] == [b'a', b'b', b'm', b'x', b'z']
   // #     assert lgr.delVres(key) == True
   // #     assert lgr.getVres(key) == []

   // assert.deepStrictEqual(_lgr.putVres(key,[Buffer.concat([wit0b , wsig0b, wit1b , wsig1b])]),true)
   // assert.deepStrictEqual(_lgr.getVres(key),Buffer.concat([wit1b , wsig1b, wit0b , wsig0b]))

   // assert.deepStrictEqual(_lgr.putVres(key,[Buffer.concat([wit1b , wsig1b])]),true)
   // assert.deepStrictEqual(_lgr.getVres(key),[Buffer.concat([wit1b , wsig1b, wit0b , wsig0b])]) 
   // assert.deepStrictEqual(_lgr.delVres(key), true)
   // assert.deepStrictEqual(_lgr.putVres(key,[Buffer.concat([wit1b , wsig1b, wit0b , wsig0b])]),true)
   // assert.deepStrictEqual(_lgr.getVres(key),Buffer.concat([wit1b , wsig1b, wit0b , wsig0b]))
   // assert.deepStrictEqual(_lgr.delVres(key), true)
   // assert.deepStrictEqual(_lgr.getVres(key), [])



   // #     # test .kels insertion order dup methods.  dup vals are insertion order
   let key1 = snkey(preb, 0)

   // assert.deepStrictEqual(_lgr.getKes(key1), [])
   // assert.deepStrictEqual(_lgr.getKeLast(key1), null)
   // assert.deepStrictEqual(_lgr.cntKes(key1), 0)
   // assert.deepStrictEqual(_lgr.delKes(key1), false)
   // assert.deepStrictEqual(_lgr.putKes(key1,vals), true)
   // assert.deepStrictEqual(_lgr.getKes(key1), vals)
   // assert.deepStrictEqual(_lgr.cntKes(key1), 4)
   // assert.deepStrictEqual(_lgr.getKeLast(key1), vals[vals.length -1 ])
   //   / assert.deepStrictEqual(_lgr.putKes(key1,[Buffer.from('a','binary')]), true)  // # duplicate
   // assert.deepStrictEqual(_lgr.getKes(key1), vals)
   // assert.deepStrictEqual(_lgr.putKes(key1,[Buffer.from('a','binary')]), true)
   // assert.deepStrictEqual(_lgr.putKes(key1,[Buffer.from('b','binary')]), true)
   // assert.deepStrictEqual(_lgr.getKes(key1), [Buffer.from('z', 'binary'), Buffer.from('m', 'binary'), Buffer.from('x', 'binary'), Buffer.from('a', 'binary'),Buffer.from('b', 'binary')])
   // assert.deepStrictEqual(_lgr.delKes(key1), true)
   // assert.deepStrictEqual(_lgr.getKes(key1), [])


   // #     # test .pses insertion order dup methods.  dup vals are insertion order
   let key2 = Buffer.from('A', 'binary')
   //   vals = [b"z", b"m", b"x", b"a"]



   // assert.deepStrictEqual(_lgr.getPses(key2), [])
   // assert.deepStrictEqual(_lgr.getPsesLast(key2), null)
   // assert.deepStrictEqual(_lgr.cntPses(key2), 0)
   // assert.deepStrictEqual(_lgr.delPses(key2), false)
   // assert.deepStrictEqual(_lgr.putPses(key2,vals), true)
   // assert.deepStrictEqual(_lgr.getPses(key2), vals)
   // assert.deepStrictEqual(_lgr.cntPses(key2), 4)
   // assert.deepStrictEqual(_lgr.getPsesLast(key2), vals[vals.length -1 ])
   // assert.deepStrictEqual(_lgr.putPses(key2,[Buffer.from('a','binary')]), true)  // # duplicate
   // assert.deepStrictEqual(_lgr.getPses(key2), vals)
   // assert.deepStrictEqual(_lgr.addPse(key2,[Buffer.from('a','binary')]), true)
   // assert.deepStrictEqual(_lgr.addPse(key2,[Buffer.from('b','binary')]), true)
   // assert.deepStrictEqual(_lgr.getPses(key2), [Buffer.from('z', 'binary'), Buffer.from('m', 'binary'), Buffer.from('x', 'binary'), Buffer.from('a', 'binary'),Buffer.from('b', 'binary')])
   // assert.deepStrictEqual(_lgr.delPses(key2), true)
   // assert.deepStrictEqual(_lgr.getPses(key2), [])







   // #     # test .ooes insertion order dup methods.  dup vals are insertion order
   // #     key = b'A'
   // #     vals = [b"z", b"m", b"x", b"a"]



   //       assert.deepStrictEqual(_lgr.getOoes(key2), [])
   // assert.deepStrictEqual(_lgr.getOoesLast(key2), null)
   // assert.deepStrictEqual(_lgr.cntOoes(key2), 0)
   // assert.deepStrictEqual(_lgr.delOoes(key2), false)
   // assert.deepStrictEqual(_lgr.putOoes(key2,vals), true)
   // assert.deepStrictEqual(_lgr.getOoes(key2), vals)
   // assert.deepStrictEqual(_lgr.cntOoes(key2), 4)
   // assert.deepStrictEqual(_lgr.getOoesLast(key2), vals[vals.length -1 ])
   //    assert.deepStrictEqual(_lgr.putOoes(key2,[Buffer.from('a','binary')]), true)  // # duplicate
   //    assert.deepStrictEqual(_lgr.getOoes(key2), vals)
   //   assert.deepStrictEqual(_lgr.addOoe(key2,[Buffer.from('a','binary')]), true)
   //    assert.deepStrictEqual(_lgr.addOoe(key2,[Buffer.from('b','binary')]), true)
   // assert.deepStrictEqual(_lgr.getOoes(key2), [Buffer.from('z', 'binary'), Buffer.from('m', 'binary'), Buffer.from('x', 'binary'), Buffer.from('a', 'binary'),Buffer.from('b', 'binary')])
   // assert.deepStrictEqual(_lgr.delOoes(key2), true)
   // assert.deepStrictEqual(_lgr.getOoes(key2), [])




   // #     # test .dels insertion order dup methods.  dup vals are insertion order
   // #     key = b'A'
   // #     vals = [b"z", b"m", b"x", b"a"]



   //       assert.deepStrictEqual(_lgr.getDes(key2), [])
   // assert.deepStrictEqual(_lgr.getDesLast(key2), null)
   // assert.deepStrictEqual(_lgr.cntDes(key2), 0)
   // assert.deepStrictEqual(_lgr.delDes(key2), false)
   // assert.deepStrictEqual(_lgr.putDes(key2,vals), true)
   // assert.deepStrictEqual(_lgr.getDes(key2), vals)
   // assert.deepStrictEqual(_lgr.cntDes(key2), 4)
   // assert.deepStrictEqual(_lgr.getDesLast(key2), vals[vals.length -1 ])
   //    assert.deepStrictEqual(_lgr.putDes(key2,[Buffer.from('a','binary')]), true)  // # duplicate
   //    assert.deepStrictEqual(_lgr.getDes(key2), vals)
   //   assert.deepStrictEqual(_lgr.addDe(key2,[Buffer.from('a','binary')]), true)
   //    assert.deepStrictEqual(_lgr.addDe(key2,[Buffer.from('b','binary')]), true)
   // assert.deepStrictEqual(_lgr.getDes(key2), [Buffer.from('z', 'binary'), Buffer.from('m', 'binary'), Buffer.from('x', 'binary'), Buffer.from('a', 'binary'),Buffer.from('b', 'binary')])
   // assert.deepStrictEqual(_lgr.delDes(key2), true)
   // assert.deepStrictEqual(_lgr.getDes(key2), [])




   // #     # test .ldes insertion order dup methods.  dup vals are insertion order
   // #     key = b'A'
   // #     vals = [b"z", b"m", b"x", b"a"]



   //       assert.deepStrictEqual(_lgr.getLdes(key2), [])
   // assert.deepStrictEqual(_lgr.getLdesLast(key2), null)
   // assert.deepStrictEqual(_lgr.cntLdes(key2), 0)
   // assert.deepStrictEqual(_lgr.delLdes(key2), false)
   // assert.deepStrictEqual(_lgr.putLdes(key2,vals), true)
   // assert.deepStrictEqual(_lgr.getLdes(key2), vals)
   // assert.deepStrictEqual(_lgr.cntLdes(key2), 4)
   // assert.deepStrictEqual(_lgr.getLdesLast(key2), vals[vals.length -1 ])
   //    assert.deepStrictEqual(_lgr.putLdes(key2,[Buffer.from('a','binary')]), true)  // # duplicate
   //    assert.deepStrictEqual(_lgr.getLdes(key2), vals)
   //   assert.deepStrictEqual(_lgr.addDe(key2,[Buffer.from('a','binary')]), true)
   //    assert.deepStrictEqual(_lgr.addDe(key2,[Buffer.from('b','binary')]), true)
   // assert.deepStrictEqual(_lgr.getLdes(key2), [Buffer.from('z', 'binary'), Buffer.from('m', 'binary'), Buffer.from('x', 'binary'), Buffer.from('a', 'binary'),Buffer.from('b', 'binary')])
   // assert.deepStrictEqual(_lgr.delLdes(key2), true)
   // assert.deepStrictEqual(_lgr.getLdes(key2), [])



}

function test_fetchkeldel(){

   let pre = Buffer.from('BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc', 'binary')
   let dig = Buffer.from('EGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4', 'binary')

   let sn = 3
   let vs = versify(null, Serials.json, 20)
   assert.equal(vs, 'KERI10JSON000014_')

   let ked = {
      vs: vs, pre: preb.toString('utf-8'),
      sn: sn.toString(16),
      ilk: "rot",
      dig: digb.toString('utf-8')
   }


   let skedb = Buffer.from(JSON.stringify(ked), 'binary')

   let sig0b = Buffer.from('AAz1KAV2z5IRqcFe4gPs9l3wsFKi1NsSZvBe8yQJmiu5AzJ91Timrykocna6Z_pQBl2gt59I_F6BsSwFbIOG1TDQ', 'binary')
   let sig1b = Buffer.from('AB_pQBl2gt59I_F6BsSwFbIOG1TDQz1KAV2z5IRqcFe4gPs9l3wsFKi1NsSZvBe8yQJmiu5AzJ91Timrykocna6Z', 'binary')


   let wit0b = Buffer.from('BmuupUhPx5_yZ-Wk1x4ejhccWzwEHHzq7K0gzQPYGGwT', 'binary')
   let wit1b = Buffer.from('BjhccWzwEHHzq7K0gzmuupUhPx5_yZ-Wk1x4eQPYGGwT', 'binary')
   let wsig0b = Buffer.from('0B1Timrykocna6Z_pQBl2gt59I_F6BsSwFbIOG1TDQz1KAV2z5IRqcFe4gPs9l3wsFKi1NsSZvBe8yQJmiu5AzJ9', 'binary')
   let wsig1b = Buffer.from('0B5IRqcFe4gPs9l3wsFKi1NsSZvBe8yQJmiu5Az_pQBl2gt59I_F6BsSwFbIOG1TDQz1KAV2zJ91Timrykocna6Z', 'binary')

   let valb = Buffer.from('EHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhccWzwEH', 'binary')
   let vdigb = Buffer.from('EQiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4GAPkzNZMtX-', 'binary')
   let vsig0b = Buffer.from('AAKAV2z5IRqcFe4gPs9l3wsFKi1NsSZvBe81Timrykocna6Z_pQBl2gt59I_F6BsSwFbIOG1TDQz1yQJmiu5AzJ9', 'binary')
   let vsig1b = Buffer.from('AB1KAV2zJ91Timrykocna6Z5IRqcFe4gPs9l3wsFKi1NsSZvBe8yQJmiu5Az_pQBl2gt59I_F6BsSwFbIOG1TDQz', 'binary')


   let lgr = openLogger()
   let _lgr = lgr.next().value
   sn = 0
   let key = snkey(preb, sn)
   assert.deepEqual(key, Buffer.concat('BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc.00000000000000000000000000000000','binary'))
   let vls0 = [skedb]
   assert.deepStrictEqual(_lgr.addKe(key, vals0[0]) , true) 
 
 
   let vals1 = [Buffer.from('mary', 'binary'), Buffer.from('peter', 'binary'), Buffer.from('john', 'binary'), Buffer.from('paul', 'binary')]
   
   sn +=1
   key = snkey(preb, sn)

   for(let val in vals2)
   assert.deepStrictEqual(_lgr.addKe(key, val) ,true) 
}
test_logger()