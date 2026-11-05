const fs=require('fs'),solc=require('solc'),ganache=require('ganache'),{ethers}=require('ethers');
(async()=>{
 const root=require('path').resolve(__dirname, '../..');
 const files=['contracts/SsiLoginAttestor.sol','tests/Contracts/SsiLoginAttestorTest.sol'];
 const sources=Object.fromEntries(files.map(f=>[f,{content:fs.readFileSync(root+'/'+f,'utf8')}]));
 const result=JSON.parse(solc.compile(JSON.stringify({language:'Solidity',sources,settings:{evmVersion:'paris',outputSelection:{'*':{'*':['abi','evm.bytecode.object']}}}})));
 if((result.errors||[]).some(x=>x.severity==='error')) throw Error(JSON.stringify(result.errors));
 const chain=ganache.provider({logging:{quiet:true},chain:{hardfork:'merge'}});
 try {
 const provider=new ethers.BrowserProvider(chain), signer=await provider.getSigner();
 const out=result.contracts[files[1]].SsiLoginAttestorTest;
 const test=await new ethers.ContractFactory(out.abi,out.evm.bytecode.object,signer).deploy();await test.waitForDeployment();
 for(const fn of out.abi.filter(x=>x.type==='function'&&x.name.startsWith('test'))) {await (await test[fn.name]()).wait();console.log('PASS '+fn.name);}
 } finally {await chain.disconnect();}
})().catch(e=>{console.error(e);process.exitCode=1});
