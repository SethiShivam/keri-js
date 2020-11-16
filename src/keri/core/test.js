const regex = "KERI([0-9a-f])([0-9a-f])([A-Z]{4})([0-9a-f]{6})_";
const str = `KERI10JSON000127_`;
let m;
console.log("Hey")
while ((m = regex.exec(str)) !== null) {
   console.log("Its not null")
    if (m.index === regex.lastIndex) {
        regex.lastIndex++;
    }
    console.log("Inside while Loop")
    // The result can be accessed through the `m`-variable.
    m.forEach((match, groupIndex) => {
        console.log(`Found match, group ${groupIndex}: ${match}`);
    });
}